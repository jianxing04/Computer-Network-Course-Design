package main

import (
	"bufio"
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	
	"github.com/fsnotify/fsnotify"
)

// DNS报文头部结构
type DNSHeader struct {
	ID      uint16 // 请求ID
	Flags   uint16 // 标志位
	QDCount uint16 // 问题数
	ANCount uint16 // 回答数
	NSCount uint16 // 授权记录数
	ARCount uint16 // 附加记录数
}

// 资源记录结构，即应答部分
type ResourceRecord struct {
	Name     []byte // 域名
	Type     uint16 // 记录类型
	Class    uint16 // 记录类
	TTL      uint32 // 生存时间
	RDLength uint16 // RDATA 部分长度
	RData    []byte // 具体资源数据，即 IP 地址等
}

// 域名-IP映射
type DomainIPMapping struct {
	Domain string
	IPs    []string // 支持多个IP
}

// 缓存项
type CacheEntry struct {
	Domain  string
	IPs     []string
	TTL     uint32
	Expires time.Time // 修复：统一使用 Expires 字段
}

// LRU缓存结构
type LRUCache struct {
	capacity int
	list     *list.List
	cache    map[string]*list.Element
	mutex    sync.RWMutex
}

// 工作请求结构
type WorkRequest struct {
	conn      *net.UDPConn
	clientAddr *net.UDPAddr
	data      []byte
}

// 全局变量
var (
	mappingTable   []DomainIPMapping
	cache          *LRUCache
	idMutex        sync.Mutex
	nextID         uint16 = 1
	externalDNS    string = "114.114.114.114"
	defaultMapping string = "dnsrelay.txt"
	debugLevel     int    = 0
	workerPoolSize int    = 100
	shutdownSignal chan struct{}
	watcher        *fsnotify.Watcher
	fileMutex      sync.RWMutex
)

// DNS相关常量
const (
	DNS_PORT         = 53     // DNS服务端口
	MAX_PACKET_SIZE  = 512    // DNS报文最大长度
	DEFAULT_TTL      = 3600   // 默认TTL
	TYPE_A           = 1      // A记录
	TYPE_AAAA        = 28     // AAAA记录
	TYPE_PTR         = 12     // PTR记录
	CLASS_IN         = 1      // IN类
	FLAG_RESPONSE    = 0x8000 // 响应标志
	RCODE_NO_ERROR   = 0      // 无错误
	RCODE_FORMERR    = 1      // 格式错误
	RCODE_NAME_ERROR = 3      // 名称错误
	RCODE_NOT_IMP    = 4      // 未实现
	MAX_DOMAIN_LEN   = 253    // 最大域名长度
	CACHE_CAPACITY   = 500    // 缓存容量
)

func main() {
	// 创建信号通道
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 定义命令行标志
	debugLevelFlag := flag.Int("debug", 0, "调试等级 (0-2)")
	externalDNSFlag := flag.String("dns", "114.114.114.114", "外部 DNS 服务器地址")
	mappingFilesFlag := flag.String("mapping", defaultMapping, "域名-IP 映射文件")
	workersFlag := flag.Int("workers", 100, "工作线程数量")

	// 解析命令行标志
	flag.Parse()
	debugLevel = *debugLevelFlag
	externalDNS = *externalDNSFlag
	workerPoolSize = *workersFlag

	// 初始化缓存
	cache = NewLRUCache(CACHE_CAPACITY)

	// 创建文件监视器
	var err error
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("创建文件监视器失败: %v", err)
	}
	defer watcher.Close()

	// 解析映射文件
	parseMappingFile(*mappingFilesFlag)
	watchConfigFile(*mappingFilesFlag)

	// 创建UDP监听
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", DNS_PORT))
	if err != nil {
		log.Fatalf("解析地址失败: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("监听端口失败: %v", err)
	}
	defer conn.Close()

	log.Printf("DNS中继服务器启动，端口: %d, 外部DNS: %s, 工作线程: %d", DNS_PORT, externalDNS, workerPoolSize)

	// 创建工作池
	shutdownSignal = make(chan struct{})
	workChan := make(chan WorkRequest, 1000)
	for i := 0; i < workerPoolSize; i++ {
		go worker(workChan)
	}

	// 启动信号监听协程
	go func() {
		sig := <-sigChan
		log.Printf("接收到信号: %v，停止服务", sig)
		close(shutdownSignal)
		conn.Close()
	}()

	// 主处理循环
	buf := make([]byte, MAX_PACKET_SIZE)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-shutdownSignal:
				log.Println("服务已停止")
				return
			default:
				logDebug(1, "读取数据失败: %v", err)
				continue
			}
		}

		// 复制数据以避免覆盖
		data := make([]byte, n)
		copy(data, buf[:n])

		select {
		case <-shutdownSignal:
			log.Println("停止处理新请求")
			return
		case workChan <- WorkRequest{conn, clientAddr, data}:
		default:
			logDebug(1, "工作队列已满，丢弃请求")
		}
	}
}

func handleClientRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte) {
	// 在函数开头立即检查关闭信号
	select {
	case <-shutdownSignal:
		return // 已经收到了关闭信号，直接退出不处理
	default:
		// 没有收到关闭信号，继续处理
	}

	// 使用defer捕获panic，避免程序崩溃
	defer func() {
		if r := recover(); r != nil {
			logDebug(1, "处理请求时发生panic: %v", r)
		}
	}()

	// 解析客户端请求的IP地址和请求长度
	clientIP := clientAddr.IP.String()
	logDebug(2, "收到客户端请求，IP: %s，长度: %d", clientIP, len(request))

	// 先检查请求长度是否足够
	if len(request) < 12 { // DNS报文头部至少需要12字节
		logDebug(1, "请求过短: %d字节", len(request))
		response := buildErrorResponse(request, RCODE_FORMERR) // 格式错误
		if response != nil {
			if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
				logDebug(1, "发送错误响应失败: %v", err)
			}
		}
		return
	}

	// 解析DNS请求，获取域名和查询类型
	domain, qtype, _, err := parseDNSMessage(request)
	if err != nil {
		logDebug(1, "解析DNS请求失败: %v", err)
		response := buildErrorResponse(request, RCODE_FORMERR) // 格式错误
		if response != nil {
			if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
				logDebug(1, "发送错误响应失败: %v", err)
			}
		}
		return
	}

	logDebug(1, "客户端查询: %s (类型: %d)", domain, qtype)

	// 处理反向查询 (PTR记录)
	if qtype == TYPE_PTR {
		logDebug(1, "收到反向查询请求: %s", domain)
		response := buildErrorResponse(request, RCODE_NOT_IMP) // 报文头部RCODE字段设为NOT_IMPLEMENTED
		if response != nil {                                   // 如果构建响应成功
			if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
				logDebug(1, "发送反向查询响应失败: %v", err)
			}
		}
		return
	}

	ips := []string{} // 存储多个IP
	rcode := 0        // 默认响应码为0（表示成功）

	// 使用LRU缓存查找
	if cachedIPs, found := cache.Get(domain); found {
		ips = cachedIPs
		logDebug(2, "缓存命中: %s -> %v", domain, ips)
	} else { // 如果缓存未命中，查找映射表
		if mappedIPs, found := lookupMapping(domain); found {
			ips = mappedIPs
			logDebug(2, "映射表命中: %s -> %v", domain, ips)

			// 检查是否有0.0.0.0（表示屏蔽）
			for _, ip := range ips {
				if ip == "0.0.0.0" {
					ips = []string{}
					rcode = RCODE_NAME_ERROR // 设置响应码为NAME_ERROR，表示域名不存在
					break
				}
			}
		} else { // 如果映射表未命中，尝试转发查询到外部DNS服务器
			logDebug(1, "转发查询: %s", domain)
			if relayedIPs, err := sendDNSQuery(domain, qtype); err == nil { // 转发查询成功
				ips = relayedIPs
				logDebug(2, "转发成功: %s -> %v", domain, ips)
				cache.Set(domain, ips, DEFAULT_TTL) // 使用LRU缓存
			} else { // 转发查询失败
				logDebug(1, "转发失败: %s: %v", domain, err)
				rcode = RCODE_NAME_ERROR // 设置响应码为NAME_ERROR，表示域名不存在
			}
		}
	}

	response := buildDNSResponse(request, ips, rcode, qtype) // 构建DNS响应报文
	if response != nil {                                     // 如果构建响应成功
		if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
			logDebug(1, "发送响应失败: %v", err)
		}
	} else {
		logDebug(1, "构建DNS响应失败")
	}
}

// 创建LRU缓存
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		list:     list.New(),
		cache:    make(map[string]*list.Element),
	}
}

// 从缓存中获取
func (c *LRUCache) Get(domain string) ([]string, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if elem, ok := c.cache[domain]; ok {
		entry := elem.Value.(*CacheEntry)
		if time.Now().Before(entry.Expires) {
			c.list.MoveToFront(elem)
			return entry.IPs, true
		}
		// 缓存过期，删除
		c.mutex.RUnlock()
		c.mutex.Lock()
		delete(c.cache, domain)
		c.list.Remove(elem)
		c.mutex.Unlock()
		c.mutex.RLock()
	}
	return nil, false
}

// 添加到缓存
func (c *LRUCache) Set(domain string, ips []string, ttl uint32) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// 如果已存在，更新
	if elem, ok := c.cache[domain]; ok {
		entry := elem.Value.(*CacheEntry)
		entry.IPs = ips
		entry.TTL = ttl
		entry.Expires = time.Now().Add(time.Duration(ttl) * time.Second)
		c.list.MoveToFront(elem)
		logDebug(2, "更新缓存: %s -> %v (TTL: %d)", domain, ips, ttl)
		return
	}

	// 如果缓存已满，移除最久未使用的
	if c.list.Len() >= c.capacity {
		elem := c.list.Back()
		if elem != nil {
			entry := elem.Value.(*CacheEntry)
			delete(c.cache, entry.Domain)
			c.list.Remove(elem)
			logDebug(2, "缓存满，移除: %s", entry.Domain)
		}
	}

	// 添加新条目
	entry := &CacheEntry{
		Domain:  domain,
		IPs:     ips,
		TTL:     ttl,
		Expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	elem := c.list.PushFront(entry)
	c.cache[domain] = elem
	logDebug(2, "添加缓存: %s -> %v (TTL: %d)", domain, ips, ttl)
}

// 工作线程
func worker(workChan chan WorkRequest) {
	for req := range workChan {
		select {
		case <-shutdownSignal:
			return
		default:
			handleClientRequest(req.conn, req.clientAddr, req.data)
		}
	}
}

// 文件监听
func watchConfigFile(filename string) {
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
					logDebug(1, "检测到文件修改: %s", event.Name)
					parseMappingFile(filename)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logDebug(1, "文件监视错误: %v", err)
			case <-shutdownSignal:
				return
			}
		}
	}()

	err := watcher.Add(filename)
	if err != nil {
		logDebug(1, "添加文件监视失败: %v", err)
	}
}

// 解析DNS报文，返回域名、查询类型、QNAME消耗字节数和错误信息
func parseDNSMessage(buffer []byte) (string, uint16, int, error) {
	if len(buffer) < 12 {
		return "", 0, 0, errors.New("报文过短")
	}

	header := DNSHeader{}
	reader := bytes.NewReader(buffer)
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return "", 0, 0, fmt.Errorf("解析DNS头部失败: %v", err)
	}

	domain, consumed, err := parseDomainName(buffer, 12) // 跳过头部，从问题部分解析域名
	if err != nil {
		return "", 0, 0, err
	}

	if len(domain) > MAX_DOMAIN_LEN {
		return "", 0, 0, fmt.Errorf("域名过长: %d字符", len(domain))
	}

	pos := 12 + consumed // pos现在指向QTYPE的位置
	if pos+4 > len(buffer) {
		return "", 0, 0, errors.New("DNS查询问题部分不完整")
	}

	qtype := binary.BigEndian.Uint16(buffer[pos:]) // 读取查询类型QTYPE，占2字节

	logDebug(3, "解析域名: %s, 类型: %d, 消耗字节: %d", domain, qtype, consumed)

	return domain, qtype, consumed, nil
}

// 解析域名，支持标签编码和指针压缩，返回域名、QNAME消耗的字节数和错误信息
func parseDomainName(buffer []byte, offset int) (string, int, error) {
	// 为了支持标签和指针混用，递归时只统计主路径消耗的字节数
	var (
		parts    []string
		pos      = offset
		consumed = 0
	)

	// 遍历域名标签，直到遇到0或指针
	for {
		if pos >= len(buffer) {
			return "", consumed, errors.New("域名解析越界")
		}
		length := int(buffer[pos])
		// 检查是否为指针
		if length&0xC0 == 0xC0 {
			// 指针必须占两个字节
			if pos+1 >= len(buffer) {
				return "", consumed, errors.New("无效的域名指针")
			}
			pointer := int(binary.BigEndian.Uint16(buffer[pos:pos+2]) & 0x3FFF)
			// 递归解析指针指向的部分，但只统计主路径消耗
			part, _, err := parseDomainName(buffer, pointer)
			if err != nil {
				return "", consumed, err
			}
			parts = append(parts, part)
			consumed += 2 // 指针占用两个字节
			break         // 结束解析
		}
		pos++            // 跳到标签内容
		consumed++       // 标签长度占用一个字节
		if length == 0 { // 遇到0表示域名结束
			break
		}
		if pos+length > len(buffer) {
			return "", consumed, errors.New("域名标签超出范围")
		}
		parts = append(parts, string(buffer[pos:pos+length]))
		pos += length      // 跳过标签内容，指向下一个标签长度
		consumed += length // 标签内容长度
	}
	return strings.Join(parts, "."), consumed, nil
}

// 根据请求报文，找到的IP地址，响应码和查询类型构建DNS响应报文
func buildDNSResponse(request []byte, ips []string, rcode int, qtype uint16) []byte {
	if len(request) < 12 {
		return nil
	}

	response := make([]byte, len(request))
	copy(response, request)

	// 解析DNS请求头部
	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		logDebug(1, "解析DNS响应头部失败: %v", err)
		return nil
	}

	header.Flags |= FLAG_RESPONSE // 将响应标志位（通常是 QR 位）设置为 1，表示这是一个响应报文
	header.Flags &= 0xFFF0        // 将RCODE字段清零，其他标志位保持不变
	header.Flags |= uint16(rcode) //设置 RCODE 字段

	if len(ips) > 0 && rcode == RCODE_NO_ERROR {
		header.ANCount = uint16(len(ips)) // 设置回答数为IP数量
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入DNS响应头部失败: %v", err)
		return nil
	}
	copy(response[:12], buf.Bytes())

	// 如果没有IP地址或响应码不是无错误，则直接返回错误响应
	if len(ips) == 0 || rcode != RCODE_NO_ERROR {
		return response
	}

	// 构建所有IP的资源记录
	for _, ip := range ips {
		rr := buildResourceRecord(ip, qtype) // 每个找到的ip地址构建一个资源记录
		if rr == nil {
			logDebug(1, "构建资源记录失败: %s", ip)
			continue
		}

		// 检查响应大小
		if len(response)+len(rr) > MAX_PACKET_SIZE {
			logDebug(1, "响应过大，无法添加更多资源记录")
			break
		}

		response = append(response, rr...) // 添加资源记录到响应
	}

	return response
}

// 构建错误响应，仅仅修改请求报文的头部，设置响应标志位和RCODE字段
func buildErrorResponse(request []byte, rcode int) []byte {
	if len(request) < 12 {
		return nil
	}

	response := make([]byte, len(request))
	copy(response, request) // 复制请求报文到响应报文

	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		logDebug(1, "解析错误响应头部失败: %v", err)
		return nil
	}

	header.Flags |= FLAG_RESPONSE // 将响应标志位（通常是 QR 位）设置为 1，表示这是一个响应报文
	header.Flags &= 0xFFF0
	header.Flags |= uint16(rcode)
	header.ANCount = 0 // 设置回答数为0，因为这是一个错误响应

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入错误响应头部失败: %v", err)
		return nil
	}
	copy(response[:12], buf.Bytes()) // 只有头部被修改

	return response
}

// 构建资源记录
func buildResourceRecord(ip string, qtype uint16) []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(0xC0)
	buf.WriteByte(0x0C) // 使用指针压缩，指向域名的起始位置

	if err := binary.Write(buf, binary.BigEndian, qtype); err != nil {
		logDebug(1, "写入资源记录类型失败: %v", err)
		return nil
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(CLASS_IN)); err != nil {
		logDebug(1, "写入资源记录类失败: %v", err)
		return nil
	}

	// 显式使用大端序写入TTL
	ttlBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBuf, DEFAULT_TTL)
	if _, err := buf.Write(ttlBuf); err != nil {
		logDebug(1, "写入资源记录TTL失败: %v", err)
		return nil
	}

	var ipBytes []byte
	var dataLength uint16

	switch qtype {
	case TYPE_A: // IPv4地址
		ipBytes = net.ParseIP(ip).To4()
		if ipBytes == nil {
			logDebug(1, "无效的IPv4地址: %s", ip)
			return nil
		}
		dataLength = 4
	case TYPE_AAAA: // IPv6地址
		ipBytes = net.ParseIP(ip).To16()
		if ipBytes == nil {
			logDebug(1, "无效的IPv6地址: %s", ip)
			return nil
		}
		dataLength = 16
	default:
		logDebug(1, "不支持的资源记录类型: %d", qtype)
		return nil
	}

	if err := binary.Write(buf, binary.BigEndian, dataLength); err != nil {
		logDebug(1, "写入资源记录数据长度失败: %v", err)
		return nil
	}

	if _, err := buf.Write(ipBytes); err != nil {
		logDebug(1, "写入资源记录IP地址失败: %v", err)
		return nil
	}

	return buf.Bytes()
}

// 查找域名-IP映射关系
func lookupMapping(domain string) ([]string, bool) {
	fileMutex.RLock()
	defer fileMutex.RUnlock()

	for _, m := range mappingTable {
		if m.Domain == domain {
			return m.IPs, true
		}
	}
	return nil, false
}

// 发送DNS查询到外部DNS服务器并返回查询结果的IP地址列表
func sendDNSQuery(domain string, qtype uint16) ([]string, error) {
	conn, err := net.Dial("udp", externalDNS+":53") // 连接外部DNS服务器
	if err != nil {
		return nil, fmt.Errorf("连接外部DNS服务器失败: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second)) // 设置读取超时时间

	query := buildDNSQuery(domain, qtype)
	if query == nil {
		return nil, errors.New("构建DNS查询失败")
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("发送DNS查询失败: %v", err)
	}

	response := make([]byte, MAX_PACKET_SIZE)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, errors.New("DNS查询超时")
		}
		return nil, fmt.Errorf("接收DNS响应失败: %v", err)
	}

	ips, err := parseDNSResponse(response[:n], qtype)
	if err != nil {
		return nil, fmt.Errorf("解析DNS响应失败: %v", err)
	}

	return ips, nil
}

// 构建DNS查询报文
func buildDNSQuery(domain string, qtype uint16) []byte {
	buf := new(bytes.Buffer)

	header := DNSHeader{
		ID:      getNextID(), // 请求ID
		Flags:   0x0100,      // 标志位：标准查询
		QDCount: 1,           // 查询数为1
	}
	err := binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入DNS查询头部失败: %v", err)
		return nil
	}
	// www.example.com 域名编码为 [3] w w w [7] e x a m p l e [3] c o m [0]
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 {
			logDebug(1, "域名标签过长: %s", label)
			return nil
		}

		err := buf.WriteByte(byte(len(label)))
		if err != nil {
			logDebug(1, "写入DNS查询域名标签长度失败: %v", err)
			return nil
		}
		_, err = buf.WriteString(label)
		if err != nil {
			logDebug(1, "写入DNS查询域名标签失败: %v", err)
			return nil
		}
	}
	err = buf.WriteByte(0) // 写入域名结束符
	if err != nil {
		logDebug(1, "写入DNS查询域名结束符失败: %v", err)
		return nil
	}

	err = binary.Write(buf, binary.BigEndian, qtype) // 写入查询类型
	if err != nil {
		logDebug(1, "写入DNS查询类型失败: %v", err)
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, uint16(CLASS_IN)) // 写入查询类
	if err != nil {
		logDebug(1, "写入DNS查询类失败: %v", err)
		return nil
	}

	return buf.Bytes()
}

// 从DNS响应中解析多个IP地址并返回
func parseDNSResponse(response []byte, qtype uint16) ([]string, error) {
	if len(response) < 12 {
		return nil, errors.New("响应过短")
	}

	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return nil, fmt.Errorf("解析DNS响应头部失败: %v", err)
	}

	rcode := header.Flags & 0x000F // 提取响应码
	if rcode != RCODE_NO_ERROR {   // 非0响应码表示错误
		return nil, fmt.Errorf("DNS错误: %d", rcode)
	}

	pos := 12
	_, consumed, err := parseDomainName(response, pos) //从问题部分解析域名
	if err != nil {
		return nil, err
	}
	pos += consumed + 4 // 跳过问题部分，QTYPE（2 字节）和 QCLASS（2 字节）

	ips := []string{}
	
	for i := 0; i < int(header.ANCount); i++ { // 遍历回答部分，每个回答部分报文格式相同

		if pos >= len(response) {
			return ips, errors.New("响应越界")
		}

		// 处理名称字段
		if response[pos]&0xC0 == 0xC0 { // 指针压缩
			pos += 2 // 跳过指针
		} else {
			// 域名 www.example.com 的编码为：
			// [3] w w w [7] e x a m p l e [3] c o m [0]
			for {
				if pos >= len(response) {
					return ips, errors.New("域名解析越界")
				}
				length := int(response[pos])
				pos++
				if length == 0 {
					break
				}
				pos += length
			}
		}

		// 检查是否有足够的字节读取资源记录头部
		if pos+10 > len(response) { // 10字节：2字节类型 + 2字节类 + 4字节TTL + 2字节RDLENGTH
			return ips, errors.New("资源记录头部不完整")
		}

		// NAME      TYPE   CLASS   TTL   RDLENGTH   RDATA
		// <标签编码> 2字节  2字节  4字节   2字节     可变长度

		rrType := binary.BigEndian.Uint16(response[pos:]) // 资源记录类型
		pos += 2
		rrClass := binary.BigEndian.Uint16(response[pos:]) // 资源记录类
		pos += 2
		pos += 4
		rdLength := binary.BigEndian.Uint16(response[pos:]) // 资源数据长度
		pos += 2

		if rrClass != CLASS_IN { // 非IN类记录
			pos += int(rdLength) // 跳过数据
			continue
		}

		// 检查数据是否足够
		if pos+int(rdLength) > len(response) { //rdLength字节，即RDATA的长度
			return ips, errors.New("资源记录数据不完整")
		}

		if rrType == qtype {
			if qtype == TYPE_A && rdLength == 4 { // IPv4地址
				ip := net.IPv4(response[pos], response[pos+1], response[pos+2], response[pos+3]).String()
				ips = append(ips, ip)
			} else if qtype == TYPE_AAAA && rdLength == 16 { // IPv6地址
				ip := net.IP(response[pos : pos+16]).String()
				ips = append(ips, ip)
			}
		}

		pos += int(rdLength) // 进入下一个资源记录
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("未找到类型为%d的记录", qtype)
	}

	return ips, nil
}

// 获取下一个DNS报文ID
func getNextID() uint16 {
	idMutex.Lock()
	defer idMutex.Unlock()
	id := nextID
	nextID++
	return id
}

// 从映射文件中解析域名-IP映射关系
func parseMappingFile(filename string) {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	// 重置映射表
	mappingTable = nil

	file, err := os.Open(filename)
	if err != nil {
		logDebug(1, "无法打开映射文件: %s", filename)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if line == "" || line[0] == '#' {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			logDebug(1, "无效的行格式: %s", line)
			continue
		}

		domain := parts[0]
		ips := []string{}

		for i := 1; i < len(parts); i++ {
			ip := parts[i]
			if net.ParseIP(ip) == nil {
				logDebug(1, "无效的IP地址: %s", ip)
				continue
			}
			ips = append(ips, ip)
		}

		if len(ips) == 0 {
			continue
		}

		mappingTable = append(mappingTable, DomainIPMapping{
			Domain: domain,
			IPs:    ips,
		})
		count++
	}

	if err := scanner.Err(); err != nil {
		logDebug(1, "读取映射文件失败: %v", err)
	}

	logDebug(1, "解析映射文件 %s，共 %d 条记录", filename, count)
}

// 调试等级：0 - 无调试信息，1 - 基本调试信息
func logDebug(level int, format string, args ...interface{}) {
	if level > debugLevel {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", timestamp, msg)
}