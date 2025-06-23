package main

import (
	"bufio"
	"bytes"
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
)

// +---------------------+
// |        头部         |
// +---------------------+
// |       问题部分      |
// +---------------------+
// |      回答部分       |
// +---------------------+
// |      授权部分       |
// +---------------------+
// |      附加部分       |
// +---------------------+

// DNS报文头部结构
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  ID                           | 2 字节
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |QR| Opcode |AA|TC|RD|RA| Z | RCODE |            | 2 字节（标志 Flags）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  QDCOUNT                      | 2 字节（问题数）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  ANCOUNT                      | 2 字节（回答数）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  NSCOUNT                      | 2 字节（授权记录数）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  ARCOUNT                      | 2 字节（附加记录数）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
}

// 资源记录结构
type ResourceRecord struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  NAME                         |  可变长度，域名（标签编码或压缩指针）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  TYPE                         |  2 字节，记录类型（如 A、AAAA、CNAME 等）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  CLASS                        |  2 字节，记录类（通常为 IN）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  TTL                          |  4 字节，生存时间（秒）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |               RDLENGTH                        |  2 字节，RDATA 部分长度
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |               RDATA                           |  可变长度，具体资源数据
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
}

// 域名-IP映射
type DomainIPMapping struct {
	Domain string
	IPs    []string // 修改为支持多个IP
}

// 缓存项
type CacheEntry struct {
	Domain    string
	IPs       []string // 修改为支持多个IP
	TTL       uint32
	Timestamp time.Time
}

// 全局变量
var (
	mappingTable   []DomainIPMapping
	cache          []CacheEntry
	cacheMutex     sync.RWMutex
	idMutex        sync.Mutex
	nextID         uint16 = 1
	externalDNS    string = "114.114.114.114"
	defaultMapping string = "dnsrelay.txt"
	debugLevel     int    = 0
	cacheMaxSize   int    = 100
	mappingCount   int
	cacheCount     int
	shutdownSignal chan struct{}
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
	RCODE_NAME_ERROR = 3      // 名称错误
	RCODE_NOT_IMP    = 4      // 未实现
	MAX_DOMAIN_LEN   = 253    // 最大域名长度
)

func main() {
	shutdownSignal = make(chan struct{})
	defer close(shutdownSignal)

	// 创建一个信号通道，用于接收操作系统信号
	sigChan := make(chan os.Signal, 1)
	// 监听 SIGINT（Ctrl+C）和 SIGTERM 信号
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 定义命令行标志
	debugLevelFlag := flag.Int("debug", 0, "调试等级 (0: 无调试信息, 1: 基本调试信息, 2: 详细调试信息)")
	externalDNSFlag := flag.String("dns", "114.114.114.114", "外部 DNS 服务器地址")
	mappingFilesFlag := flag.String("mapping", defaultMapping, "域名-IP 映射文件，多个文件用逗号分隔")

	// 解析命令行标志
	flag.Parse()

	// 设置全局变量
	debugLevel = *debugLevelFlag
	externalDNS = *externalDNSFlag

	// 解析映射文件
	mappingFiles := strings.Split(*mappingFilesFlag, ",")
	for _, file := range mappingFiles {
		file = strings.TrimSpace(file)
		if file != "" {
			parseMappingFile(file)
		}
	}

	if mappingCount == 0 {
		parseMappingFile(defaultMapping)
	}

	cache = make([]CacheEntry, cacheMaxSize)

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", DNS_PORT))
	if err != nil {
		log.Fatalf("解析地址失败: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("监听端口失败: %v", err)
	}
	defer conn.Close()

	log.Printf("DNS中继服务器启动，监听端口%d，外部DNS服务器: %s", DNS_PORT, externalDNS)

	buf := make([]byte, MAX_PACKET_SIZE)

	go func() {
		// 监听信号通道
		sig := <-sigChan
		log.Printf("接收到信号: %v，停止服务", sig)
		// 往 shutdownSignal 通道发送信号
		close(shutdownSignal)
	}()

	for {
		select {
		case <-shutdownSignal:
			log.Println("接收到关闭信号，停止服务")
			return
		default:
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 检查是否收到关闭信号
					select {
					case <-shutdownSignal:
						log.Println("接收到关闭信号，停止服务")
						return
					default:
						logDebug(1, "读取超时: %v", err)
						continue
					}
				}
				logDebug(1, "读取数据失败: %v", err)
				continue
			}

			go func() {
				select {
				case <-shutdownSignal:
					return
				default:
					handleClientRequest(conn, clientAddr, buf[:n])
				}
			}()
		}
	}
}

func handleClientRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte) {
	defer func() {
		if r := recover(); r != nil {
			logDebug(1, "处理请求时发生panic: %v", r)
		}
	}()

	clientIP := clientAddr.IP.String()
	logDebug(2, "收到客户端请求，IP: %s，长度: %d", clientIP, len(request))

	if len(request) < 12 { // DNS报文头部至少需要12字节
		logDebug(1, "请求过短: %d字节", len(request))
		response := buildErrorResponse(request, RCODE_NAME_ERROR) // 报文头部RCODE字段设为NAME_ERROR
		if response != nil {                                      // 如果构建响应成功
			if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
				logDebug(1, "发送错误响应失败: %v", err)
			}
		}
		return
	}

	domain, qtype, _, err := parseDNSMessage(request)
	if err != nil {
		logDebug(1, "解析DNS请求失败: %v", err)
		response := buildErrorResponse(request, RCODE_NAME_ERROR) // 报文头部RCODE字段设为NAME_ERROR
		if response != nil {                                      // 如果构建响应成功
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
	rcode := 0

	if cachedIPs, found := lookupCache(domain); found { // 查找缓存
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
				addToCache(domain, ips, DEFAULT_TTL)
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
	var parts []string
	pos := offset
	totalBytes := 0 // 累计解析的字节数
	maxDepth := 10
	depth := 0

	for {
		if pos >= len(buffer) {
			return "", totalBytes, errors.New("域名解析越界")
		}

		depth++
		if depth > maxDepth {
			return "", totalBytes, errors.New("域名解析递归深度过大")
		}

		// www.example.com 在 DNS 报文中的存储格式为：
		// [3] w w w [7] e x a m p l e [3] c o m [0]

		length := int(buffer[pos]) // 读取标签长度
		pos++                      // 移动到标签内容
		totalBytes++               // 加.的长度

		if length == 0 {
			break
		}

		if length&0xC0 == 0xC0 { // 检测指针压缩
			if pos >= len(buffer) {
				return "", totalBytes, errors.New("无效的域名指针")
			}
			// 指针压缩格式为 11xx xxxx   xxxx xxxx ，这后14位即为偏移量，目前pos指向的是指针的第二个字节
			pointer := int(binary.BigEndian.Uint16([]byte{byte(length & 0x3F), buffer[pos]}))
			totalBytes = 2 // 指针压缩的长度为2字节

			part, _, err := parseDomainName(buffer, pointer)
			if err != nil {
				return "", totalBytes, err
			}
			parts = append(parts, part)
			break
		}

		if pos+length > len(buffer) {
			return "", totalBytes, errors.New("域名标签超出范围")
		}

		parts = append(parts, string(buffer[pos:pos+length])) // 读取标签内容
		pos += length
		totalBytes += length // 累加标签长度
	}

	return strings.Join(parts, "."), totalBytes, nil
}

// 修改为支持多个IP
func buildDNSResponse(request []byte, ips []string, rcode int, qtype uint16) []byte {
	if len(request) < 12 {
		return nil
	}

	response := make([]byte, len(request))
	copy(response, request)

	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		logDebug(1, "解析DNS响应头部失败: %v", err)
		return nil
	}

	// +--+-----+---+---+---+---+---+---+---+----+
	// |QR|Opcode|AA|TC|RD|RA| Z |AD|CD| RCODE  |
	// +--+-----+---+---+---+---+---+---+---+----+
	//  1    4    1   1   1   1   1   1   1   4

	header.Flags |= FLAG_RESPONSE
	header.Flags &= 0xFFF0
	header.Flags |= uint16(rcode)

	if len(ips) > 0 && rcode == 0 {
		header.ANCount = uint16(len(ips)) // 设置回答数为IP数量
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入DNS响应头部失败: %v", err)
		return nil
	}
	copy(response[:12], buf.Bytes())

	if len(ips) == 0 || rcode != 0 {
		return response
	}

	// 构建所有IP的资源记录
	for _, ip := range ips {
		rr := buildResourceRecord(ip, qtype)
		if rr == nil {
			logDebug(1, "构建资源记录失败: %s", ip)
			continue
		}

		// 检查响应大小
		if len(response)+len(rr) > MAX_PACKET_SIZE {
			logDebug(1, "响应过大，无法添加更多资源记录")
			break
		}

		response = append(response, rr...)
	}

	return response
}

// 构建错误响应
func buildErrorResponse(request []byte, rcode int) []byte {
	if len(request) < 12 {
		return nil
	}

	response := make([]byte, len(request))
	copy(response, request)

	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		logDebug(1, "解析错误响应头部失败: %v", err)
		return nil
	}

	// +--+------+---+---+---+---+---+---+---+------+
	// |QR|Opcode|AA |TC |RD |RA | Z |AD |CD | RCODE|
	// +--+------+---+---+---+---+---+---+---+------+
	//  1    4     1   1   1   1   1   1   1    4

	// QR（1 位）：查询/响应标志（0=查询，1=响应）
	// Opcode（4 位）：操作码（通常为 0，表示标准查询）
	// AA（1 位）：权威应答（仅响应时有效）
	// TC（1 位）：截断标志（消息是否被截断）
	// RD（1 位）：期望递归（客户端希望递归查询）
	// RA（1 位）：可用递归（服务器是否支持递归）
	// Z（1 位）：保留，必须为 0
	// AD（1 位）：认证数据（DNSSEC，通常为 0）
	// CD（1 位）：检查禁用（DNSSEC，通常为 0）
	// RCODE（4 位）：响应码（如 0=无错误，3=域名不存在等）

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
	copy(response[:12], buf.Bytes())

	return response
}

// 构建资源记录
func buildResourceRecord(ip string, qtype uint16) []byte {
	buf := new(bytes.Buffer)

	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  NAME                         |  可变长度，域名（标签编码或压缩指针）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  TYPE                         |  2 字节，记录类型（如 A、AAAA、CNAME 等）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  CLASS                        |  2 字节，记录类（通常为 IN）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                  TTL                          |  4 字节，生存时间（秒）
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |               RDLENGTH                        |  2 字节，RDATA 部分长度
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |               RDATA                           |  可变长度，具体资源数据
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	buf.WriteByte(0xC0)
	buf.WriteByte(0x0C) // 使用指针压缩，指向域名的起始位置（假设域名在12字节后）

	err := binary.Write(buf, binary.BigEndian, qtype) // 写入资源记录类型
	if err != nil {
		logDebug(1, "写入资源记录类型失败: %v", err)
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, uint16(CLASS_IN)) // 写入资源记录类
	if err != nil {
		logDebug(1, "写入资源记录类失败: %v", err)
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, uint32(DEFAULT_TTL)) // 写入资源记录TTL
	if err != nil {
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
	default: // 不支持的资源记录类型
		logDebug(1, "不支持的资源记录类型: %d", qtype)
		return nil
	}

	err = binary.Write(buf, binary.BigEndian, dataLength)
	if err != nil {
		logDebug(1, "写入资源记录数据长度失败: %v", err)
		return nil
	}

	_, err = buf.Write(ipBytes)
	if err != nil {
		logDebug(1, "写入资源记录IP地址失败: %v", err)
		return nil
	}

	return buf.Bytes()
}

// 查找域名-IP映射关系
func lookupMapping(domain string) ([]string, bool) {
	for _, m := range mappingTable {
		if m.Domain == domain {
			return m.IPs, true
		}
	}
	return nil, false
}

// 查找缓存
func lookupCache(domain string) ([]string, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	now := time.Now()
	for i := 0; i < cacheCount; i++ {
		if cache[i].Domain == domain {
			if now.Before(cache[i].Timestamp.Add(time.Duration(cache[i].TTL) * time.Second)) {
				return cache[i].IPs, true
			}
			return nil, false
		}
	}
	return nil, false
}

// 添加或更新缓存项
func addToCache(domain string, ips []string, ttl uint32) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	now := time.Now()

	for i := 0; i < cacheCount; i++ { // 遍历缓存
		if cache[i].Domain == domain { // 如果域名已存在
			cache[i].IPs = ips       // 更新IP地址列表
			cache[i].TTL = ttl       // 更新TTL
			cache[i].Timestamp = now // 更新时间戳
			logDebug(2, "更新缓存: %s -> %v (TTL: %d)", domain, ips, ttl)
			// 如果缓存项已存在且未过期，则不需要添加新项
			return
		}
	}

	if cacheCount < cacheMaxSize { // 如果缓存未满
		logDebug(2, "添加新缓存项: %s -> %v (TTL: %d)", domain, ips, ttl)
		cache[cacheCount] = CacheEntry{ // 添加新缓存项
			Domain:    domain,
			IPs:       ips,
			TTL:       ttl,
			Timestamp: now,
		}
		cacheCount++
	} else { // 如果缓存已满，替换最旧的项
		oldest := 0
		for i := 1; i < cacheMaxSize; i++ {
			if cache[i].Timestamp.Before(cache[oldest].Timestamp) { // 找到最旧的缓存项
				oldest = i
			}
		}
		cache[oldest] = CacheEntry{ // 替换最旧的缓存项
			Domain:    domain,
			IPs:       ips,
			TTL:       ttl,
			Timestamp: now,
		}
		logDebug(2, "替换最旧缓存项: %s -> %v (TTL: %d)", domain, ips, ttl)
	}
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

	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                      ID (16 bits)             |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                    QDCOUNT (16 bits)          |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                    ANCOUNT (16 bits)          |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                    NSCOUNT (16 bits)          |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                    ARCOUNT (16 bits)          |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	rcode := header.Flags & 0x000F // 提取响应码
	if rcode != 0 {                // 非0响应码表示错误
		return nil, fmt.Errorf("DNS错误: %d", rcode)
	}

	pos := 12
	domain, consumed, err := parseDomainName(response, pos) //从问题部分解析域名
	if err != nil {
		return nil, err
	}
	pos += consumed + 4 // 跳过问题部分，QTYPE（2 字节）和 QCLASS（2 字节）

	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                                               |
	// /                     QNAME                     /
	// /                                               /
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                     QTYPE                     |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                     QCLASS                    |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	ips := []string{}
	defer func() {
		if len(ips) > 0 {
			addToCache(domain, ips, DEFAULT_TTL) // 将解析到的IP地址添加到缓存
		}
	}()

	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                                               |
	// /                                               /
	// /                      NAME                     /
	// |                                               |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                      TYPE                     |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                     CLASS                     |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                      TTL                      |
	// |                                               |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                   RDLENGTH                    |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
	// /                     RDATA                     /
	// /                                               /
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	for i := 0; i < int(header.ANCount); i++ { // 遍历回答部分，每个回答部分报文格式相同

		// Header
		// Question
		// Answer 1（IP1）
		// Answer 2（IP2）
		// Answer 3（IP3）

		if pos >= len(response) {
			return ips, errors.New("响应越界")
		}

		// 处理名称字段
		if response[pos]&0xC0 == 0xC0 { // 指针压缩

			// 举例说明：
			// 报文中 Question 区有 www.example.com 的标签式编码。
			// Answer 区的 NAME 字段为 0xC0 0x0C，表示指向报文第 12 字节
			// （通常是 Question 区域的域名起始位置）。
			// 解析时跳转到第 12 字节，读取标签，得到 www.example.com。

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
	file, err := os.Open(filename)
	if err != nil {
		logDebug(1, "无法打开映射文件: %s", filename)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	cntHere := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if line == "" || line[0] == '#' {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			logDebug(1, "无效的行格式: %s (行 %d)", line, lineNum)
			continue
		}

		// 第一个部分是域名
		domain := parts[0]
		// 其余部分都是IP地址
		ips := []string{}

		for i := 1; i < len(parts); i++ {
			ip := parts[i]
			if net.ParseIP(ip) == nil {
				logDebug(1, "无效的IP地址: %s 在映射文件 %s 行 %d", ip, filename, lineNum)
				continue
			} // 检查IP地址有效性
			ips = append(ips, ip)
		}

		if len(ips) == 0 {
			continue
		} // 如果没有有效的IP地址，则跳过此行

		if len(domain) > MAX_DOMAIN_LEN {
			logDebug(1, "域名过长: %s (行 %d)", domain, lineNum)
			continue
		} // 检查域名长度

		mappingTable = append(mappingTable, DomainIPMapping{
			Domain: domain,
			IPs:    ips,
		}) // 记录映射关系

		cntHere++ // 统计当前文件的映射条数
	}

	if err := scanner.Err(); err != nil {
		logDebug(1, "读取映射文件失败: %v", err)
	}

	mappingCount += cntHere

	logDebug(1, "解析映射文件 %s，共 %d 条记录", filename, cntHere)
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
