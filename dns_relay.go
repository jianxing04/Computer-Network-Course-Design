package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// DNS报文头部结构
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// 资源记录结构
type ResourceRecord struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

// 域名-IP映射
type DomainIPMapping struct {
	Domain string
	IP     string
}

// 缓存项
type CacheEntry struct {
	Domain    string
	IP        string
	TTL       uint32
	Timestamp time.Time
}

// 全局变量
var (
	mappingTable []DomainIPMapping
	cache        []CacheEntry
	cacheMutex   sync.Mutex
	idMutex      sync.Mutex
	nextID       uint16 = 1
	externalDNS  string = "114.114.114.114"
	debugLevel   int    = 0
	cacheMaxSize int    = 100
	mappingCount int
	cacheCount   int
)

const (
	DNS_PORT         = 53
	MAX_PACKET_SIZE  = 512
	DEFAULT_TTL      = 3600 // 默认TTL 1小时
	TYPE_A           = 1    // A记录类型
	CLASS_IN         = 1    // IN类
	FLAG_RESPONSE    = 0x8000
	RCODE_NAME_ERROR = 3 // 域名不存在错误码
)

func main() {
	// 解析命令行参数
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d":
			debugLevel = 1
			if i+1 < len(args) {
				externalDNS = args[i+1]
				i++
			}
		case "-dd":
			debugLevel = 2
			if i+1 < len(args) {
				externalDNS = args[i+1]
				i++
			}
		default:
			if strings.HasSuffix(args[i], ".txt") {
				parseMappingFile(args[i])
			}
		}
	}

	// 如果没有指定映射文件，使用默认文件
	if mappingCount == 0 {
		parseMappingFile("dnsrelay.txt")
	}

	// 初始化缓存
	cache = make([]CacheEntry, cacheMaxSize)

	// 创建UDP服务器
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

	// 处理客户端请求
	buf := make([]byte, MAX_PACKET_SIZE)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("读取数据失败: %v", err)
			continue
		}

		// 处理请求
		go handleClientRequest(conn, clientAddr, buf[:n])
	}
}

// 处理客户端请求
func handleClientRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte) {
	clientIP := clientAddr.IP.String()
	logDebug(2, "收到客户端请求，IP: %s，长度: %d", clientIP, len(request))

	domain, qtype, err := parseDNSMessage(request)
	if err != nil {
		logDebug(1, "解析DNS请求失败: %v", err)
		// 发送错误响应
		response := buildErrorResponse(request, RCODE_NAME_ERROR)
		if response != nil {
			if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
				logDebug(1, "发送错误响应失败: %v", err)
			}
		}
		return
	}

	logDebug(1, "客户端查询: %s (类型: %d)", domain, qtype)

	ip, rcode := "", 0

	// 先检查缓存
	if cachedIP, found := lookupCache(domain); found {
		ip = cachedIP
		logDebug(2, "缓存命中: %s -> %s", domain, ip)
	} else {
		// 检查映射表
		if mappedIP, found := lookupMapping(domain); found {
			ip = mappedIP
			logDebug(2, "映射表命中: %s -> %s", domain, ip)

			// 如果IP是0.0.0.0，返回域名未找到
			if ip == "0.0.0.0" {
				ip = ""
				rcode = RCODE_NAME_ERROR
			}
		} else {
			// 转发到外部DNS服务器
			logDebug(1, "转发查询: %s", domain)
			if relayedIP, err := sendDNSQuery(domain, qtype); err == nil {
				ip = relayedIP
				logDebug(2, "转发成功: %s -> %s", domain, ip)
				addToCache(domain, ip, DEFAULT_TTL)
			} else {
				logDebug(1, "转发失败: %s: %v", domain, err)
				rcode = RCODE_NAME_ERROR
			}
		}
	}

	// 构建并发送响应
	response := buildDNSResponse(request, ip, rcode)
	if response != nil {
		if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
			logDebug(1, "发送响应失败: %v", err)
		}
	} else {
		logDebug(1, "构建DNS响应失败")
	}
}

// 解析DNS报文
func parseDNSMessage(buffer []byte) (string, uint16, error) {
	if len(buffer) < 12 {
		return "", 0, errors.New("报文过短")
	}

	// 解析头部
	header := DNSHeader{}
	reader := bytes.NewReader(buffer)
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return "", 0, fmt.Errorf("解析DNS头部失败: %v", err)
	}

	// 解析域名
	domain, err := parseDomainName(buffer, 12)
	if err != nil {
		return "", 0, err
	}

	// 跳过问题部分
	pos := 12 + len(domain) + 1 + 4 // 头部 + 域名 + 结束符 + QTYPE/QCLASS

	// 检查是否越界
	if pos+4 > len(buffer) {
		return "", 0, errors.New("无效的DNS查询，可能越界")
	}

	// 解析查询类型
	qtype := binary.BigEndian.Uint16(buffer[pos:])
	pos += 2
	//class := binary.BigEndian.Uint16(buffer[pos:])

	logDebug(3, "解析域名: %s, 类型: %d", domain, qtype)

	return domain, qtype, nil
}

// 解析域名
func parseDomainName(buffer []byte, offset int) (string, error) {
	var parts []string
	pos := offset

	for {
		if pos >= len(buffer) {
			return "", errors.New("无效的域名偏移")
		}

		length := int(buffer[pos])
		pos++

		if length == 0 {
			break // 域名结束
		}

		if length&0xC0 == 0xC0 { // 指针
			if pos >= len(buffer) {
				return "", errors.New("无效的域名指针")
			}
			pointer := int(binary.BigEndian.Uint16([]byte{byte(length & 0x3F), buffer[pos]}))
			pos++
			part, err := parseDomainName(buffer, pointer)
			if err != nil {
				return "", err
			}
			parts = append(parts, part)
			break
		}

		if pos+length > len(buffer) {
			return "", errors.New("域名超出范围")
		}

		parts = append(parts, string(buffer[pos:pos+length]))
		pos += length
	}

	return strings.Join(parts, "."), nil
}

// 构建DNS响应
func buildDNSResponse(request []byte, ip string, rcode int) []byte {
	if len(request) < 12 {
		return nil
	}

	// 复制请求报文
	response := make([]byte, len(request))
	copy(response, request)

	// 修改头部
	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		logDebug(1, "解析DNS响应头部失败: %v", err)
		return nil
	}

	header.Flags |= FLAG_RESPONSE // 设置为响应
	header.Flags &= 0xFFF0        // 清除响应码
	header.Flags |= uint16(rcode) // 设置响应码

	if ip != "" && rcode == 0 {
		header.ANCount = 1 // 设置回答数为1
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入DNS响应头部失败: %v", err)
		return nil
	}
	copy(response[:12], buf.Bytes())

	// 如果没有IP或存在错误，直接返回
	if ip == "" || rcode != 0 {
		return response
	}

	// 构建资源记录
	rr := buildResourceRecord(ip)
	if rr == nil {
		logDebug(1, "构建资源记录失败")
		return nil
	}
	return append(response, rr...)
}

// 构建错误响应
func buildErrorResponse(request []byte, rcode int) []byte {
	if len(request) < 12 {
		return nil
	}

	// 复制请求报文
	response := make([]byte, len(request))
	copy(response, request)

	// 修改头部
	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		logDebug(1, "解析错误响应头部失败: %v", err)
		return nil
	}

	header.Flags |= FLAG_RESPONSE // 设置为响应
	header.Flags &= 0xFFF0        // 清除响应码
	header.Flags |= uint16(rcode) // 设置响应码
	header.ANCount = 0            // 无回答

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
func buildResourceRecord(ip string) []byte {
	buf := new(bytes.Buffer)

	// 使用指针指向查询中的域名
	buf.WriteByte(0xC0)
	buf.WriteByte(0x0C) // 指向请求中域名的位置

	// 类型 (A记录)
	err := binary.Write(buf, binary.BigEndian, uint16(TYPE_A))
	if err != nil {
		logDebug(1, "写入资源记录类型失败: %v", err)
		return nil
	}
	// 类 (IN)
	err = binary.Write(buf, binary.BigEndian, uint16(CLASS_IN))
	if err != nil {
		logDebug(1, "写入资源记录类失败: %v", err)
		return nil
	}
	// TTL (1小时)
	err = binary.Write(buf, binary.BigEndian, uint32(DEFAULT_TTL))
	if err != nil {
		logDebug(1, "写入资源记录TTL失败: %v", err)
		return nil
	}
	// 数据长度 (IPv4地址)
	err = binary.Write(buf, binary.BigEndian, uint16(4))
	if err != nil {
		logDebug(1, "写入资源记录数据长度失败: %v", err)
		return nil
	}

	// IP地址
	ipBytes := net.ParseIP(ip).To4()
	if ipBytes == nil {
		logDebug(1, "无效的IP地址: %s", ip)
		return nil
	}
	_, err = buf.Write(ipBytes)
	if err != nil {
		logDebug(1, "写入资源记录IP地址失败: %v", err)
		return nil
	}

	return buf.Bytes()
}

// 查找映射表
func lookupMapping(domain string) (string, bool) {
	for _, m := range mappingTable {
		if m.Domain == domain {
			return m.IP, true
		}
	}
	return "", false
}

// 查找缓存
func lookupCache(domain string) (string, bool) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	now := time.Now()
	for i := 0; i < cacheCount; i++ {
		if cache[i].Domain == domain && now.Before(cache[i].Timestamp.Add(time.Duration(cache[i].TTL)*time.Second)) {
			return cache[i].IP, true
		}
	}
	return "", false
}

// 添加到缓存
func addToCache(domain, ip string, ttl uint32) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	now := time.Now()

	// 检查是否已存在
	for i := 0; i < cacheCount; i++ {
		if cache[i].Domain == domain {
			cache[i].IP = ip
			cache[i].TTL = ttl
			cache[i].Timestamp = now
			return
		}
	}

	// 添加新条目
	if cacheCount < cacheMaxSize {
		cache[cacheCount] = CacheEntry{
			Domain:    domain,
			IP:        ip,
			TTL:       ttl,
			Timestamp: now,
		}
		cacheCount++
	} else {
		// 替换最早的条目
		oldest := 0
		for i := 1; i < cacheMaxSize; i++ {
			if cache[i].Timestamp.Before(cache[oldest].Timestamp) {
				oldest = i
			}
		}
		cache[oldest] = CacheEntry{
			Domain:    domain,
			IP:        ip,
			TTL:       ttl,
			Timestamp: now,
		}
	}
}

// 发送DNS查询
func sendDNSQuery(domain string, qtype uint16) (string, error) {
	// 创建UDP连接
	conn, err := net.Dial("udp", externalDNS+":53")
	if err != nil {
		return "", fmt.Errorf("连接外部DNS服务器失败: %v", err)
	}
	defer conn.Close()

	// 设置超时
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 构建查询
	query := buildDNSQuery(domain, qtype)
	if query == nil {
		return "", errors.New("构建DNS查询失败")
	}
	if _, err := conn.Write(query); err != nil {
		return "", fmt.Errorf("发送DNS查询失败: %v", err)
	}

	// 接收响应
	response := make([]byte, MAX_PACKET_SIZE)
	n, err := conn.Read(response)
	if err != nil {
		return "", fmt.Errorf("接收DNS响应失败: %v", err)
	}

	// 解析响应
	ip, err := parseDNSResponse(response[:n])
	if err != nil {
		return "", fmt.Errorf("解析DNS响应失败: %v", err)
	}

	return ip, nil
}

// 构建DNS查询
func buildDNSQuery(domain string, qtype uint16) []byte {
	buf := new(bytes.Buffer)

	// 头部
	header := DNSHeader{
		ID:      getNextID(),
		Flags:   0x0100, // 标准查询
		QDCount: 1,
	}
	err := binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入DNS查询头部失败: %v", err)
		return nil
	}

	// 域名
	labels := strings.Split(domain, ".")
	for _, label := range labels {
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
	err = buf.WriteByte(0) // 结束符
	if err != nil {
		logDebug(1, "写入DNS查询域名结束符失败: %v", err)
		return nil
	}

	// 查询类型和类
	err = binary.Write(buf, binary.BigEndian, qtype)
	if err != nil {
		logDebug(1, "写入DNS查询类型失败: %v", err)
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, uint16(CLASS_IN))
	if err != nil {
		logDebug(1, "写入DNS查询类失败: %v", err)
		return nil
	}

	return buf.Bytes()
}

// 解析DNS响应
func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}

	// 解析头部
	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return "", fmt.Errorf("解析DNS响应头部失败: %v", err)
	}

	// 检查响应码
	rcode := header.Flags & 0x000F
	if rcode != 0 {
		return "", fmt.Errorf("DNS错误: %d", rcode)
	}

	// 跳过问题部分
	pos := 12
	domain, err := parseDomainName(response, pos)
	if err != nil {
		return "", err
	}
	pos += len(domain) + 1 + 4 // 域名 + 结束符 + QTYPE/QCLASS

	// 解析回答部分
	for i := 0; i < int(header.ANCount); i++ {
		// 跳过名称 (可能是指针)
		if pos+2 > len(response) {
			return "", errors.New("无效的响应，可能越界")
		}

		if response[pos]&0xC0 == 0xC0 { // 指针
			pos += 2
		} else { // 标准名称
			for response[pos] != 0 {
				length := int(response[pos])
				pos += 1 + length
			}
			pos++ // 跳过结束符
		}

		if pos+10 > len(response) {
			return "", errors.New("无效的资源记录，可能越界")
		}

		// 解析资源记录
		rrType := binary.BigEndian.Uint16(response[pos:])
		pos += 2
		//rrClass := binary.BigEndian.Uint16(response[pos:])
		pos += 2
		ttl := binary.BigEndian.Uint32(response[pos:])
		pos += 4
		rdLength := binary.BigEndian.Uint16(response[pos:])
		pos += 2

		if rrType == TYPE_A && rdLength == 4 {
			if pos+4 > len(response) {
				return "", errors.New("无效的IP地址，可能越界")
			}

			ip := net.IPv4(response[pos], response[pos+1], response[pos+2], response[pos+3]).String()
			addToCache(domain, ip, ttl)
			return ip, nil
		}

		pos += int(rdLength)
	}

	return "", errors.New("未找到A记录")
}

// 获取下一个ID
func getNextID() uint16 {
	idMutex.Lock()
	defer idMutex.Unlock()
	id := nextID
	nextID++
	return id
}

// 解析映射文件
func parseMappingFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		logDebug(1, "无法打开映射文件: %s", filename)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// 跳过注释和空行
		if line == "" || line[0] == '#' {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		ip := parts[0]
		domain := parts[1]

		// 检查IP地址是否有效
		if net.ParseIP(ip) == nil {
			logDebug(1, "无效的IP地址: %s 在映射文件 %s 中", ip, filename)
			continue
		}

		// 添加到映射表
		mappingTable = append(mappingTable, DomainIPMapping{
			Domain: domain,
			IP:     ip,
		})
		mappingCount++
	}

	logDebug(1, "解析映射文件 %s，共 %d 条记录", filename, mappingCount)
}

// 调试日志
func logDebug(level int, format string, args ...interface{}) {
	if level > debugLevel {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", timestamp, msg)
}
