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
	mappingTable   []DomainIPMapping
	cache          []CacheEntry
	cacheMutex     sync.RWMutex
	idMutex        sync.Mutex
	nextID         uint16 = 1
	externalDNS    string = "114.114.114.114"
	debugLevel     int    = 0
	cacheMaxSize   int    = 100
	mappingCount   int
	cacheCount     int
	shutdownSignal chan struct{}
)

const (
	DNS_PORT         = 53
	MAX_PACKET_SIZE  = 512
	DEFAULT_TTL      = 3600
	TYPE_A           = 1
	TYPE_AAAA        = 28
	TYPE_PTR         = 12
	CLASS_IN         = 1
	FLAG_RESPONSE    = 0x8000
	RCODE_NAME_ERROR = 3
	RCODE_NOT_IMP    = 4
	MAX_DOMAIN_LEN   = 253
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
	mappingFilesFlag := flag.String("mapping", "dnsrelay.txt", "域名-IP 映射文件，多个文件用逗号分隔")

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
		parseMappingFile("dnsrelay.txt")
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
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					logDebug(1, "读取超时: %v", err)
					continue
				}
				logDebug(1, "读取数据失败: %v", err)
				continue
			}

			go handleClientRequest(conn, clientAddr, buf[:n])
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

	if len(request) < 12 {
		logDebug(1, "请求过短: %d字节", len(request))
		response := buildErrorResponse(request, RCODE_NAME_ERROR)
		if response != nil {
			if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
				logDebug(1, "发送错误响应失败: %v", err)
			}
		}
		return
	}

	domain, qtype, _, err := parseDNSMessage(request)
	if err != nil {
		logDebug(1, "解析DNS请求失败: %v", err)
		response := buildErrorResponse(request, RCODE_NAME_ERROR)
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
		response := buildErrorResponse(request, RCODE_NOT_IMP)
		if response != nil {
			if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
				logDebug(1, "发送反向查询响应失败: %v", err)
			}
		}
		return
	}

	ip, rcode := "", 0

	if cachedIP, found := lookupCache(domain); found {
		ip = cachedIP
		logDebug(2, "缓存命中: %s -> %s", domain, ip)
	} else {
		if mappedIP, found := lookupMapping(domain); found {
			ip = mappedIP
			logDebug(2, "映射表命中: %s -> %s", domain, ip)
			if ip == "0.0.0.0" {
				ip = ""
				rcode = RCODE_NAME_ERROR
			}
		} else {
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

	response := buildDNSResponse(request, ip, rcode, qtype)
	if response != nil {
		if _, err := conn.WriteToUDP(response, clientAddr); err != nil {
			logDebug(1, "发送响应失败: %v", err)
		}
	} else {
		logDebug(1, "构建DNS响应失败")
	}
}

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

	domain, consumed, err := parseDomainName(buffer, 12)
	if err != nil {
		return "", 0, 0, err
	}

	if len(domain) > MAX_DOMAIN_LEN {
		return "", 0, 0, fmt.Errorf("域名过长: %d字符", len(domain))
	}

	pos := 12 + consumed
	if pos+4 > len(buffer) {
		return "", 0, 0, errors.New("DNS查询问题部分不完整")
	}

	qtype := binary.BigEndian.Uint16(buffer[pos:])

	logDebug(3, "解析域名: %s, 类型: %d, 消耗字节: %d", domain, qtype, consumed)

	return domain, qtype, consumed, nil
}

func parseDomainName(buffer []byte, offset int) (string, int, error) {
	var parts []string
	pos := offset
	totalBytes := 0
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

		length := int(buffer[pos])
		pos++
		totalBytes++

		if length == 0 {
			break
		}

		if length&0xC0 == 0xC0 {
			if pos >= len(buffer) {
				return "", totalBytes, errors.New("无效的域名指针")
			}

			pointer := int(binary.BigEndian.Uint16([]byte{byte(length & 0x3F), buffer[pos]}))
			pos++
			totalBytes++

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

		parts = append(parts, string(buffer[pos:pos+length]))
		pos += length
		totalBytes += length
	}

	return strings.Join(parts, "."), totalBytes, nil
}

func buildDNSResponse(request []byte, ip string, rcode int, qtype uint16) []byte {
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

	header.Flags |= FLAG_RESPONSE
	header.Flags &= 0xFFF0
	header.Flags |= uint16(rcode)

	if ip != "" && rcode == 0 {
		header.ANCount = 1
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入DNS响应头部失败: %v", err)
		return nil
	}
	copy(response[:12], buf.Bytes())

	if ip == "" || rcode != 0 {
		return response
	}

	rr := buildResourceRecord(ip, qtype)
	if rr == nil {
		logDebug(1, "构建资源记录失败")
		return nil
	}

	if len(response)+len(rr) > MAX_PACKET_SIZE {
		logDebug(1, "响应过大，无法添加资源记录")
		return response
	}

	return append(response, rr...)
}

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

	header.Flags |= FLAG_RESPONSE
	header.Flags &= 0xFFF0
	header.Flags |= uint16(rcode)
	header.ANCount = 0

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入错误响应头部失败: %v", err)
		return nil
	}
	copy(response[:12], buf.Bytes())

	return response
}

func buildResourceRecord(ip string, qtype uint16) []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(0xC0)
	buf.WriteByte(0x0C)

	err := binary.Write(buf, binary.BigEndian, qtype)
	if err != nil {
		logDebug(1, "写入资源记录类型失败: %v", err)
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, uint16(CLASS_IN))
	if err != nil {
		logDebug(1, "写入资源记录类失败: %v", err)
		return nil
	}
	err = binary.Write(buf, binary.BigEndian, uint32(DEFAULT_TTL))
	if err != nil {
		logDebug(1, "写入资源记录TTL失败: %v", err)
		return nil
	}

	var ipBytes []byte
	var dataLength uint16

	switch qtype {
	case TYPE_A:
		ipBytes = net.ParseIP(ip).To4()
		if ipBytes == nil {
			logDebug(1, "无效的IPv4地址: %s", ip)
			return nil
		}
		dataLength = 4
	case TYPE_AAAA:
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

func lookupMapping(domain string) (string, bool) {
	for _, m := range mappingTable {
		if m.Domain == domain {
			return m.IP, true
		}
	}
	return "", false
}

func lookupCache(domain string) (string, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	now := time.Now()
	for i := 0; i < cacheCount; i++ {
		if cache[i].Domain == domain {
			if now.Before(cache[i].Timestamp.Add(time.Duration(cache[i].TTL) * time.Second)) {
				return cache[i].IP, true
			}
			return "", false
		}
	}
	return "", false
}

func addToCache(domain, ip string, ttl uint32) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	now := time.Now()

	for i := 0; i < cacheCount; i++ {
		if cache[i].Domain == domain {
			cache[i].IP = ip
			cache[i].TTL = ttl
			cache[i].Timestamp = now
			return
		}
	}

	if cacheCount < cacheMaxSize {
		cache[cacheCount] = CacheEntry{
			Domain:    domain,
			IP:        ip,
			TTL:       ttl,
			Timestamp: now,
		}
		cacheCount++
	} else {
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

func sendDNSQuery(domain string, qtype uint16) (string, error) {
	conn, err := net.Dial("udp", externalDNS+":53")
	if err != nil {
		return "", fmt.Errorf("连接外部DNS服务器失败: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	query := buildDNSQuery(domain, qtype)
	if query == nil {
		return "", errors.New("构建DNS查询失败")
	}
	if _, err := conn.Write(query); err != nil {
		return "", fmt.Errorf("发送DNS查询失败: %v", err)
	}

	response := make([]byte, MAX_PACKET_SIZE)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", errors.New("DNS查询超时")
		}
		return "", fmt.Errorf("接收DNS响应失败: %v", err)
	}

	ip, err := parseDNSResponse(response[:n], qtype)
	if err != nil {
		return "", fmt.Errorf("解析DNS响应失败: %v", err)
	}

	return ip, nil
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	buf := new(bytes.Buffer)

	header := DNSHeader{
		ID:      getNextID(),
		Flags:   0x0100,
		QDCount: 1,
	}
	err := binary.Write(buf, binary.BigEndian, header)
	if err != nil {
		logDebug(1, "写入DNS查询头部失败: %v", err)
		return nil
	}

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
	err = buf.WriteByte(0)
	if err != nil {
		logDebug(1, "写入DNS查询域名结束符失败: %v", err)
		return nil
	}

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

func parseDNSResponse(response []byte, qtype uint16) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}

	header := DNSHeader{}
	reader := bytes.NewReader(response[:12])
	err := binary.Read(reader, binary.BigEndian, &header)
	if err != nil {
		return "", fmt.Errorf("解析DNS响应头部失败: %v", err)
	}

	rcode := header.Flags & 0x000F
	if rcode != 0 {
		return "", fmt.Errorf("DNS错误: %d", rcode)
	}

	pos := 12
	domain, consumed, err := parseDomainName(response, pos)
	if err != nil {
		return "", err
	}
	pos += consumed + 4 // 跳过问题部分

	for i := 0; i < int(header.ANCount); i++ {
		if pos >= len(response) {
			return "", errors.New("响应越界")
		}

		// 处理名称字段
		if response[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for {
				if pos >= len(response) {
					return "", errors.New("域名解析越界")
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
		if pos+10 > len(response) {
			return "", errors.New("资源记录头部不完整")
		}

		rrType := binary.BigEndian.Uint16(response[pos:])
		pos += 2
		rrClass := binary.BigEndian.Uint16(response[pos:])
		pos += 2
		ttl := binary.BigEndian.Uint32(response[pos:])
		pos += 4
		rdLength := binary.BigEndian.Uint16(response[pos:])
		pos += 2

		if rrClass != CLASS_IN {
			pos += int(rdLength)
			continue
		}

		// 检查数据是否足够
		if pos+int(rdLength) > len(response) {
			return "", errors.New("资源记录数据不完整")
		}

		if rrType == qtype {
			if qtype == TYPE_A && rdLength == 4 {
				ip := net.IPv4(response[pos], response[pos+1], response[pos+2], response[pos+3]).String()
				addToCache(domain, ip, ttl)
				return ip, nil
			} else if qtype == TYPE_AAAA && rdLength == 16 {
				ip := net.IP(response[pos : pos+16]).String()
				addToCache(domain, ip, ttl)
				return ip, nil
			}
		}

		pos += int(rdLength)
	}

	return "", fmt.Errorf("未找到类型为%d的记录", qtype)
}

func getNextID() uint16 {
	idMutex.Lock()
	defer idMutex.Unlock()
	id := nextID
	nextID++
	return id
}

func parseMappingFile(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		logDebug(1, "无法打开映射文件: %s", filename)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
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

		ip := parts[0]
		domain := parts[1]

		if net.ParseIP(ip) == nil {
			logDebug(1, "无效的IP地址: %s 在映射文件 %s 行 %d", ip, filename, lineNum)
			continue
		}

		if len(domain) > MAX_DOMAIN_LEN {
			logDebug(1, "域名过长: %s (行 %d)", domain, lineNum)
			continue
		}

		mappingTable = append(mappingTable, DomainIPMapping{
			Domain: domain,
			IP:     ip,
		})
		mappingCount++
	}

	if err := scanner.Err(); err != nil {
		logDebug(1, "读取映射文件失败: %v", err)
	}

	logDebug(1, "解析映射文件 %s，共 %d 条记录", filename, mappingCount)
}

func logDebug(level int, format string, args ...interface{}) {
	if level > debugLevel {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", timestamp, msg)
}
