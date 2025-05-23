#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ws2tcpip.h> // Required for inet_pton or InetPton

#pragma comment(lib, "ws2_32.lib")

#define MAX_CACHE_ENTRIES 1000
#define MAX_PACKET_SIZE 512
#define MAX_DOMAIN_LENGTH 256
#define MAX_IP_LENGTH 16
#define MAX_MAPPINGS 100

// DNS头部结构
typedef struct {
    unsigned short id;         // 会话标识
    unsigned short flags;      // 标志位
    unsigned short qdcount;    // 问题数
    unsigned short ancount;    // 回答资源记录数
    unsigned short nscount;    // 授权资源记录数
    unsigned short arcount;    // 附加资源记录数
} dns_header;

// DNS资源记录结构
typedef struct {
    unsigned char* name;       // 域名
    unsigned short type;       // 类型
    unsigned short class;      // 类
    unsigned int ttl;          // 生存时间
    unsigned short rdlength;   // 资源数据长度
    unsigned char* rdata;      // 资源数据
} dns_resource_record;

// 缓存条目结构
typedef struct {
    char domain[MAX_DOMAIN_LENGTH];
    char ip[MAX_IP_LENGTH];
    time_t timestamp;          // 缓存时间戳
    int ttl;                   // 生存时间（秒）
} cache_entry;

// 映射表条目结构
typedef struct {
    char domain[MAX_DOMAIN_LENGTH];
    char ip[MAX_IP_LENGTH];
} mapping_entry;

// 全局变量
cache_entry cache[MAX_CACHE_ENTRIES];
int cache_count = 0;
mapping_entry mappings[MAX_MAPPINGS];
int mapping_count = 0;
int debug_level = 2;
CRITICAL_SECTION cache_mutex;
CRITICAL_SECTION mapping_mutex;
CRITICAL_SECTION process_mutex;
char external_dns[16] = "114.114.114.114";  // 默认使用国内 DNS

// 进程控制块
typedef struct {
    unsigned int process_id;
    unsigned int request_count;
    time_t last_active;
} ProcessControlBlock;

#define MAX_PROCESSES 1024
ProcessControlBlock processes[MAX_PROCESSES];
unsigned int next_process_id = 1;

// 函数声明
void init_process_table();
unsigned int allocate_process_id();
unsigned int get_process_request_count(unsigned int process_id);
void log_debug(int level, const char* format, ...);
void parse_mapping_file(const char* filename);
int lookup_mapping(const char* domain, char* ip);
int lookup_cache(const char* domain, int type, char* ip);
void add_to_cache(const char* domain, const char* ip, int ttl);
int send_dns_query(const char* domain, int type, char* ip);
unsigned char* build_dns_response(unsigned char* request, int request_len, const char* ip, int rcode);
int parse_dns_message(unsigned char* buffer, int len, char* domain, int* type);
DWORD WINAPI handle_client(LPVOID arg);

// 初始化进程表
void init_process_table() {
    InitializeCriticalSection(&process_mutex);
    for (int i = 0; i < MAX_PROCESSES; i++) {
        processes[i].process_id = 0;
        processes[i].request_count = 0;
        processes[i].last_active = 0;
    }
}

// 分配新的进程ID
unsigned int allocate_process_id() {
    EnterCriticalSection(&process_mutex);
    unsigned int pid = 0;

    // 查找空闲槽位
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (processes[i].process_id == 0) {
            pid = next_process_id++;
            processes[i].process_id = pid;
            processes[i].request_count = 0;
            processes[i].last_active = time(NULL);
            LeaveCriticalSection(&process_mutex);
            return pid;
        }
    }

    // 如果没有找到空闲槽位，尝试回收长时间未活动的进程
    time_t now = time(NULL);
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (processes[i].last_active < now - 3600) { // 1小时未活动
            pid = next_process_id++;
            processes[i].process_id = pid;
            processes[i].request_count = 0;
            processes[i].last_active = now;
            LeaveCriticalSection(&process_mutex);
            return pid;
        }
    }

    LeaveCriticalSection(&process_mutex);
    return 0; // 无法分配进程ID
}

// 获取进程的请求计数
unsigned int get_process_request_count(unsigned int process_id) {
    EnterCriticalSection(&process_mutex);
    unsigned int count = 0;

    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (processes[i].process_id == process_id) {
            count = ++processes[i].request_count;
            processes[i].last_active = time(NULL);
            break;
        }
    }

    LeaveCriticalSection(&process_mutex);
    return count;
}

// 日志输出函数
void log_debug(int level, const char* format, ...) {
    if (level > debug_level) return;

    va_list args;
    va_start(args, format);

    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);

    char time_str[26];
    asctime_s(time_str, sizeof(time_str), tm_info);
    time_str[24] = '\0'; // 移除换行符

    printf("[%s] ", time_str);
    vprintf(format, args);
    printf("\n");

    va_end(args);
}

// 解析映射文件
void parse_mapping_file(const char* filename) {
    EnterCriticalSection(&mapping_mutex);

    FILE* file = fopen(filename, "r");
    if (!file) {
        log_debug(1, "无法打开映射文件: %s", filename);
        LeaveCriticalSection(&mapping_mutex);
        return;
    }

    char line[512];
    mapping_count = 0;

    while (fgets(line, sizeof(line), file) && mapping_count < MAX_MAPPINGS) {
        // 跳过注释行
        if (line[0] == '#' || line[0] == '\n') continue;

        char* domain = strtok(line, " \t\n");
        char* ip = strtok(NULL, " \t\n");

        if (domain && ip) {
            if (strlen(domain) < MAX_DOMAIN_LENGTH && strlen(ip) < MAX_IP_LENGTH) {
                strcpy_s(mappings[mapping_count].domain, MAX_DOMAIN_LENGTH, domain);
                strcpy_s(mappings[mapping_count].ip, MAX_IP_LENGTH, ip);
                mapping_count++;
            }
            else {
                log_debug(1, "映射文件中记录过长: %s -> %s", domain, ip);
            }
        }
    }

    fclose(file);
    log_debug(2, "解析映射文件完成，共 %d 条记录", mapping_count);
    LeaveCriticalSection(&mapping_mutex);
}

// 在映射表中查找域名
int lookup_mapping(const char* domain, char* ip) {
    if (!domain || !ip) return -1;

    EnterCriticalSection(&mapping_mutex);

    for (int i = 0; i < mapping_count; i++) {
        if (strcmp(mappings[i].domain, domain) == 0) {
            strcpy_s(ip, MAX_IP_LENGTH, mappings[i].ip);
            LeaveCriticalSection(&mapping_mutex);
            return 0; // 找到映射
        }
    }

    LeaveCriticalSection(&mapping_mutex);
    return -1; // 未找到映射
}

// 在缓存中查找域名
int lookup_cache(const char* domain, int type, char* ip) {
    if (!domain || !ip || type != 1) return -1; // 只处理A记录

    EnterCriticalSection(&cache_mutex);

    time_t now = time(NULL);
    int found = -1;

    for (int i = 0; i < cache_count; i++) {
        if (strcmp(cache[i].domain, domain) == 0) {
            // 检查缓存是否过期
            if (cache[i].timestamp + cache[i].ttl > now) {
                strcpy_s(ip, MAX_IP_LENGTH, cache[i].ip);
                found = 0;
                break;
            }
            else {
                // 缓存已过期，移除该条目
                for (int j = i; j < cache_count - 1; j++) {
                    cache[j] = cache[j + 1];
                }
                cache_count--;
                break;
            }
        }
    }

    LeaveCriticalSection(&cache_mutex);
    return found;
}

// 添加到缓存
void add_to_cache(const char* domain, const char* ip, int ttl) {
    if (!domain || !ip) return;

    if (cache_count >= MAX_CACHE_ENTRIES) {
        // 缓存已满，移除最旧的条目
        for (int i = 1; i < cache_count; i++) {
            cache[i - 1] = cache[i];
        }
        cache_count--;
    }

    EnterCriticalSection(&cache_mutex);

    if (strlen(domain) < MAX_DOMAIN_LENGTH && strlen(ip) < MAX_IP_LENGTH) {
        strcpy_s(cache[cache_count].domain, MAX_DOMAIN_LENGTH, domain);
        strcpy_s(cache[cache_count].ip, MAX_IP_LENGTH, ip);
        cache[cache_count].timestamp = time(NULL);
        cache[cache_count].ttl = ttl;
        cache_count++;
    }
    else {
        log_debug(1, "缓存记录过长: %s -> %s", domain, ip);
    }

    LeaveCriticalSection(&cache_mutex);
}

// 发送DNS查询到外部服务器
int send_dns_query(const char* domain, int type, char* ip) {
    if (!domain || !ip || type != 1) return -1;

    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server_addr;
    unsigned char request[MAX_PACKET_SIZE];
    unsigned char response[MAX_PACKET_SIZE];
    int request_len, response_len;
    int ret = -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        log_debug(1, "WSAStartup failed");
        return -1;
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        log_debug(1, "Socket creation failed");
        WSACleanup();
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    // Replace the deprecated inet_addr with InetPton
    wchar_t wide_external_dns[16];
    size_t converted_chars = 0;
    mbstowcs_s(&converted_chars, wide_external_dns, 16, external_dns, _TRUNCATE); // Convert char to wchar_t
    if (InetPton(AF_INET, wide_external_dns, &server_addr.sin_addr) != 1) {
        log_debug(1, "Invalid external DNS address: %s", external_dns);
        closesocket(sock);
        WSACleanup();
        return -1; // Handle error if the address is invalid
    }

    // 构建DNS请求
    dns_header* header = (dns_header*)request;
    header->id = htons((unsigned short)rand());
    header->flags = htons(0x0100); // 标准查询
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    request_len = sizeof(dns_header);

    // 添加域名
    const char* p = domain;
    char label[64];
    int label_len = 0;

    while (*p) {
        if (*p == '.') {
            request[request_len++] = label_len;
            memcpy(&request[request_len], label, label_len);
            request_len += label_len;
            label_len = 0;
        }
        else {
            label[label_len++] = *p;
        }
        p++;
    }

    if (label_len > 0) {
        request[request_len++] = label_len;
        memcpy(&request[request_len], label, label_len);
        request_len += label_len;
    }

    request[request_len++] = 0; // 域名结束标志

    // 添加查询类型和类
    unsigned short qtype = htons(type);
    unsigned short qclass = htons(1); // IN类

    memcpy(&request[request_len], &qtype, sizeof(qtype));
    request_len += sizeof(qtype);
    memcpy(&request[request_len], &qclass, sizeof(qclass));
    request_len += sizeof(qclass);

    // 发送请求
    if (sendto(sock, (char*)request, request_len, 0,
        (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        log_debug(1, "发送DNS查询失败");
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    // 接收响应
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    int select_result = select((int)(sock + 1), &readfds, NULL, NULL, &timeout);
    if (select_result > 0) {
        response_len = recvfrom(sock, (char*)response, MAX_PACKET_SIZE, 0, NULL, NULL);
        if (response_len > 0) {
            // 解析响应
            dns_header* resp_header = (dns_header*)response;
            unsigned short ancount = ntohs(resp_header->ancount);

            if (ancount > 0) {
                // 查找问题部分的结束位置
                int pos = sizeof(dns_header);
                while (response[pos] != 0) {
                    pos += response[pos] + 1;
                }
                pos += 4; // 跳过QTYPE和QCLASS

                // 解析回答部分
                for (int i = 0; i < ancount && pos < response_len; i++) {
                    // 跳过域名（可能是压缩格式）
                    if ((response[pos] & 0xC0) == 0xC0) {
                        pos += 2; // 压缩域名
                    }
                    else {
                        while (response[pos] != 0) {
                            pos += response[pos] + 1;
                        }
                        pos++;
                    }

                    // 解析类型、类、TTL和RDATA长度
                    unsigned short type = ntohs(*(unsigned short*)&response[pos]);
                    pos += 2;
                    pos += 2; // 跳过类
                    unsigned int ttl = ntohl(*(unsigned int*)&response[pos]);
                    pos += 4;
                    unsigned short rdlength = ntohs(*(unsigned short*)&response[pos]);
                    pos += 2;

                    // 如果是A记录，提取IP地址
                    if (type == 1 && rdlength == 4) {
                        sprintf_s(ip, MAX_IP_LENGTH, "%d.%d.%d.%d",
                            response[pos], response[pos + 1], response[pos + 2], response[pos + 3]);
                        add_to_cache(domain, ip, ttl);
                        ret = 0;
                        break;
                    }

                    pos += rdlength;
                }
            }
        }
    }

    closesocket(sock);
    WSACleanup();
    return ret;
}

// 解析DNS消息中的域名
int parse_domain(unsigned char* buffer, int pos, char* domain) {
    if (!buffer || !domain) return -1;

    int len = 0;
    int offset = 0;
    int jumped = 0;

    while (buffer[pos] != 0) {
        if ((buffer[pos] & 0xC0) == 0xC0) {
            // 指针（压缩格式）
            if (!jumped) {
                offset = pos + 2;
            }
            pos = ((buffer[pos] & 0x3F) << 8) | buffer[pos + 1];
            jumped = 1;
        }
        else {
            // 标签
            int label_len = buffer[pos];
            if (len > 0) {
                domain[len++] = '.';
            }
            memcpy(&domain[len], &buffer[pos + 1], label_len);
            len += label_len;
            pos += label_len + 1;
        }
    }

    domain[len] = '\0';
    return jumped ? offset : pos + 1;
}

// 解析DNS消息
int parse_dns_message(unsigned char* buffer, int len, char* domain, int* type) {
    if (!buffer || !domain || !type || len < sizeof(dns_header)) return -1;

    dns_header* header = (dns_header*)buffer;
    unsigned short qdcount = ntohs(header->qdcount);

    if (qdcount < 1) return -1;

    // 解析问题部分
    int pos = sizeof(dns_header);

    // 解析域名
    pos = parse_domain(buffer, pos, domain);

    if (pos >= len - 4) return -1;

    // 解析查询类型和类
    *type = ntohs(*(unsigned short*)&buffer[pos]);
    pos += 4; // 跳过QTYPE和QCLASS

    return pos;
}

// 构建DNS响应
unsigned char* build_dns_response(unsigned char* request, int request_len, const char* ip, int rcode) {
    if (!request || request_len < sizeof(dns_header)) return NULL;

    dns_header* req_header = (dns_header*)request;
    unsigned char* response = (unsigned char*)malloc(MAX_PACKET_SIZE);
    if (!response) return NULL;

    memcpy(response, request, request_len);

    dns_header* resp_header = (dns_header*)response;
    resp_header->flags = htons(0x8180 | (rcode & 0x0F)); // 响应标志 + RCODE
    resp_header->qdcount = req_header->qdcount;

    if (rcode == 0 && ip && strlen(ip) > 0) {
        // 有回答
        resp_header->ancount = htons(1);
    }
    else {
        // 无回答
        resp_header->ancount = 0;
    }

    resp_header->nscount = 0;
    resp_header->arcount = 0;

    int pos = sizeof(dns_header);

    // 复制问题部分
    while (pos < request_len && request[pos] != 0) {
        pos++;
    }
    pos++; // 跳过0终止符
    pos += 4; // 跳过QTYPE和QCLASS

    if (rcode == 0 && ip && strlen(ip) > 0) {
        // 添加回答部分
        // 域名（使用指针）
        response[pos++] = 0xC0;
        response[pos++] = 0x0C; // 指向问题部分的域名

        // 类型和类
        unsigned short type = htons(1); // A记录
        unsigned short class = htons(1); // IN类
        memcpy(&response[pos], &type, sizeof(type));
        pos += sizeof(type);
        memcpy(&response[pos], &class, sizeof(class));
        pos += sizeof(class);

        // TTL (3600秒)
        unsigned int ttl = htonl(3600);
        memcpy(&response[pos], &ttl, sizeof(ttl));
        pos += sizeof(ttl);

        // RDLENGTH (4字节)
        unsigned short rdlength = htons(4);
        memcpy(&response[pos], &rdlength, sizeof(rdlength));
        pos += sizeof(rdlength);

        // RDATA (IP地址)
        unsigned char ip_parts[4];
        sscanf_s(ip, "%hhu.%hhu.%hhu.%hhu", &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]);
        memcpy(&response[pos], ip_parts, 4);
        pos += 4;
    }

    return response;
}

// 处理客户端请求线程函数
DWORD WINAPI handle_client(LPVOID arg) {
    if (arg == NULL) {
        log_debug(1, "handle_client 收到NULL参数");
        return 1;
    }

    // 解析参数
    SOCKET sockfd;
    int request_len;
    struct sockaddr_in client_addr;

    memcpy(&sockfd, arg, sizeof(SOCKET));
    memcpy(&request_len, (char*)arg + sizeof(SOCKET), sizeof(int));
    memcpy(&client_addr, (char*)arg + sizeof(SOCKET) + sizeof(int), sizeof(client_addr));

    // 验证请求长度
    if (request_len <= 0 || request_len > MAX_PACKET_SIZE) {
        log_debug(1, "收到无效的请求长度: %d", request_len);
        free(arg);
        return 1;
    }

    // 复制请求数据
    unsigned char* buffer = (unsigned char*)malloc(request_len);
    if (!buffer) {
        log_debug(1, "内存分配失败");
        free(arg);
        return 1;
    }

    memcpy(buffer, (unsigned char*)arg + sizeof(SOCKET) + sizeof(int), request_len);
    free(arg);

    // 分配进程ID和请求计数
    unsigned int process_id = allocate_process_id();
    if (process_id == 0) {
        log_debug(1, "无法分配进程ID");
        free(buffer);
        return 1;
    }

    unsigned int req_count = get_process_request_count(process_id);

    // 解析DNS请求
    char domain[MAX_DOMAIN_LENGTH] = { 0 };
    int type = 0;

    if (parse_dns_message(buffer, request_len, domain, &type) < 0) {
        log_debug(1, "解析DNS请求失败");
        free(buffer);
        return 1;
    }

    // 记录请求日志
    log_debug(1, "收到第%u个进程的第%u个请求: %s (类型: %d)",
        process_id, req_count, domain, type);

    // 准备响应数据
    char ip[MAX_IP_LENGTH] = { 0 };
    int rcode = 0; // 响应码，0表示成功
    char source_str[30] = { 0 };

    // 1. 检查本地缓存
    if (lookup_cache(domain, type, ip) == 0) {
        strcpy_s(source_str, sizeof(source_str), "cache");
        log_debug(2, "缓存命中: %s -> %s", domain, ip);
    }
    // 2. 检查映射文件
    else if (lookup_mapping(domain, ip) == 0) {
        strcpy_s(source_str, sizeof(source_str), "dnsrelay.txt");
        log_debug(2, "映射文件命中: %s -> %s", domain, ip);

        // 如果IP是0.0.0.0，表示域名不存在
        if (strcmp(ip, "0.0.0.0") == 0) {
            strcpy_s(ip, MAX_IP_LENGTH, "");
            rcode = 3; // 域名不存在
        }
    }
    // 3. 中继到外部DNS服务器
    else {
        log_debug(1, "中继查询: %s", domain);
        if (send_dns_query(domain, type, ip) == 0) {
            strcpy_s(source_str, sizeof(source_str), "外部DNS");
            log_debug(2, "中继成功: %s -> %s", domain, ip);
        }
        else {
            strcpy_s(source_str, sizeof(source_str), "查询失败");
            rcode = 3; // 域名不存在
            log_debug(1, "中继失败: %s", domain);
        }
    }

    // 构建并发送响应
    unsigned char* response = build_dns_response(buffer, request_len, ip, rcode);
    if (response) {
        int response_len = MAX_PACKET_SIZE;

        // 记录响应日志
        if (rcode == 0 && strlen(ip) > 0) {
            log_debug(1, "应答进程%u的请求%u，结果为: %s -> %s，查询结果来自%s",
                process_id, req_count, domain, ip, source_str);
        }
        else {
            log_debug(1, "应答进程%u的请求%u，结果为: 域名不存在，查询结果来自%s",
                process_id, req_count, source_str);
        }

        // 发送响应
        if (sendto(sockfd, (char*)response, response_len, 0,
            (struct sockaddr*)&client_addr, sizeof(client_addr)) == SOCKET_ERROR) {
            log_debug(1, "发送DNS响应失败: %d", WSAGetLastError());
        }

        free(response);
    }
    else {
        log_debug(1, "构建DNS响应失败");
    }

    free(buffer);
    return 0;
}

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    SOCKET sockfd;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);
    int port = 53; // DNS标准端口

    // 初始化调试级别
    debug_level = 2;

    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            if (strlen(argv[i + 1]) < MAX_IP_LENGTH) {
                strcpy_s(external_dns, MAX_IP_LENGTH, argv[++i]);
            }
            else {
                log_debug(1, "外部DNS地址过长: %s", argv[i + 1]);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
            if (port < 1 || port > 65535) {
                log_debug(1, "无效的端口号: %d", port);
                return 1;
            }
        }
        else if (strcmp(argv[i], "-v") == 0) {
            debug_level = 3;
        }
    }

    // 初始化进程表和同步原语
    init_process_table();
    InitializeCriticalSection(&cache_mutex);
    InitializeCriticalSection(&mapping_mutex);

    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // 设置套接字选项，允许地址重用
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("setsockopt failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    // 绑定地址和端口
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    // Replace the deprecated inet_addr with InetPton
    wchar_t ip_address[10];
    size_t converted_chars = 0;
    mbstowcs_s(&converted_chars, ip_address, 10, "127.0.0.1", _TRUNCATE); // Convert char to wchar_t
    if (InetPton(AF_INET, ip_address, &server_addr.sin_addr) != 1) {
        printf("Invalid IP address format\n");
        closesocket(sockfd);
        WSACleanup();
        return 1; // Handle error if the address is invalid
    }

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    printf("DNS中继服务器启动，监听端口 %d，外部DNS服务器: %s\n", port, external_dns);

    // 解析映射文件
    parse_mapping_file("dnsrelay.txt");

    // 主循环
    while (1) {
        // 接收客户端请求
        unsigned char buffer[MAX_PACKET_SIZE];
        int request_len = recvfrom(sockfd, (char*)buffer, MAX_PACKET_SIZE, 0,
            (struct sockaddr*)&client_addr, &client_len);

        if (request_len > 0) {
            // 为每个请求分配内存并复制数据
            int data_size = sizeof(SOCKET) + sizeof(int) + sizeof(client_addr) + request_len;
            void* thread_data = malloc(data_size);
            if (thread_data) {
                memcpy(thread_data, &sockfd, sizeof(SOCKET));
                memcpy((char*)thread_data + sizeof(SOCKET), &request_len, sizeof(int));
                memcpy((char*)thread_data + sizeof(SOCKET) + sizeof(int), &client_addr, sizeof(client_addr));
                memcpy((char*)thread_data + sizeof(SOCKET) + sizeof(int) + sizeof(client_addr), buffer, request_len);

                // 创建线程处理请求
                HANDLE thread_id = CreateThread(NULL, 0, handle_client, thread_data, 0, NULL);
                if (thread_id == NULL) {
                    log_debug(1, "创建线程失败");
                    free(thread_data);
                }
                else {
                    CloseHandle(thread_id); // 关闭线程句柄，不等待线程结束
                }
            }
            else {
                log_debug(1, "内存分配失败");
            }
        }
    }

    // 清理资源
    closesocket(sockfd);
    WSACleanup();
    DeleteCriticalSection(&cache_mutex);
    DeleteCriticalSection(&mapping_mutex);
    DeleteCriticalSection(&process_mutex);

    return 0;
}