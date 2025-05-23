#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>      // Windows套接字API
#include <ws2tcpip.h>      // Windows TCP/IP扩展
#include <windows.h>       // Windows基础API
#include <time.h>

#pragma comment(lib, "ws2_32.lib")  // 链接Winsock库

// DNS报文头部结构
typedef struct {
    unsigned short id;          // 查询ID
    unsigned short flags;       // 标志位
    unsigned short qdcount;     // 问题数
    unsigned short ancount;     // 回答数
    unsigned short nscount;     // 授权服务器数
    unsigned short arcount;     // 附加资源数
} dns_header;

// 域名资源记录结构
typedef struct {
    unsigned short type;        // 资源类型
    unsigned short _class;      // 资源类
    unsigned int ttl;           // 生存时间
    unsigned short rdlength;    // 资源数据长度
    unsigned char rdata[256];   // 资源数据
} dns_resource_record;

// 域名-IP映射结构
typedef struct {
    char domain[256];
    char ip[16];
} domain_ip_mapping;

// 缓存项结构
typedef struct {
    char domain[256];
    char ip[16];
    unsigned int ttl;
    time_t timestamp;
} cache_entry;

typedef struct {
    unsigned int process_id;     // 进程ID
    unsigned int request_count;  // 该进程的请求计数
    time_t last_active;          // 最后活跃时间
} ProcessControlBlock;

#define MAX_PROCESSES 1024       // 最大同时处理的进程数
ProcessControlBlock processes[MAX_PROCESSES];
CRITICAL_SECTION process_mutex;  // 保护进程表的临界区

typedef enum {
    SOURCE_CACHE,      // 来自缓存
    SOURCE_FILE,       // 来自配置文件
    SOURCE_RELAY,      // 来自外部中继
    SOURCE_ERROR       // 查询错误
} ResponseSource;

// 定义客户端请求结构体
typedef struct {
    SOCKET sockfd;                   // 套接字描述符
    struct sockaddr_in client_addr;  // 客户端地址
    unsigned char* buffer;           // 请求数据缓冲区
    int len;                         // 请求数据长度
} ClientRequest;

// 全局变量
domain_ip_mapping* mapping_table = NULL;
int mapping_count = 0;
cache_entry* cache = NULL;
int cache_count = 0;
int cache_max_size = 100;
char external_dns[16] = "202.106.0.20";  // 默认外部DNS服务器
int debug_level = 0;
CRITICAL_SECTION cache_mutex;             // Windows临界区替代pthread_mutex
CRITICAL_SECTION id_mutex;                // Windows临界区替代pthread_mutex
unsigned short next_id = 1;

// 函数声明
void parse_mapping_file(const char* filename);
void process_client_request(SOCKET sock, struct sockaddr_in client_addr);
DWORD WINAPI handle_client(LPVOID arg);   // Windows线程函数
int parse_dns_message(unsigned char* buffer, int length, char* domain, int* type);
unsigned char* build_dns_response(unsigned char* request, int request_len,
    const char* ip, int rcode);
int resolve_domain(const char* domain, int type, char* ip);
int lookup_mapping(const char* domain, char* ip);
int lookup_cache(const char* domain, int type, char* ip);
void add_to_cache(const char* domain, const char* ip, unsigned int ttl);
int send_dns_query(const char* domain, int type, char* ip);
unsigned short get_next_id();
void log_debug(int level, const char* format, ...);
void init_process_table(); 
unsigned int allocate_process_id(); 
unsigned int get_process_request_count(unsigned int process_id); 
int relay_query(const char* domain, char* ip);
int parse_dns_response(unsigned char* response, int response_len, char* ip);
int build_dns_query(const char* domain, unsigned char* query, size_t query_size);

int main(int argc, char* argv[]) {
	init_process_table(); // 初始化进程表
    WSADATA wsaData;
    SOCKET sockfd;
    int port = 53;
    struct sockaddr_in server_addr, client_addr;
    int client_len = sizeof(client_addr);
    HANDLE thread_id;

    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    // 初始化临界区
    InitializeCriticalSection(&cache_mutex);
    InitializeCriticalSection(&id_mutex);

    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            debug_level = 1;
            if (i + 2 < argc) {
                // 原代码
                //strcpy(external_dns, argv[i + 1]);

                // 修改后的代码
                if (strcpy_s(external_dns, sizeof(external_dns), argv[i + 1]) != 0) {
                    // 处理复制失败的情况
                    log_debug(1, "复制外部DNS地址失败");
                }
                i++;
            }
        }
        else if (strcmp(argv[i], "-dd") == 0) {
            debug_level = 2;
            if (i + 1 < argc) {
                if (strcpy_s(external_dns, sizeof(external_dns), argv[i + 1]) != 0) {
                    // Handle the error if the copy operation fails
                    fprintf(stderr, "Error: Failed to copy external DNS address.\n");
                    exit(EXIT_FAILURE);
                }
                i++;
            }
        }
        else if (strstr(argv[i], ".txt") != NULL) {
            parse_mapping_file(argv[i]);
        }
    }

    // 如果没有指定映射文件，使用默认文件
    if (mapping_count == 0) {
        parse_mapping_file("dnsrelay.txt");
    }

    // 初始化缓存
    cache = (cache_entry*)malloc(cache_max_size * sizeof(cache_entry));
    if (cache == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for cache.\n");
        exit(EXIT_FAILURE); // 退出程序，避免后续操作空指针
    }
    memset(cache, 0, cache_max_size * sizeof(cache_entry));

    // 创建UDP套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // 绑定套接字
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    log_debug(1, "DNS中继服务器启动，监听端口53，外部DNS服务器: %s", external_dns);

    // 处理客户端请求
    while (1) {
        unsigned char buffer[512];
        int recv_len = recvfrom(sockfd, (char*)buffer, sizeof(buffer), 0,
            (struct sockaddr*)&client_addr, &client_len);

        if (recv_len > 0) {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            log_debug(2, "收到客户端请求，IP: %s，长度: %d", client_ip, recv_len);

            // 创建线程处理客户端请求
            void* thread_data = malloc(sizeof(SOCKET) + sizeof(int) + sizeof(client_addr));
            if (thread_data != NULL) {
                memcpy(thread_data, &sockfd, sizeof(SOCKET));
                memcpy((char*)thread_data + sizeof(SOCKET), &recv_len, sizeof(int));
                memcpy((char*)thread_data + sizeof(SOCKET) + sizeof(int), &client_addr, sizeof(client_addr));
            }
            else {
                log_debug(1, "Memory allocation for thread_data failed");
                return; // Handle the error appropriately, e.g., return or log
            }

            thread_id = CreateThread(NULL, 0, handle_client, thread_data, 0, NULL);
            if (thread_id == NULL) {
                log_debug(1, "创建线程失败");
                free(thread_data);
            }
            else {
                CloseHandle(thread_id); // 释放线程句柄，不等待线程结束
            }
        }
    }

    // 清理资源
    DeleteCriticalSection(&cache_mutex);
    DeleteCriticalSection(&id_mutex);
    closesocket(sockfd);
    free(mapping_table);
    free(cache);
    WSACleanup();

    return 0;
}

// 处理客户端请求线程函数
DWORD WINAPI handle_client(LPVOID arg) {
    if (arg == NULL) {
        log_debug(1, "handle_client received a NULL argument");
        return 1; // Exit early if the argument is NULL
    }

    SOCKET sockfd;
    int request_len;
    struct sockaddr_in client_addr;

    // Parse the argument
    memcpy(&sockfd, arg, sizeof(SOCKET));
    memcpy(&request_len, (char*)arg + sizeof(SOCKET), sizeof(int));
    memcpy(&client_addr, (char*)arg + sizeof(SOCKET) + sizeof(int), sizeof(client_addr));

    // Validate request_len before using it
    if (request_len <= 0 || request_len > 512) {
        log_debug(1, "Invalid request length received: %d", request_len);
        free(arg); // Free the allocated memory for the argument
        return 1; // Exit if the request length is invalid
    }

    unsigned char buffer[512];
    memcpy(buffer, (unsigned char*)arg + sizeof(SOCKET) + sizeof(int), request_len);
    free(arg); // Free the allocated memory for the argument

    char domain[256] = { 0 };
    int type = 0;

    if (parse_dns_message(buffer, request_len, domain, &type) < 0) {
        log_debug(1, "Failed to parse DNS request");
        return 1;
    }

    log_debug(1, "Client query: %s (Type: %d)", domain, type);

    char ip[16] = { 0 };
    int rcode = 0; // Response code, 0 indicates no error

    // First, check the cache
    if (lookup_cache(domain, type, ip) == 0) {
        log_debug(2, "Cache hit: %s -> %s", domain, ip);
    }
    else {
        // Check the mapping table
        if (lookup_mapping(domain, ip) == 0) {
            log_debug(2, "Mapping table hit: %s -> %s", domain, ip);

            // If the IP is 0.0.0.0, return domain not found
            if (strcmp(ip, "0.0.0.0") == 0) {
                if (strcpy_s(ip, sizeof(ip), "") != 0) {
                    log_debug(1, "Failed to copy empty string to IP address");
                }
                rcode = 3; // Domain not found
            }
        }
        else {
            // Relay to external DNS server
            log_debug(1, "Relaying query: %s", domain);
            if (send_dns_query(domain, type, ip) == 0) {
                log_debug(2, "Relay successful: %s -> %s", domain, ip);
                add_to_cache(domain, ip, 3600); // Default TTL 1 hour
            }
            else {
                log_debug(1, "Relay failed: %s", domain);
                rcode = 3; // Domain not found
            }
        }
    }

    // Build and send the response
    unsigned char* response = build_dns_response(buffer, request_len, ip, rcode);
    if (response != NULL) {
        int response_len = request_len;
        if (ip && strlen(ip) > 0 && rcode == 0) {
            // Update response length based on the actual response
            dns_header* header = (dns_header*)response;
            response_len = sizeof(dns_header);
            // Skip the question section
            int pos = sizeof(dns_header);
            while (response[pos] != 0) {
                pos += response[pos] + 1;
            }
            pos += 4; // Skip QTYPE and QCLASS
            response_len = pos;
            if (header->ancount > 0) {
                response_len += sizeof(dns_resource_record) - sizeof(((dns_resource_record*)0)->rdata) + 4;
            }
        }
        if (sendto(sockfd, (char*)response, response_len, 0,
            (struct sockaddr*)&client_addr, sizeof(client_addr)) == SOCKET_ERROR) {
            log_debug(1, "Failed to send DNS response: %d", WSAGetLastError());
        }
        free(response);
    }
    else {
        log_debug(1, "Failed to build DNS response");
    }

    return 0;
}
// 解析DNS请求消息
int parse_dns_message(unsigned char* buffer, int length, char* domain, int* type) {
    if (length < sizeof(dns_header) + 1) {
        return -1;
    }

    dns_header* header = (dns_header*)buffer;
    int pos = sizeof(dns_header);
    int label_len;

    // 解析域名
    while ((label_len = buffer[pos++]) != 0) {
        if (pos + label_len > length) {
            return -1;
        }

        // 使用strncat_s替代strncat
        // 原代码
        // if (strncat_s(domain, (char*)&buffer[pos], sizeof(domain) - strlen(domain) - 1, label_len) != 0) {
        // 修改为
        if (strncat_s(domain, sizeof(domain), (char*)&buffer[pos], label_len) != 0) {
            return -1;
        }
        pos += label_len;

        // 使用strcat_s替代strcat
        // 原代码
        // if (strcat_s(domain, sizeof(domain) - strlen(domain) - 1, ".") != 0) {
        // 修改为
        if (strcat_s(domain, sizeof(domain), ".") != 0) {
            return -1;
        }
    }

    // 去除最后的点
    if (strlen(domain) > 0) {
        domain[strlen(domain) - 1] = '\0';
    }

    // 解析查询类型
    if (pos + 3 >= length) {
        return -1;
    }

    *type = ntohs(*(unsigned short*)&buffer[pos]);
    pos += 2;
    unsigned short _class = ntohs(*(unsigned short*)&buffer[pos]);

    log_debug(3, "解析域名: %s, 类型: %d, 类: %d", domain, *type, _class);

    return 0;
}

// 构建DNS响应消息
unsigned char* build_dns_response(unsigned char* request, int request_len, const char* ip, int rcode) {
    // Allocate a larger buffer to prevent overflow
    int response_len = request_len + 17; // Add extra space for the additional data
    unsigned char* response = (unsigned char*)malloc(response_len);
    if (response == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for response.\n");
        return NULL;
    }

    memcpy(response, request, request_len);

    dns_header* header = (dns_header*)response;

    // Modify header flags
    header->flags = ntohs(header->flags);
    header->flags &= ~0x8000;  // Clear query flag
    header->flags |= 0x8000;   // Set response flag
    header->flags &= ~0x000F;  // Clear response code
    header->flags |= rcode;    // Set response code
    header->flags = htons(header->flags);

    if (ip && strlen(ip) > 0 && rcode == 0) {
        dns_resource_record rr;
        rr.type = htons(1);         // A record
        rr._class = htons(1);       // IN class
        rr.ttl = htonl(3600);       // TTL 1 hour
        rr.rdlength = htons(4);     // IP address length (4 bytes)

        int pos = request_len;

        // Add domain name pointer
        if (pos + 2 > response_len) {
            fprintf(stderr, "Error: Response buffer overflow.\n");
            free(response);
            return NULL;
        }
        response[pos++] = 0xc0;
        response[pos++] = 0x0c;

        // Add resource record
        if (pos + sizeof(rr) - sizeof(rr.rdata) > response_len) {
            fprintf(stderr, "Error: Response buffer overflow.\n");
            free(response);
            return NULL;
        }
        memcpy(&response[pos], &rr, sizeof(rr) - sizeof(rr.rdata));
        pos += sizeof(rr) - sizeof(rr.rdata);

        // Convert IP address to binary and add it
        struct in_addr addr;
        inet_pton(AF_INET, ip, &addr);
        if (pos + 4 > response_len) {
            fprintf(stderr, "Error: Response buffer overflow.\n");
            free(response);
            return NULL;
        }
        memcpy(response + pos, &addr, 4);
        pos += 4;

        // Update response length
        request_len = pos;
    }
    else {
        header->ancount = htons(0); // No answers
    }

    return response;
}

// 查找映射表
int lookup_mapping(const char* domain, char* ip) {
    for (int i = 0; i < mapping_count; i++) {
        if (strcmp(mapping_table[i].domain, domain) == 0) {
            // 使用strcpy_s替代strcpy
            // 原代码
            //if (strcpy_s(ip, sizeof(mapping_table[i].ip), mapping_table[i].ip) != 0) {
            //    return -1;
            // }

            // 优化后的修改代码
            if (strcpy_s(ip, sizeof(ip), mapping_table[i].ip) != 0) {
                log_debug(1, "从映射表复制IP地址失败");
                return -1;
            }
            return 0;
        }
    }
    return -1;
}

// 查找缓存
int lookup_cache(const char* domain, int type, char* ip) {
    EnterCriticalSection(&cache_mutex);

    time_t now = time(NULL);
    for (int i = 0; i < cache_count; i++) {
        if (strcmp(cache[i].domain, domain) == 0 && cache[i].ttl > now - cache[i].timestamp) {
            // 使用strcpy_s替代strcpy
            // 原代码
            /*if (strcpy_s(ip, sizeof(cache[i].ip), cache[i].ip) != 0) {
                LeaveCriticalSection(&cache_mutex);
                return -1;
            }*/

            // 优化后的修改代码
            if (strcpy_s(ip, sizeof(ip), cache[i].ip) != 0) {
                log_debug(1, "从缓存复制IP地址失败");
                LeaveCriticalSection(&cache_mutex);
                return -1;
            }
            LeaveCriticalSection(&cache_mutex);
            return 0;
        }
    }

    LeaveCriticalSection(&cache_mutex);
    return -1;
}

// 添加到缓存
void add_to_cache(const char* domain, const char* ip, unsigned int ttl) {
    EnterCriticalSection(&cache_mutex);

    // 查找是否已有该域名
    for (int i = 0; i < cache_count; i++) {
        if (strcmp(cache[i].domain, domain) == 0) {
            // 使用strcpy_s替代strcpy
            // 原代码
            /*if (strcpy_s(cache[i].ip, sizeof(cache[i].ip), ip) != 0) {
                LeaveCriticalSection(&cache_mutex);
                return;
            }*/

            // 优化后的修改代码
            if (strcpy_s(cache[i].ip, sizeof(cache[i].ip), ip) != 0) {
                log_debug(1, "添加到缓存时复制IP地址失败");
                LeaveCriticalSection(&cache_mutex);
                return;
            }
            cache[i].ttl = ttl + time(NULL);
            LeaveCriticalSection(&cache_mutex);
            return;
        }
    }

    // 添加新缓存项
    if (cache_count < cache_max_size) {
        // 使用strcpy_s替代strcpy
       // 原代码
       /* if (strcpy_s(cache[cache_count].domain, sizeof(cache[cache_count].domain), domain) != 0 ||
            strcpy_s(cache[cache_count].ip, sizeof(cache[cache_count].ip), ip) != 0) {
            LeaveCriticalSection(&cache_mutex);
            return;
        }*/

        // 优化后的修改代码
        if (strcpy_s(cache[cache_count].domain, sizeof(cache[cache_count].domain), domain) != 0) {
            log_debug(1, "添加到缓存时复制域名失败");
            LeaveCriticalSection(&cache_mutex);
            return;
        }
        if (strcpy_s(cache[cache_count].ip, sizeof(cache[cache_count].ip), ip) != 0) {
            log_debug(1, "添加到缓存时复制IP地址失败");
            LeaveCriticalSection(&cache_mutex);
            return;
        }
        cache[cache_count].ttl = ttl + time(NULL);
        cache[cache_count].timestamp = time(NULL);
        cache_count++;
    }
    else {
        // 缓存已满，替换最早的项
        int oldest = 0;
        for (int i = 1; i < cache_max_size; i++) {
            if (cache[i].timestamp < cache[oldest].timestamp) {
                oldest = i;
            }
        }
        // 使用strcpy_s替代strcpy
        // 原代码
        /*if (strcpy_s(cache[oldest].domain, sizeof(cache[oldest].domain), domain) != 0 ||
            strcpy_s(cache[oldest].ip, sizeof(cache[oldest].ip), ip) != 0) {
            LeaveCriticalSection(&cache_mutex);
            return;
        }*/

        // 优化后的修改代码
        if (strcpy_s(cache[oldest].domain, sizeof(cache[oldest].domain), domain) != 0) {
            log_debug(1, "替换缓存项时复制域名失败");
            LeaveCriticalSection(&cache_mutex);
            return;
        }
        if (strcpy_s(cache[oldest].ip, sizeof(cache[oldest].ip), ip) != 0) {
            log_debug(1, "替换缓存项时复制IP地址失败");
            LeaveCriticalSection(&cache_mutex);
            return;
        }
        cache[oldest].ttl = ttl + time(NULL);
        cache[oldest].timestamp = time(NULL);
    }

    LeaveCriticalSection(&cache_mutex);
}

// 发送DNS查询到外部服务器// send_dns_query 函数修改
int send_dns_query(const char* domain, int type, char* ip) {
    SOCKET sockfd;
    struct sockaddr_in dns_addr;
    unsigned char request[512], response[512];
    int response_len = sizeof(response);
    struct timeval timeout;
    fd_set read_fds;

    // 创建UDP套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        log_debug(1, "创建套接字失败: %d", WSAGetLastError());
        return -1;
    }

    // 设置DNS服务器地址
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(53);
    inet_pton(AF_INET, external_dns, &dns_addr.sin_addr);

    // 构建DNS查询
    dns_header* header = (dns_header*)request;
    header->id = get_next_id();
    header->flags = htons(0x0100);  // 标准查询，期望递归
    header->qdcount = htons(1);
    header->ancount = htons(0);
    header->nscount = htons(0);
    header->arcount = htons(0);

    int pos = sizeof(dns_header);
    // 添加标志
    int token_allocated = 0;
    char* token = strdup(domain);
    if (token) {
        token_allocated = 1;
    }
    else {
        log_debug(1, "内存分配失败");
        closesocket(sockfd);
        return -1;
    }
    char* label = NULL;
    char* context = NULL;  // strtok_s需要的上下文指针

    // 使用strtok_s替代strtok
    label = strtok_s(token, ".", &context);
    while (label) {
        request[pos++] = strlen(label);
        // 使用strncpy_s替代strncpy
        if (strncpy_s((char*)&request[pos], sizeof(request) - pos, label, strlen(label)) != 0) {
            if (token_allocated) {
                free(token);
            }
            closesocket(sockfd);
            return -1;
        }
        pos += strlen(label);
        label = strtok_s(NULL, ".", &context);  // 继续使用strtok_s
    }
    request[pos++] = 0;  // 域名结束

    // 构建查询类型和类
    *((unsigned short*)&request[pos]) = htons(type);
    pos += 2;
    *((unsigned short*)&request[pos]) = htons(1);  // IN类
    pos += 2;

    // 发送查询
    if (sendto(sockfd, request, pos, 0, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) == SOCKET_ERROR) {
        log_debug(1, "发送查询失败: %d", WSAGetLastError());
        if (token_allocated) {
            free(token);
        }
        closesocket(sockfd);
        return -1;
    }

    // 设置超时
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    // 等待响应
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    int ready = select((int)(sockfd + 1), &read_fds, NULL, NULL, &timeout);
    if (ready <= 0) {
        log_debug(1, "DNS查询超时");
        if (token_allocated) {
            free(token);
        }
        closesocket(sockfd);
        return -1;
    }

    // 接收响应
    response_len = recvfrom(sockfd, (char*)response, response_len, 0, NULL, NULL);
    if (response_len == SOCKET_ERROR) {
        log_debug(1, "接收响应失败: %d", WSAGetLastError());
        if (token_allocated) {
            free(token);
        }
        closesocket(sockfd);
        return -1;
    }

    // 解析响应获取IP
    dns_header* resp_header = (dns_header*)response;
    unsigned short flags = ntohs(resp_header->flags);
    unsigned short rcode = flags & 0x000F;  // 提取低4位的RCODE

    if (rcode != 0) {
        log_debug(1, "外部DNS服务器返回错误: %d", rcode);
        if (token_allocated) {
            free(token);
        }
        closesocket(sockfd);
        return -1;
    }

    int ancount = ntohs(resp_header->ancount);
    if (ancount == 0) {
        log_debug(1, "外部DNS服务器没有找到记录");
        if (token_allocated) {
            free(token);
        }
        closesocket(sockfd);
        return -1;
    }

    pos = sizeof(dns_header);
    // 跳过问题部分
    while (response[pos] != 0) {
        pos += response[pos] + 1;
    }
    pos += 4;  // 跳过QTYPE和QCLASS

    // 解析回答部分
    for (int i = 0; i < ancount; i++) {
        // 跳过域名部分（可能是指针）
        if (response[pos] == 0xc0) {
            pos += 2;
        }
        else {
            while (response[pos] != 0) {
                pos += response[pos] + 1;
            }
            pos++;
        }

        // 跳过TYPE和CLASS
        pos += 4;

        // 读取TTL
        unsigned int ttl = ntohl(*(unsigned int*)&response[pos]);
        pos += 4;

        // 读取RDLENGTH
        unsigned short rdlength = ntohs(*(unsigned short*)&response[pos]);
        pos += 2;

        // 如果是A记录，提取IP
        if (ntohs(*(unsigned short*)&(response[pos - 4])) == 1 && rdlength == 4) {
            struct in_addr addr;
            memcpy(&addr, &response[pos], 4);
            inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN);
            if (token_allocated) {
                free(token);
            }
            closesocket(sockfd);
            return 0;
        }
        else {
            pos += rdlength;
        }
    }

    log_debug(1, "没有找到A记录");
    if (token_allocated) {
        free(token);
    }
    closesocket(sockfd);
    return -1;
}

// 获取下一个查询ID
unsigned short get_next_id() {
    EnterCriticalSection(&id_mutex);
    unsigned short id = next_id++;
    LeaveCriticalSection(&id_mutex);
    return id;
}

// 解析映射文件
void parse_mapping_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        log_debug(1, "无法打开映射文件: %s", filename);
        return;
    }

    // 先计算行数，确定分配空间
    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), file)) {
        if (strlen(line) > 0 && line[0] != '#' && line[0] != '\n') {
            count++;
        }
    }

    rewind(file);

    // 分配空间
    mapping_table = (domain_ip_mapping*)malloc(count * sizeof(domain_ip_mapping));
    if (!mapping_table) {
        fclose(file);
        perror("内存分配失败");
        exit(EXIT_FAILURE);
    }

    // 读取映射
    mapping_count = 0;
    while (fgets(line, sizeof(line), file) && mapping_count < count) {
        char* ptr = strchr(line, '\n');
        if (ptr) *ptr = '\0';

        ptr = strchr(line, ' ');
        if (ptr) {
            *ptr = '\0';
            // 使用strcpy_s替代strcpy
            if (strcpy_s(mapping_table[mapping_count].ip, sizeof(mapping_table[mapping_count].ip), line) != 0 ||
                strcpy_s(mapping_table[mapping_count].domain, sizeof(mapping_table[mapping_count].domain), ptr + 1) != 0) {
                continue; // 复制失败，跳过此行
            }
            mapping_count++;
        }
    }

    fclose(file);
    log_debug(1, "解析映射文件 %s，共 %d 条记录", filename, mapping_count);
}

// 调试日志
void log_debug(int level, const char* format, ...) {
    if (level > debug_level) return;

    va_list args;
    va_start(args, format);

    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    printf("[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);

    vprintf(format, args);
    printf("\n");

    va_end(args);
}

void process_client_request(SOCKET sock, struct sockaddr_in client_addr) {
    unsigned char buffer[512];
    int client_len = sizeof(client_addr);

    // 接收客户端请求
    int recv_len = recvfrom(sock, (char*)buffer, sizeof(buffer), 0,
        (struct sockaddr*)&client_addr, &client_len);
    if (recv_len <= 0) {
        log_debug(1, "接收客户端请求失败: %d", WSAGetLastError());
        return;
    }

    char domain[256] = { 0 };
    int type = 0;

    // 解析DNS请求
    if (parse_dns_message(buffer, recv_len, domain, &type) < 0) {
        log_debug(1, "解析DNS请求失败");
        return;
    }

    log_debug(1, "客户端查询: %s (类型: %d)", domain, type);

    char ip[16] = { 0 };
    int rcode = 0; // 响应代码，0表示无错误

    // 首先检查缓存
    if (lookup_cache(domain, type, ip) == 0) {
        log_debug(2, "缓存命中: %s -> %s", domain, ip);
    }
    else {
        // 检查映射表
        if (lookup_mapping(domain, ip) == 0) {
            log_debug(2, "映射表命中: %s -> %s", domain, ip);

            // 如果IP是0.0.0.0，返回域名未找到
            if (strcmp(ip, "0.0.0.0") == 0) {
                strcpy_s(ip, sizeof(ip), "");
                rcode = 3; // 域名未找到
            }
        }
        else {
            // 转发到外部DNS服务器
            log_debug(1, "转发查询: %s", domain);
            if (send_dns_query(domain, type, ip) == 0) {
                log_debug(2, "转发成功: %s -> %s", domain, ip);
                add_to_cache(domain, ip, 3600); // 默认TTL为1小时
            }
            else {
                log_debug(1, "转发失败: %s", domain);
                rcode = 3; // 域名未找到
            }
        }
    }

    // 构建并发送响应
    unsigned char* response = build_dns_response(buffer, recv_len, ip, rcode);
    if (response != NULL) {
        sendto(sock, (char*)response, recv_len, 0,
            (struct sockaddr*)&client_addr, client_len);
        free(response);
    }
    else {
        log_debug(1, "构建DNS响应失败");
    }
}

int resolve_domain(const char* domain, int type, char* ip) {
    // Check if the domain exists in the cache
    if (lookup_cache(domain, type, ip) == 0) {
        log_debug(2, "Cache hit: %s -> %s", domain, ip);
        return 0; // Found in cache
    }

    // Check if the domain exists in the mapping table
    if (lookup_mapping(domain, ip) == 0) {
        log_debug(2, "Mapping table hit: %s -> %s", domain, ip);

        // If the IP is 0.0.0.0, return domain not found
        if (strcmp(ip, "0.0.0.0") == 0) {
            ip[0] = '\0'; // Clear the IP
            return 3; // Domain not found
        }
        return 0; // Found in mapping table
    }

    // Relay the query to the external DNS server
    log_debug(1, "Relaying query: %s", domain);
    if (send_dns_query(domain, type, ip) == 0) {
        log_debug(2, "Relay successful: %s -> %s", domain, ip);
        add_to_cache(domain, ip, 3600); // Add to cache with a default TTL of 1 hour
        return 0; // Successfully resolved
    }

    log_debug(1, "Relay failed: %s", domain);
    return 3; // Domain not found
}

void init_process_table() {
    InitializeCriticalSection(&process_mutex);
    for (int i = 0; i < MAX_PROCESSES; i++) {
        processes[i].process_id = 0;  // 0表示未使用
        processes[i].request_count = 0;
    }
}

unsigned int allocate_process_id() {
    EnterCriticalSection(&process_mutex);
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (processes[i].process_id == 0) {
            processes[i].process_id = i + 1;  // 进程ID从1开始
            processes[i].request_count = 0;
            processes[i].last_active = time(NULL);
            LeaveCriticalSection(&process_mutex);
            return processes[i].process_id;
        }
    }
    LeaveCriticalSection(&process_mutex);
    return 0;  // 没有可用槽位
}

unsigned int get_process_request_count(unsigned int process_id) {
    EnterCriticalSection(&process_mutex);
    unsigned int count = 0;
    if (process_id > 0 && process_id <= MAX_PROCESSES) {
        count = ++processes[process_id - 1].request_count;
        processes[process_id - 1].last_active = time(NULL);
    }
    LeaveCriticalSection(&process_mutex);
    return count;
}

int relay_query(const char* domain, char* ip) {
    // Create a socket for communication with the external DNS server
    SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == INVALID_SOCKET) {
        log_debug(1, "Failed to create socket for relay query: %d", WSAGetLastError());
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53); // DNS uses port 53
    inet_pton(AF_INET, external_dns, &server_addr.sin_addr);

    // Build a DNS query packet
    unsigned char query[512];
    int query_len = build_dns_query(domain, query, sizeof(query));
    if (query_len < 0) {
        log_debug(1, "Failed to build DNS query for domain: %s", domain);
        closesocket(sockfd);
        return -1;
    }

    // Send the query to the external DNS server
    if (sendto(sockfd, (char*)query, query_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        log_debug(1, "Failed to send DNS query: %d", WSAGetLastError());
        closesocket(sockfd);
        return -1;
    }

    // Receive the response
    unsigned char response[512];
    int response_len = recvfrom(sockfd, (char*)response, sizeof(response), 0, NULL, NULL);
    if (response_len <= 0) {
        log_debug(1, "Failed to receive DNS response: %d", WSAGetLastError());
        closesocket(sockfd);
        return -1;
    }

    // Parse the response to extract the IP address
    if (parse_dns_response(response, response_len, ip) < 0) {
        log_debug(1, "Failed to parse DNS response for domain: %s", domain);
        closesocket(sockfd);
        return -1;
    }

    closesocket(sockfd);
    return 0; // Success
}

// Function to build a DNS query
int build_dns_query(const char* domain, unsigned char* query, size_t query_size) {
    if (domain == NULL || query == NULL || query_size < 12) {
        return -1; // Error: Invalid input or insufficient buffer size
    }

    memset(query, 0, query_size);

    // Set up the DNS header
    dns_header* header = (dns_header*)query;
    header->id = htons(get_next_id()); // Generate a unique ID
    header->flags = htons(0x0100);     // Standard query
    header->qdcount = htons(1);        // One question

    // Encode the domain name into the query
    size_t pos = sizeof(dns_header);
    const char* label_start = domain;
    while (*label_start) {
        const char* label_end = strchr(label_start, '.');
        if (!label_end) {
            label_end = label_start + strlen(label_start);
        }

        size_t label_length = label_end - label_start;
        if (pos + label_length + 1 >= query_size) {
            return -1; // Error: Query buffer too small
        }

        query[pos++] = (unsigned char)label_length;
        memcpy(&query[pos], label_start, label_length);
        pos += label_length;

        label_start = (*label_end) ? label_end + 1 : label_end;
    }

    query[pos++] = 0; // Null terminator for the domain name

    // Set the query type and class
    if (pos + 4 > query_size) {
        return -1; // Error: Query buffer too small
    }
    *(unsigned short*)&query[pos] = htons(1); // Type A (host address)
    pos += 2;
    *(unsigned short*)&query[pos] = htons(1); // Class IN (Internet)
    pos += 2;

    return (int)pos; // Return the length of the query
}

// 定义 parse_dns_response 函数
int parse_dns_response(unsigned char* response, int response_len, char* ip) {
    if (response_len < sizeof(dns_header)) {
        return -1; // 响应长度不足
    }

    dns_header* header = (dns_header*)response;
    int pos = sizeof(dns_header);

    // 跳过问题部分
    while (pos < response_len && response[pos] != 0) {
        pos += response[pos] + 1;
    }
    pos += 5; // 跳过终止字节和 QTYPE、QCLASS

    if (pos >= response_len || header->ancount == 0) {
        return -1; // 没有回答部分
    }

    // 解析回答部分
    for (int i = 0; i < ntohs(header->ancount); i++) {
        // 跳过名称部分
        while (pos < response_len && response[pos] != 0) {
            if ((response[pos] & 0xC0) == 0xC0) { // 压缩指针
                pos += 2;
                break;
            }
            pos += response[pos] + 1;
        }
        pos += 1; // 跳过终止字节

        if (pos + 10 > response_len) {
            return -1; // 数据不足
        }

        unsigned short type = ntohs(*(unsigned short*)&response[pos]);
        pos += 8; // 跳过 TYPE、CLASS 和 TTL
        unsigned short rdlength = ntohs(*(unsigned short*)&response[pos]);
        pos += 2;

        if (type == 1 && rdlength == 4) { // A记录
            if (pos + 4 > response_len) {
                return -1; // 数据不足
            }
            snprintf(ip, 16, "%u.%u.%u.%u", response[pos], response[pos + 1], response[pos + 2], response[pos + 3]);
            return 0; // 成功解析IP地址
        }
        pos += rdlength; // 跳过资源数据
    }

    return -1; // 未找到A记录
}