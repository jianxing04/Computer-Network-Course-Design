#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define DNS_PORT 53
#define BUFFER_SIZE 512
#define MAX_CLIENTS 100
#define MAX_CACHE_ENTRIES 1000
#define CACHE_TTL 300  // 缓存有效期（秒）
#define DNSRELAY_FILE "dnsrelay.txt"
#define MAX_DOMAIN_LENGTH 256
#define MAX_IP_LENGTH 16
#define EXTERNAL_DNS_SERVER "114.114.114.114"  // 外部 DNS 服务器地址

// DNS头部结构
typedef struct {
    unsigned short id;        // 标识符
    unsigned char rd : 1;     // 递归标志
    unsigned char tc : 1;     // 截断标志
    unsigned char aa : 1;     // 权威答案标志
    unsigned char opcode : 4; // 操作码
    unsigned char qr : 1;     // 查询/响应标志
    unsigned char rcode : 4;  // 响应码
    unsigned char z : 3;      // 保留位
    unsigned char ra : 1;     // 递归可用标志
    unsigned short qdcount;   // 问题数量
    unsigned short ancount;   // 回答数量
    unsigned short nscount;   // 权威服务器数量
    unsigned short arcount;   // 附加信息数量
} DNS_HEADER;

//+-------------------- - +
//| 头部 |
//+-------------------- - +
//| 问题部分 |
//+-------------------- - +
//| 回答部分 | < -多个答案在此处扩展
//+ -------------------- - +
//| 权威服务器部分 | < -可能包含多个RR
//+ -------------------- - +
//| 附加记录部分 | < -可能包含多个RR
//+ -------------------- - +

// 缓存条目结构
typedef struct CacheEntry {
    char domain[MAX_DOMAIN_LENGTH];// 域名
    char ip[MAX_IP_LENGTH];// IP地址
    time_t timestamp;// 缓存时间戳
    struct CacheEntry* prev;// 指向前一个条目
    struct CacheEntry* next;// 指向下一个条目
} CACHE_ENTRY;

// LRU缓存结构
typedef struct {
    CACHE_ENTRY* head;// 指向最新的条目
    CACHE_ENTRY* tail;// 指向最旧的条目
    int count;// 当前缓存条目数量
    CRITICAL_SECTION lock;// 互斥锁保护缓存
} LRU_CACHE;

// 传递给线程的参数结构
typedef struct {
    SOCKET sockfd;// 套接字描述符
    struct sockaddr_in client_addr;// 客户端地址
    int client_addr_len;// 客户端地址长度
    unsigned char* buffer;// 接收缓冲区
    int recv_len;// 接收数据长度
} CLIENT_PARAM;

// 全局变量
LRU_CACHE cache;// LRU缓存
LONG count_recv = 0;  // 使用 LONG 类型配合原子操作

// 函数声明
void parse_dns_query(unsigned char* buffer, int len, char* domain, int domain_size);// 解析DNS查询中的域名
void send_dns_response(SOCKET sockfd, struct sockaddr_in* client_addr, int client_addr_len,
    unsigned char* request, int request_len, char** ips, int ip_count);
DWORD WINAPI handle_client(LPVOID arg);// 处理客户端请求的线程函数
void search_in_file(const char* domain, char* ip);// 在文件中查找域名对应的IP地址
void init_cache();// 初始化缓存
void add_to_cache(const char* domain, const char* ip);// 添加到缓存
void find_in_cache(const char* domain, char** ips, int* ip_count);// 在缓存中查找
void remove_from_cache(CACHE_ENTRY* entry);// 从缓存中移除条目
void move_to_front(CACHE_ENTRY* entry);// 将条目移动到链表头部
int forward_to_external_dns(unsigned char* request, int request_len, unsigned char* response);// 转发 DNS 请求到外部服务器并接收响应
void parse_ip_from_response(unsigned char* response, int response_len, const char* domain);// 从外部 DNS 响应中解析 IP 地址
void free_ips(char** ips);// 辅助函数：释放IP地址数组

int main() {
    WSADATA wsaData;
    SOCKET sockfd = INVALID_SOCKET;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    HANDLE threads[MAX_CLIENTS];
    int thread_count = 0;

    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    // 创建UDP套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // 设置套接字选项
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        fprintf(stderr, "setsockopt failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    // 准备服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;// IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;// 监听所有接口
    server_addr.sin_port = htons(DNS_PORT);// DNS端口

    // 绑定套接字
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    printf("DNS中继服务器启动，监听地址: 127.0.0.1:%d\n", DNS_PORT);

    init_cache();  // 初始化缓存

    // 主循环
    while (1) {
        // 分配缓冲区
        unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE);
        if (!buffer) {
            fprintf(stderr, "内存分配失败\n");
            continue;
        }

        // 接收客户端请求
        int recv_len = recvfrom(sockfd, (char*)buffer, BUFFER_SIZE, 0,
            (struct sockaddr*)&client_addr, &client_addr_len);
        if (recv_len == SOCKET_ERROR) {
            fprintf(stderr, "接收数据失败: %d\n", WSAGetLastError());
            free(buffer);
            continue;
        }

        // 分配参数结构
        CLIENT_PARAM* param = (CLIENT_PARAM*)malloc(sizeof(CLIENT_PARAM));
        if (!param) {
            fprintf(stderr, "参数结构内存分配失败\n");
            free(buffer);
            continue;
        }
        param->sockfd = sockfd;
        param->client_addr = client_addr;
        param->client_addr_len = client_addr_len;
        param->buffer = buffer;
        param->recv_len = recv_len;

        // 创建线程处理客户端请求
        threads[thread_count] = CreateThread(NULL, 0, handle_client, (LPVOID)param, 0, NULL);
        if (threads[thread_count] == NULL) {
            fprintf(stderr, "创建线程失败: %d\n", GetLastError());
            free(buffer);
            free(param);
            continue;
        }
        thread_count++;

        // 检查线程数量是否超过最大限制
        if (thread_count >= MAX_CLIENTS) {
            // 等待任意一个线程结束
            DWORD result = WaitForMultipleObjects(
                thread_count,        // 等待所有当前线程
                threads,             // 线程句柄数组
                FALSE,               // 等待任意一个
                INFINITE             // 无限等待
            );

            // 计算结束的线程索引
            DWORD index = result - WAIT_OBJECT_0;

            // 关闭已结束线程的句柄
            CloseHandle(threads[index]);

            // 将后续线程前移，覆盖已结束的线程
            for (int i = index; i < thread_count - 1; i++) {
                threads[i] = threads[i + 1];
            }

            thread_count--;
        }
    }

    // 清理资源（实际上不会执行到这里）
    EnterCriticalSection(&cache.lock);
    CACHE_ENTRY* current = cache.head;
    while (current != NULL) {
        CACHE_ENTRY* next = current->next;
        free(current);
        current = next;
    }
    LeaveCriticalSection(&cache.lock);
    DeleteCriticalSection(&cache.lock);
    closesocket(sockfd);
    WSACleanup();
    return 0;
}

// 处理客户端请求的线程函数
DWORD WINAPI handle_client(LPVOID arg) {
    CLIENT_PARAM* param = (CLIENT_PARAM*)arg;
    SOCKET sockfd = param->sockfd;
    struct sockaddr_in client_addr = param->client_addr;
    int client_addr_len = param->client_addr_len;
    unsigned char* buffer = param->buffer;
    int recv_len = param->recv_len;

    // 保护全局变量 count_recv
    int current_count = InterlockedIncrement(&count_recv);

    // 打印请求信息
    printf("接收到第 %d 个请求：", current_count);
    char client_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN) == NULL) {
        printf("来自 [IP转换失败]:%d，数据长度: %d 字节，错误: %d\n",
            ntohs(client_addr.sin_port), recv_len, WSAGetLastError());
    }
    else {
        printf("来自 %s:%d，数据长度: %d 字节，",
            client_ip, ntohs(client_addr.sin_port), recv_len);
    }

    // 解析并打印域名
    char domain[MAX_DOMAIN_LENGTH] = { 0 };
    parse_dns_query(buffer, recv_len, domain, MAX_DOMAIN_LENGTH);
    printf("请求的域名: %s\n", domain);

    // 分配 IP 地址数组
    char** ips = (char**)malloc(MAX_CACHE_ENTRIES * sizeof(char*));
    if (!ips) {
        fprintf(stderr, "IP地址数组内存分配失败\n");
        free(buffer);
        free(param);
        return 1;
    }
    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        ips[i] = (char*)malloc(MAX_IP_LENGTH);
        if (!ips[i]) {
            fprintf(stderr, "IP地址内存分配失败\n");
            free_ips(ips);
            free(buffer);
            free(param);
            return 1;
        }
        memset(ips[i], 0, MAX_IP_LENGTH);
    }
    int ip_count = 0;

    // 检查是否为反向 DNS 查询
    if (strstr(domain, ".in-addr.arpa") != NULL) {
        // 处理反向 DNS 查询，这里简单返回默认值
        strcpy_s(ips[0], MAX_IP_LENGTH, "127.0.0.1");
        ip_count = 1;
        printf("反向查询，返回默认值 127.0.0.1\n");
    }
    else {
        // 先从缓存中查找
        find_in_cache(domain, ips, &ip_count);
        if (ip_count > 0) {
            printf("从缓存中找到域名 %s 对应的 %d 个 IP\n", domain, ip_count);
            for (int i = 0; i < ip_count; i++) {
                printf("IP %d: %s\n", i + 1, ips[i]);
            }
        }
        else {
            // 缓存中未找到，在 dnsrelay.txt 文件中查找 IP
			char ip[MAX_IP_LENGTH] = { 0 };// 初始化 IP 字符串
            search_in_file(domain, ip);
            if (strlen(ip) > 0) {
                printf("在文件中找到域名 %s 对应的 IP: %s\n", domain, ip);
                strcpy_s(ips[0], MAX_IP_LENGTH, ip);
                ip_count = 1;
                // 将查询结果添加到缓存
                add_to_cache(domain, ip);
            }
            else {
                // 在文件中未找到，直接转发客户端请求到外部 DNS 服务器
                unsigned char response[BUFFER_SIZE] = { 0 };
                int response_len = forward_to_external_dns(buffer, recv_len, response);
                if (response_len > 0) {
                    // 解析外部 DNS 响应，提取 IP 并添加到缓存
                    parse_ip_from_response(response, response_len, domain);

                    // 直接将外部 DNS 响应发送给客户端
                    int sent_bytes = sendto(sockfd, (char*)response, response_len, 0,
                        (struct sockaddr*)&client_addr, client_addr_len);
                    if (sent_bytes == SOCKET_ERROR) {
                        fprintf(stderr, "发送响应失败: %d\n", WSAGetLastError());
                    }
                    else {
                        printf("已原封不动转发外部 DNS 响应，长度: %d 字节\n", sent_bytes);
                    }

                    // 释放资源并返回
                    free_ips(ips);
                    free(buffer);
                    free(param);
                    return 0;
                }
                else {
                    strcpy_s(ips[0], MAX_IP_LENGTH, "0.0.0.0"); //找不到
                    ip_count = 1;
                    printf("外部查询失败，返回 0.0.0.0\n");
                }
            }
        }
    }

    // 发送响应
    send_dns_response(sockfd, &client_addr, client_addr_len, buffer, recv_len, ips, ip_count);

    // 释放资源
    free_ips(ips);
    free(buffer);
    free(param);

    return 0;
}

// 解析DNS查询中的域名
void parse_dns_query(unsigned char* buffer, int len, char* domain, int domain_size) {
    // 检查输入参数的有效性
    if (buffer == NULL || domain == NULL || len < (int)sizeof(DNS_HEADER)) {
        if (domain != NULL) {
            domain[0] = '\0';
        }
        return;
    }

    DNS_HEADER* header = (DNS_HEADER*)buffer;
    unsigned char* qname = buffer + sizeof(DNS_HEADER);// 跳过头部
    int pos = 0;

    // 解析域名部分
    while (pos < domain_size - 1 && qname < buffer + len) {
        int label_len = *qname++;// 读取标签长度
        if (label_len == 0) break;

        // 检查是否为压缩指针
        if ((label_len & 0xC0) == 0xC0) {
            // 处理压缩指针
            unsigned short pointer = ((label_len & 0x3F) << 8) | *qname++;
            if (pointer >= len) {
                domain[0] = '\0';
                return;
            }
            unsigned char* ptr = buffer + pointer;
            while (pos < domain_size - 1 && ptr < buffer + len) {
                int sub_label_len = *ptr++;
                if (sub_label_len == 0) break;
                for (int i = 0; i < sub_label_len && pos < domain_size - 1; i++) {
                    domain[pos++] = *ptr++;
                }
                if (*ptr != 0 && pos < domain_size - 1) {
                    domain[pos++] = '.';
                }
            }
            break;
        }

        // 检查标签长度是否有效
        if (qname + label_len > buffer + len) {
            domain[0] = '\0';
            return;
        }

        for (int i = 0; i < label_len && pos < domain_size - 1; i++) {
            domain[pos++] = *qname++;
        }

        if (*qname != 0 && pos < domain_size - 1) {
            domain[pos++] = '.';
        }
    }

    domain[pos] = '\0';
}

// 发送DNS响应
void send_dns_response(SOCKET sockfd, struct sockaddr_in* client_addr, int client_addr_len,
    unsigned char* request, int request_len, char** ips, int ip_count) {
    // 分配响应缓冲区
    unsigned char* response = (unsigned char*)malloc(BUFFER_SIZE);
    if (!response) {
        fprintf(stderr, "响应缓冲区分配失败\n");
        return;
    }
    memset(response, 0, BUFFER_SIZE);

    // 复制请求头部到响应
    memcpy(response, request, sizeof(DNS_HEADER));

    // 修改头部标志为响应
    DNS_HEADER* header = (DNS_HEADER*)response;
    header->qr = 1;    // 查询/响应标志设为响应
    header->ra = 1;    // 递归可用

    int response_pos = sizeof(DNS_HEADER);// 响应位置从头部开始
    if (strcmp(ips[0], "0.0.0.0") == 0) {
        header->rcode = 3;  // 3表示域名不存在(NXDOMAIN)
        header->ancount = htons(0);  // 没有回答记录
        printf("拦截域名查询，返回域名不存在错误\n");
    }
    else {
        header->rcode = 0;  // 0表示没有错误
        header->ancount = htons(ip_count);  // 回答记录数量

        int question_len = 0; // 问题部分长度
        // 复制问题部分到响应
        unsigned char* qname = request + sizeof(DNS_HEADER);
        while (question_len < request_len - sizeof(DNS_HEADER) && qname[question_len] != 0) {
            question_len++;
        }
        question_len++;  // 加上结尾的'0'字符
        question_len += 4;  // 加上 QTYPE 和 QCLASS (4字节)
        memcpy(response + sizeof(DNS_HEADER), qname, question_len);

        // 构建回答部分
        response_pos = sizeof(DNS_HEADER) + question_len;

        for (int i = 0; i < ip_count; i++) {

            //+-------------------------------- - +
            //| 域名（Domain） |
            //+-------------------------------- - +
            //| 类型（Type） |
            //+-------------------------------- - +
            //| 类（Class） |
            //+-------------------------------- - +
            //| 生存时间（TTL） | < -4字节，单位秒
            //+ -------------------------------- - +
            //| 数据长度（RDLength） | < -2字节
            //+ -------------------------------- - +
            //| 数据（RData） | < -可变长度
            //+ -------------------------------- - +

            // 域名指针 (指向问题部分的域名),NAME部分使用压缩指针
            response[response_pos++] = 0xC0;  // 压缩指针
            response[response_pos++] = 0x0C;  // 指向问题部分的域名,偏移量为12字节

            // 类型和类 (A记录, IN类)
            response[response_pos++] = 0x00;
            response[response_pos++] = 0x01;  // TYPE A，IPv4地址，2字节
            response[response_pos++] = 0x00;
            response[response_pos++] = 0x01;  // CLASS IN，互联网，2字节

            // TTL (300秒)
            unsigned int ttl = htonl(CACHE_TTL); // 使用缓存TTL
            memcpy(&response[response_pos], &ttl, 4);
			response_pos += 4;// TTL，4字节

            // RDLENGTH (IPv4地址长度)
            response[response_pos++] = 0x00;
            response[response_pos++] = 0x04; // IPv4地址长度，4字节

            // IP地址
            unsigned char ip_parts[4];
            if (sscanf_s(ips[i], "%hhu.%hhu.%hhu.%hhu", &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]) != 4) {
                fprintf(stderr, "Invalid IP address format: %s\n", ips[i]);
                free(response);
                return;
            }
            memcpy(&response[response_pos], ip_parts, 4);
            /*不需要将 ip_parts 转换为网络字节序，原因如下：
                1.	IPv4 地址已经被拆分为 4 个独立的字节（如 192.168.1.1）
                2.	每个字节是单独存储的，不存在字节序的问题
                3.	DNS 协议中，A 记录的 IP 地址就是按照这个顺序直接存储的*/
            response_pos += 4;
        }
    }

    // 发送响应
    int sent_bytes = sendto(sockfd, (char*)response, response_pos, 0,
        (struct sockaddr*)client_addr, client_addr_len);
    if (sent_bytes == SOCKET_ERROR) {
        fprintf(stderr, "发送响应失败: %d\n", WSAGetLastError());
    }
    else {
        printf("已发送响应，长度: %d 字节\n", sent_bytes);
    }

    // 释放响应缓冲区
    free(response);
}

// 在文件中查找域名对应的IP地址
void search_in_file(const char* domain, char* ip) {
    FILE* file = NULL;
    ip[0] = '\0'; // 初始化为空字符串

    if (fopen_s(&file, DNSRELAY_FILE, "r") != 0) {
        return; // 文件不存在或无法打开，直接返回
    }

    char line[MAX_DOMAIN_LENGTH + MAX_IP_LENGTH + 5]; // 预留空间给域名、IP和空格
    while (fgets(line, sizeof(line), file) != NULL) {
        char file_ip[MAX_IP_LENGTH];
        char file_domain[MAX_DOMAIN_LENGTH];
        memset(file_ip, 0, sizeof(file_ip)); // 确保缓冲区初始化
        memset(file_domain, 0, sizeof(file_domain)); // 确保缓冲区初始化

        if (sscanf_s(line, "%15s %255s", file_ip, (unsigned int)sizeof(file_ip),
            file_domain, (unsigned int)sizeof(file_domain)) == 2) {
            file_ip[MAX_IP_LENGTH - 1] = '\0'; // 确保字符串以零终止符结尾
            file_domain[MAX_DOMAIN_LENGTH - 1] = '\0'; // 确保字符串以零终止符结尾
            if (strcmp(file_domain, domain) == 0) {
                strcpy_s(ip, MAX_IP_LENGTH, file_ip);
                break;
            }
        }
    }
    fclose(file);
}

// 初始化缓存
void init_cache() {
    InitializeCriticalSection(&cache.lock);
    cache.head = NULL;
    cache.tail = NULL;
    cache.count = 0;
}

// 添加到缓存
void add_to_cache(const char* domain, const char* ip) {
    EnterCriticalSection(&cache.lock);

    // 检查缓存是否已满
    if (cache.count >= MAX_CACHE_ENTRIES) {
        // 移除最旧的条目
        CACHE_ENTRY* oldest = cache.tail;
        if (oldest != NULL) {
            cache.tail = oldest->prev;
            if (cache.tail != NULL) {
                cache.tail->next = NULL;
            }
            else {
                cache.head = NULL;
            }
            free(oldest);
            cache.count--;
        }
    }

    // 创建新的缓存条目
    CACHE_ENTRY* new_entry = (CACHE_ENTRY*)malloc(sizeof(CACHE_ENTRY));
    if (new_entry != NULL) {
        strcpy_s(new_entry->domain, MAX_DOMAIN_LENGTH, domain);
        strcpy_s(new_entry->ip, MAX_IP_LENGTH, ip);
        new_entry->timestamp = time(NULL);
        new_entry->prev = NULL;
        new_entry->next = cache.head;

        if (cache.head != NULL) {
            cache.head->prev = new_entry;
        }
        cache.head = new_entry;

        if (cache.tail == NULL) {
            cache.tail = new_entry;
        }

        cache.count++;
    }

    LeaveCriticalSection(&cache.lock);
}

// 在缓存中查找
void find_in_cache(const char* domain, char** ips, int* ip_count) {
    EnterCriticalSection(&cache.lock);

    *ip_count = 0;
    time_t now = time(NULL);
    CACHE_ENTRY* current = cache.head;
    CACHE_ENTRY* found_entry = NULL;

    while (current != NULL) {
        if (now - current->timestamp  > CACHE_TTL) {// 如果缓存过期，移除该条目
            CACHE_ENTRY* to_remove = current;
            current = current->next;
            remove_from_cache(to_remove);
			continue; // 继续检查下一个条目
        }
        if (strcmp(current->domain, domain) == 0) {
            strcpy_s(ips[(*ip_count)++], MAX_IP_LENGTH, current->ip);
            found_entry = current;
            current = current->next;
            move_to_front(found_entry);// 如果找到，将其移到链表头部
        }
    }

    LeaveCriticalSection(&cache.lock);
}

// 从缓存中移除条目
void remove_from_cache(CACHE_ENTRY* entry) {
    if (entry == NULL) return;

    EnterCriticalSection(&cache.lock);

	if (entry->prev != NULL) {// 如果不是头部，更新前一个条目的next指针
        entry->prev->next = entry->next;
    }
	else {// 如果是头部，更新头部指针
        cache.head = entry->next;
    }

	if (entry->next != NULL) {// 如果不是尾部，更新下一个条目的prev指针
        entry->next->prev = entry->prev;
    }
	else {// 如果是尾部，更新尾部指针
        cache.tail = entry->prev;
    }

    free(entry);
    cache.count--;

    LeaveCriticalSection(&cache.lock);
}

// 将条目移动到链表头部
void move_to_front(CACHE_ENTRY* entry) {
	if (entry == NULL || entry == cache.head) {// 如果条目为空或已经是头部，直接返回
        return;
    }

    EnterCriticalSection(&cache.lock);

    // 先从当前位置移除
	if (entry->prev != NULL) {// 如果不是头部，更新前一个条目的next指针
        entry->prev->next = entry->next;
    }
	if (entry->next != NULL) {// 如果不是尾部，更新下一个条目的prev指针
        entry->next->prev = entry->prev;
    }
	if (entry == cache.tail) {// 如果是尾部，更新尾部指针
        cache.tail = entry->prev;
    }

    // 插入到头部
    entry->next = cache.head;
    entry->prev = NULL;
    if (cache.head != NULL) {
        cache.head->prev = entry;
    }
    cache.head = entry;

    LeaveCriticalSection(&cache.lock);
}

// 转发 DNS 请求到外部服务器并接收响应
int forward_to_external_dns(unsigned char* request, int request_len, unsigned char* response) {
    WSADATA wsaData;
    SOCKET sockfd = INVALID_SOCKET;
    struct sockaddr_in external_dns_addr;
    int result;

    // 初始化Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return -1;
    }

    // 创建UDP套接字
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == INVALID_SOCKET) {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    // 设置超时
    int timeout = 5000; // 5秒
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
        fprintf(stderr, "setsockopt(SO_RCVTIMEO) failed: %d\n", WSAGetLastError());
    }

    // 准备外部 DNS 服务器地址
    memset(&external_dns_addr, 0, sizeof(external_dns_addr));
    external_dns_addr.sin_family = AF_INET;
    external_dns_addr.sin_port = htons(DNS_PORT);
    result = inet_pton(AF_INET, EXTERNAL_DNS_SERVER, &external_dns_addr.sin_addr);
    if (result <= 0) {
        fprintf(stderr, "inet_pton failed: %d\n", result);
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    // 发送请求
    result = sendto(sockfd, (char*)request, request_len, 0,
        (struct sockaddr*)&external_dns_addr, sizeof(external_dns_addr));
    if (result == SOCKET_ERROR) {
        fprintf(stderr, "sendto failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return -1;
    }

    // 接收响应
    int response_len = recvfrom(sockfd, (char*)response, BUFFER_SIZE, 0, NULL, NULL);
    if (response_len == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error == WSAETIMEDOUT) {
            fprintf(stderr, "外部DNS查询超时\n");
        }
        else {
            fprintf(stderr, "recvfrom failed: %d\n", error);
        }
        response_len = -1;
    }

    // 清理资源
    closesocket(sockfd);
    WSACleanup();

    return response_len;
}

// 从外部 DNS 响应中解析 IP 地址
void parse_ip_from_response(unsigned char* response, int response_len, const char* domain) {
    if (response == NULL || response_len < (int)sizeof(DNS_HEADER)) {
        return;
    }

    DNS_HEADER* header = (DNS_HEADER*)response;
    int answer_count = ntohs(header->ancount);

    if (answer_count == 0) {
        return;
    }

    // 跳过问题部分
    unsigned char* ptr = response + sizeof(DNS_HEADER);

    // 查找问题部分的结束位置
    while (ptr < response + response_len && *ptr != 0) {
        ptr++;
    }
    ptr++; // 跳过终止符
    ptr += 4; // 跳过 QTYPE 和 QCLASS

    // 解析回答部分
    for (int i = 0; i < answer_count && ptr < response + response_len; i++) {
        // 解析 NAME (可能是压缩指针)
        if ((ptr[0] & 0xC0) == 0xC0) {
            ptr += 2; // 跳过压缩指针
        }
        else {
            // 非压缩形式，这里简化处理，直接跳过
            while (ptr < response + response_len && *ptr != 0) {
                ptr++;
            }
            ptr++; // 跳过终止符
        }

        if (ptr + 10 > response + response_len) {
            break;
        }

        // 解析 TYPE 和 CLASS
        unsigned short type = (ptr[0] << 8) | ptr[1];
        unsigned short class = (ptr[2] << 8) | ptr[3];
        ptr += 4;

        // 解析 TTL
        unsigned int ttl = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        ptr += 4;

        // 解析 RDLENGTH
        unsigned short rdlength = (ptr[0] << 8) | ptr[1];
        ptr += 2;

        // 只处理 A 记录 (IPv4)
        if (type == 1 && class == 1 && ptr + rdlength <= response + response_len) {
            // 提取 IP 地址
            char ip[MAX_IP_LENGTH];
            sprintf_s(ip, MAX_IP_LENGTH, "%d.%d.%d.%d", ptr[0], ptr[1], ptr[2], ptr[3]);

            // 添加到缓存
            add_to_cache(domain, ip);
            printf("从外部DNS响应中获取到域名 %s 对应的 IP: %s，已添加到缓存\n", domain, ip);

            ptr += rdlength;
        }
        else {
            // 跳过其他类型的记录
            ptr += rdlength;
        }
    }
}

// 辅助函数：释放IP地址数组
void free_ips(char** ips) {
    if (ips != NULL) {
        for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
            if (ips[i] != NULL) {
                free(ips[i]);
            }
        }
        free(ips);
    }
}