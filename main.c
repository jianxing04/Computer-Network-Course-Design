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

// 缓存条目结构
typedef struct {
    char domain[256];
    char ip[16];
    time_t timestamp;
} CACHE_ENTRY;

// 传递给线程的参数结构
typedef struct {
    SOCKET sockfd;
    struct sockaddr_in client_addr;
    int client_addr_len;
    unsigned char* buffer;
    int recv_len;
} CLIENT_PARAM;

// 全局变量
CACHE_ENTRY cache[MAX_CACHE_ENTRIES];
CRITICAL_SECTION cache_lock;
int cache_count = 0;
LONG count_recv = 0;  // 使用 LONG 类型配合原子操作

// 函数声明
void parse_dns_query(unsigned char* buffer, int len, char* domain, int domain_size);
void send_dns_response(SOCKET sockfd, struct sockaddr_in* client_addr, int client_addr_len,
    unsigned char* request, int request_len, const char* ip);
DWORD WINAPI handle_client(LPVOID arg);

int main() {
    WSADATA wsaData;
    SOCKET sockfd;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    HANDLE threads[MAX_CLIENTS];
    int thread_count = 0;

    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    // 创建UDP套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // 设置套接字选项
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("setsockopt failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    // 准备服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    // 绑定套接字
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    printf("DNS中继服务器启动，监听地址: 127.0.0.1:%d\n", DNS_PORT);

    InitializeCriticalSection(&cache_lock);  // 初始化缓存锁

    // 主循环
    while (1) {
        // 分配缓冲区
        unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE);
        if (!buffer) {
            printf("内存分配失败\n");
            continue;
        }

        // 接收客户端请求
        int recv_len = recvfrom(sockfd, (char*)buffer, BUFFER_SIZE, 0,
            (struct sockaddr*)&client_addr, &client_addr_len);
        if (recv_len == SOCKET_ERROR) {
            printf("接收数据失败: %d\n", WSAGetLastError());
            free(buffer);
            continue;
        }

        // 分配参数结构
        CLIENT_PARAM* param = (CLIENT_PARAM*)malloc(sizeof(CLIENT_PARAM));
        if (!param) {
            printf("参数结构内存分配失败\n");
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
            printf("创建线程失败: %d\n", GetLastError());
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
    DeleteCriticalSection(&cache_lock);
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

    // 分配 IP 地址
    char* ip = (char*)malloc(MAX_IP_LENGTH);
    if (ip == NULL) {
        printf("ip内存分配失败\n");
        free(buffer);
        free(param);
        return 1;
    }

    // 检查是否为反向 DNS 查询
    if (strstr(domain, ".in-addr.arpa") != NULL) {
        // 处理反向 DNS 查询，这里简单返回默认值
        strcpy_s(ip, MAX_IP_LENGTH, "127.0.0.1");
    }
    else {
        // 正向 DNS 查询，在域名库中查找 IP
        strcpy_s(ip, MAX_IP_LENGTH, "127.0.0.1"); // 默认 IP
    }

    // 发送响应
    send_dns_response(sockfd, &client_addr, client_addr_len, buffer, recv_len, ip);

    // 释放资源
    free(buffer);
    free(param);
    free(ip);

    return 0;
}

// 解析DNS查询中的域名
void parse_dns_query(unsigned char* buffer, int len, char* domain, int domain_size) {
    // 检查输入参数的有效性
    if (buffer == NULL || domain == NULL || len < (int)sizeof(DNS_HEADER)) {
        if (domain != NULL) {
            domain[0] = '\0'; // 确保 domain 不为 NULL 后再取消引用
        }
        return;
    }

    DNS_HEADER* header = (DNS_HEADER*)buffer;
    unsigned char* qname = buffer + sizeof(DNS_HEADER);// 跳过头部
    int pos = 0;

    // 解析域名部分
    while (pos < domain_size - 1 && qname < buffer + len) {// 确保 qname 在有效范围内
        int label_len = *qname++;// 读取标签长度
        if (label_len == 0) break;

        // 检查是否为压缩指针
        if ((label_len & 0xC0) == 0xC0) {
            // 处理压缩指针
            unsigned short pointer = ((label_len & 0x3F) << 8) | *qname++;
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
    unsigned char* request, int request_len, const char* ip) {
    // 分配响应缓冲区
    unsigned char* response = (unsigned char*)malloc(BUFFER_SIZE);
    if (!response) {
        printf("响应缓冲区分配失败\n");
        return;
    }
    memset(response, 0, BUFFER_SIZE);

    // 复制请求头部到响应
    memcpy(response, request, sizeof(DNS_HEADER));

    // 修改头部标志为响应
    DNS_HEADER* header = (DNS_HEADER*)response;
    header->qr = 1;    // 查询/响应标志设为响应
    header->ra = 1;    // 递归可用
    header->ancount = htons(1);  // 一个回答记录

    // 复制问题部分到响应
    int question_len = 0;
    unsigned char* qname = request + sizeof(DNS_HEADER);
    while (question_len < request_len - sizeof(DNS_HEADER) && qname[question_len] != 0) {
        question_len++;
    }
    question_len++;  // 加上结尾的'0'字符
    question_len += 4;  // 加上 QTYPE 和 QCLASS (4字节)
    memcpy(response + sizeof(DNS_HEADER), qname, question_len);

    // 构建回答部分
    int response_pos = sizeof(DNS_HEADER) + question_len;

    // 域名指针 (指向问题部分的域名),NAME部分使用压缩指针
    response[response_pos++] = 0xC0;  // 压缩指针
    response[response_pos++] = 0x0C;  // 指向问题部分的域名,偏移量为12字节

    // 类型和类 (A记录, IN类)
    response[response_pos++] = 0x00;
    response[response_pos++] = 0x01;  // TYPE A，IPv4地址，2字节
    response[response_pos++] = 0x00;
    response[response_pos++] = 0x01;  // CLASS IN，互联网，2字节

    // TTL (300秒)
    unsigned int ttl = htonl(300);// 300秒，4字节，网络字节序
    memcpy(&response[response_pos], &ttl, 4);
    response_pos += 4;

    // RDLENGTH (IPv4地址长度)
    response[response_pos++] = 0x00;
    response[response_pos++] = 0x04;// IPv4地址长度，4字节

    // IP地址
    unsigned char ip_parts[4];
    if (sscanf_s(ip, "%hhu.%hhu.%hhu.%hhu", &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]) != 4) {// 检查IP地址格式
        printf("Invalid IP address format: %s\n", ip);
        free(response);
        return;
    }
    memcpy(&response[response_pos], ip_parts, 4);// 4字节的IPv4地址
    response_pos += 4;

    // 发送响应
    int sent_bytes = sendto(sockfd, (char*)response, response_pos, 0,
        (struct sockaddr*)client_addr, client_addr_len);
    if (sent_bytes == SOCKET_ERROR) {
        printf("发送响应失败: %d\n", WSAGetLastError());
    }
    else {
        printf("已发送响应，长度: %d 字节\n", sent_bytes);
    }

    // 释放响应缓冲区
    free(response);
}