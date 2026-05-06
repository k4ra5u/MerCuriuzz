#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#define PORT 12345
#define BUFFER_SIZE 1024
__AFL_FUZZ_INIT();

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int set_socket_timeout(int fd, int timeout_sec) {
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    // 设置接收超时
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        return -1;
    }

    return 0;
}

int udp_echo() {
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE];

    // 创建套接字
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        error("Error opening socket");
    }

    // 设置接收超时为 5 秒
    if (set_socket_timeout(server_fd, 5) < 0) {
        error("Error setting socket timeout");
    }

    // 设置服务器地址结构
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 绑定套接字
    if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        error("Error on binding");
    }

    printf("Server is listening on port %d...\n", PORT);

    // 循环处理客户端消息
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        client_len = sizeof(client_addr);
        int n = recvfrom(server_fd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &client_addr, &client_len);
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // 超时未接收到数据
                printf("Receive timeout, no data received within 5 seconds.\n");
                continue;
            } else {
                error("Error reading from socket");
            }
        }

        printf("Received %d bytes:", n);
        for (int i = 0; i < n; i++) {
            printf("%02x ", (unsigned char)buffer[i]);
        }
        printf("\n");

        // 例如处理特定数据
        if (n >= 4 && memcmp(buffer, "1234", 4) == 0) {
            printf("Triggering crash!\n");
            char *ptr = NULL;
            *ptr = 0; // 触发崩溃
        }

        n = sendto(server_fd, buffer, n, 0, (struct sockaddr *) &client_addr, client_len);
        if (n < 0) {
            error("Error writing to socket");
        }
    }

    // 关闭套接字
    close(server_fd);

    return 0;
}

int main() {
    __AFL_INIT();
    udp_echo();
    return 0;
}