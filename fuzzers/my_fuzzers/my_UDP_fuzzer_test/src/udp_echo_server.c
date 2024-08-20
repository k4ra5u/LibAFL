
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


#define PORT 12345
#define BUFFER_SIZE 1024
#define ACCEPT true
#define REJECT false



void error(const char *msg) {
    perror(msg);
    exit(1);
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
        int n = recvfrom(server_fd, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *) &client_addr, &client_len);
        if (n < 0) {
            error("Error reading from socket");
        }

        printf("Received message: %s\n", buffer);
        if (strncmp(buffer, "19951206", 8) == 0) {
            printf("Triggering crash!\n");
            char *ptr = NULL;
            *ptr = 0; // 触发崩溃
        }

        n = sendto(server_fd, buffer, strlen(buffer), 0, (struct sockaddr *) &client_addr, client_len);
        if (n < 0) {
            error("Error writing to socket");
        }
    }

    // 关闭套接字
    close(server_fd);

    return 0;
}

int main ()
{
    udp_echo();
    return 0;
}