#include "tcp_echo_server.h"

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int tcp_echo() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    char buffer[BUFFER_SIZE];

    // 创建套接字
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
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

    // 监听连接
    if (listen(server_fd, 5) < 0) {
        error("Error on listening");
    }

    printf("Server is listening on port %d...\n", PORT);

    // 接受客户端连接
    client_len = sizeof(client_addr);
    client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_len);
    if (client_fd < 0) {
        error("Error on accept");
    }

    printf("Client connected\n");

    // 循环处理客户端消息
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(client_fd, buffer, BUFFER_SIZE - 1);
        if (n < 0) {
            error("Error reading from socket");
        } else if (n == 0) {
            printf("Client disconnected\n");
            break;
        }

        printf("Received message: %s\n", buffer);
        if (strncmp(buffer, "19951206", 8) == 0) {
            printf("Triggering crash!\n");
            char *ptr = NULL;
            *ptr = 0; // 触发崩溃
        }
        n = write(client_fd, buffer, strlen(buffer));
        if (n < 0) {
            error("Error writing to socket");
        }
    }

    // 关闭连接
    close(client_fd);
    close(server_fd);

    return 0;
}
