#pragma once
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>
#include <fcntl.h>

inline std::string banner_grabber(const std::string& ip, int port, int timeout_sec) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return "";

    struct timeval timeout{};
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sockfd);
        return "";
    }

    std::string banner;
    char buffer[1024];
    auto start = std::chrono::steady_clock::now();

    while (true)
    {
        int bytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);

        if (bytes > 0)
        {
            buffer[bytes] = '\0';
            banner += buffer;
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        
        if (elapsed > std::chrono::seconds(timeout_sec)) break;

        if (bytes == 0 || (bytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN)) break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    close(sockfd);
    return !banner.empty() ? banner : "";
}

inline bool is_port_open(const std::string& ip, int port, int timeout_sec) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return false;

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int result = connect(sockfd, (sockaddr*)&addr, sizeof(addr));
    close(sockfd);

    return result == 0;
}