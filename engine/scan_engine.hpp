#pragma once
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#include <iostream>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <iomanip>
#include <fcntl.h>
#include <algorithm>
#include <cctype>

inline std::string ServiceBannerGrabber(const std::string& ip, int port, int timeout_sec) {
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

    if (port == 80 || port == 8080)
    {
        const char* send_head = "HEAD / HTTP/1.0\r\n\r\n";
        send(sockfd, send_head, strlen(send_head), 0);
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

        // Filter by only the server type and version
        if (port == 80 || port == 8080) 
        {
            std::string banner_lower = banner;
            std::transform(banner_lower.begin(), banner_lower.end(), banner_lower.begin(), [](unsigned char c) { return std::tolower(c); });

            size_t pos = banner_lower.find("server: ");

            if (pos != std::string::npos) 
            {
                size_t start = pos + 8;
                size_t end = banner.find("\r\n", start);
                
                if (end != std::string::npos) 
                {
                    banner = banner.substr(start, end - start);
                } else {
                    banner = banner.substr(start);
                }
            }
        }

        // Filter only the FTP server header
        if (port == 21 || port == 2121)
        {
            size_t pos = banner.find("220 ");

            if (pos != std::string::npos)
            {
                size_t start = pos + 4;
                size_t end = banner.find("[", start);

                if (end != std::string::npos)
                {
                    banner = banner.substr(start, end - start);
                } else {
                    banner = banner.substr(start);
                }
            }
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        
        if (elapsed > std::chrono::seconds(timeout_sec)) break;

        if (bytes == 0 || (bytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN)) break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    close(sockfd);

    while (!banner.empty() && (banner.back() == '\n' || banner.back() == '\r')) banner.pop_back();

    return !banner.empty() ? banner : "";
}

inline bool IsPortOpen(const std::string& ip, int port, int timeout_sec) {
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

unsigned short checksum(void* b, int len) {

    unsigned short* buf = static_cast<unsigned short*>(b);
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) sum += *buf++;

    if (len == 1) sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

bool IsHostUpICMP(const std::string& ip) {

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0) {
        perror("socket");
        return false;
    }

    struct timeval timeout = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    char packet[64];
    memset(packet, 0, sizeof(packet));

    icmphdr* icmp = reinterpret_cast<icmphdr*>(packet);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid() & 0xFFFF;
    icmp->un.echo.sequence = 1;
    icmp->checksum = checksum(packet, sizeof(packet));

    ssize_t sent = sendto(sockfd, packet, sizeof(packet), 0, (sockaddr*)&addr, sizeof(addr));

    if (sent < 0) {
        perror("sendto");
        close(sockfd);
        return false;
    }

    char recv_buf[1024];
    sockaddr_in recv_addr {};
    socklen_t addr_len = sizeof(recv_addr);
    ssize_t received = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0, (sockaddr*)&recv_addr, &addr_len);
    close(sockfd);

    return received > 0;
}

bool IsValidIP(const std::string& ip) {
    sockaddr_in addr;
    return inet_pton(AF_INET, ip.c_str(), &(addr.sin_addr)) == 1;
}