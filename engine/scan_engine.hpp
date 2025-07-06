#pragma once
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <chrono>
#include <thread>
#include <iomanip>
#include <fcntl.h>
#include <algorithm>
#include <cctype>
#include <atomic>

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

std::string GetLocalIP(const std::string& ip_buffer) {

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return "";

    struct sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53);
    inet_pton(AF_INET, ip_buffer.c_str(), &dest_addr.sin_addr);

    connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    struct sockaddr_in local_addr = {};
    socklen_t addr_len = sizeof(local_addr);
    getsockname(sockfd, (struct sockaddr*)&local_addr, &addr_len);

    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip));

    close(sockfd);
    return std::string(local_ip);

}

std::string ServiceBannerGrabber(const std::string& s_ip, int port, int timeout_sec) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return "";

    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, s_ip.c_str(), &addr.sin_addr);

    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sockfd);
        return "";
    }

    // If the port is a known web port, send a HEAD request.
    // The HEAD request will make us receive the server information.
    if (port == 80 || port == 8080) {
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

        // If the port is a known web port receives its response
        // Transform the entire response in lowercase to filter it.
        if (port == 80 || port == 8080) {
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

        // If the port is a known FTP port, filter the response.
        // This will give us only the FTP service information.
        // That information is available in the header.
        if (port == 21 || port == 2121) {
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
        if (elapsed > std::chrono::seconds(timeout_sec))
            break;
        
        if (bytes == 0 || (bytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN))
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    close(sockfd);

    while (!banner.empty() && (banner.back() == '\n' || banner.back() == '\r')) banner.pop_back();

    return !banner.empty() ? banner : "";
}

bool IsPortOpenTcp(const std::string& s_ip, int port, int timeout_sec) {

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
    inet_pton(AF_INET, s_ip.c_str(), &addr.sin_addr);

    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) == 0) {
        std::cout << "[+] Found open port " << port << "/tcp on host " << s_ip << "\n";
        close(sockfd);
        return true;
    }

    close(sockfd);
    return false;
}

bool IsPortOpenSyn(const std::string& s_ip, int port, int timeout_sec) {

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    
    if (sockfd < 0) {
        perror("socket");
        close(sockfd);
        return 0;
    }

    int one = 1;
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;

    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    std::string local_ip = GetLocalIP(s_ip);
    if (local_ip.empty()) return false;
    ip->saddr = inet_addr(local_ip.c_str());
    ip->daddr = inet_addr(s_ip.c_str());
    ip->check = checksum((unsigned short*)ip, sizeof(struct iphdr));

    uint16_t source_port = 33217;
    tcp->source = htons(source_port);
    tcp->dest = htons(port);
    tcp->seq = htonl(0);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(5840);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    struct pseudo_header {
        uint32_t src, dst;
        uint8_t zero, protocol;
        uint16_t tcp_len;
    } psh;

    psh.src = ip->saddr;
    psh.dst = ip->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));

    char pseudo[sizeof(psh) + sizeof(struct tcphdr)];
    memcpy(pseudo, &psh, sizeof(psh));
    memcpy(pseudo + sizeof(psh), tcp, sizeof(struct tcphdr));

    tcp->check = checksum((unsigned short *)pseudo, sizeof(pseudo));

    struct sockaddr_in dest = {};
    dest.sin_family = AF_INET;
    dest.sin_port = tcp->dest;
    dest.sin_addr.s_addr = ip->daddr;

    if (sendto(sockfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto function failed");
        close(sockfd);
        return false;
    }

    char buffer[4096];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    while (true) {
        ssize_t bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&sender, &sender_len);

        if (bytes < 0) {
            close(sockfd);
            return false;
        }

        struct iphdr *rip = (struct iphdr *)buffer;
        if (rip->protocol != IPPROTO_TCP) continue;

        int ip_header_len = rip->ihl * 4;
        struct tcphdr *rtcp = (struct tcphdr *)(buffer + ip_header_len);

        // Match correct source/dest IP and port
        if (rip->saddr == ip->daddr && rip->daddr == ip->saddr &&
            ntohs(rtcp->source) == port && ntohs(rtcp->dest) == source_port) {

            if (rtcp->syn && rtcp->ack) {
                std::cout << "[+] Found open port " << port << "/tcp on host " << s_ip << "\n";
                close(sockfd);
                return true;
            } else if (rtcp->rst) {
                close(sockfd);
                return false;
            }
        }
    }
}

bool IsHostUpICMP(const std::string& ip) {

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0) {
        std::cerr << "[!] Operation not permitted. Please run as root.\n";
        exit(1);
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