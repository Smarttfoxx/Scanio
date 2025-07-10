/*
* GNU GENERAL PUBLIC LICENSE
* Version 3, 29 June 2007

* Copyright (C) 2025 Smarttfoxx

* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, 
* or any later version.

* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.

* This program comes with ABSOLUTELY NO WARRANTY; This is free software, 
* and you are welcome to redistribute it under certain conditions.
*/

#pragma once

// C++ libraries
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <atomic>

// Custom libraries
#include "default_ports.h"
#include "../dependencies/helper_functions.hpp"

struct HostInstance {
    const std::string ipValue;
    std::vector<int> openPorts;

    HostInstance(const std::string& ip) : ipValue(ip){};
};

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    
    return (unsigned short)(~sum);
}

unsigned short checksum(void* b, int len) {
    unsigned short* buf = static_cast<unsigned short*>(b);
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char*)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

std::string GetLocalIP(const std::string& ipValue) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        return "";

    struct sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53);

    inet_pton(AF_INET, ipValue.c_str(), &dest_addr.sin_addr);
    connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    struct sockaddr_in local_addr = {};
    socklen_t addr_len = sizeof(local_addr);
    getsockname(sockfd, (struct sockaddr*)&local_addr, &addr_len);

    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip));

    close(sockfd);

    return std::string(local_ip);

}

std::string ServiceBannerGrabber(const std::string& ipValue, int port, int timeoutValue) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        return "";

    struct timeval timeout;
    timeout.tv_sec = timeoutValue;
    timeout.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ipValue.c_str(), &addr.sin_addr);

    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sockfd);
        return "";
    }

    // If the port is a known web port, send a HEAD request.
    // The HEAD request will make us receive the server information.
    if (std::find(common_web_ports.begin(), common_web_ports.end(), port) != common_web_ports.end()) {
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
        if (std::find(common_web_ports.begin(), common_web_ports.end(), port) != common_web_ports.end()) {
            std::string banner_lower = banner;
            std::transform(banner_lower.begin(), banner_lower.end(), banner_lower.begin(), [](unsigned char c) { return std::tolower(c); });

            size_t pos = banner_lower.find("server: ");

            if (pos != std::string::npos)  {
                size_t start = pos + 8;
                size_t end = banner.find("\r\n", start);
                
                if (end != std::string::npos) 
                    banner = banner.substr(start, end - start);
                else
                    banner = banner.substr(start);
            }
        }

        // If the port is a known FTP port, filter the response.
        // This will give us only the FTP service information.
        // That information is available in the header.
        if (std::find(common_ftp_ports.begin(), common_ftp_ports.end(), port) != common_ftp_ports.end()) {
            size_t pos = banner.find("220 ");

            if (pos != std::string::npos)
            {
                size_t start = pos + 4;
                size_t end = banner.find("[", start);

                if (end != std::string::npos)
                    banner = banner.substr(start, end - start);
                else
                    banner = banner.substr(start);
            }
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(timeoutValue))
            break;
        
        if (bytes == 0 || (bytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN))
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    close(sockfd);

    while (!banner.empty() && (banner.back() == '\n' || banner.back() == '\r'))
        banner.pop_back();

    return !banner.empty() ? banner : "";
}

bool IsPortOpenTcp(const std::string& ipValue, int port, int timeoutValue) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
        return false;

    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = timeoutValue;
    timeout.tv_usec = 0;

    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ipValue.c_str(), &addr.sin_addr);

    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) == 0) {
        logsys.NewEvent("Found open port", port, "/tcp on host", ipValue);
        close(sockfd);
        return true;
    }

    close(sockfd);

    return false;
}

std::vector<int> PortScanSyn(const std::string& ipValue, const std::vector<int>& ports, float timeoutValue) {
    std::vector<int> open_ports;
    std::unordered_set<int> scanned_ports;
    std::unordered_map<int, int> port_map;

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (raw_sock < 0) {
        perror("socket");
        return open_ports;
    }

    // Set non-blocking
    int flags = fcntl(raw_sock, F_GETFL, 0);
    fcntl(raw_sock, F_SETFL, flags | O_NONBLOCK);

    int one = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // epoll setup
    int epfd = epoll_create1(0);
    if (epfd == -1) {
        perror("epoll_create1");
        close(raw_sock);
        return open_ports;
    }

    epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = raw_sock;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
        perror("epoll_ctl");
        close(raw_sock);
        close(epfd);
        return open_ports;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, ipValue.c_str(), &dst.sin_addr);

    char packet[4096];

    std::string local_ip;
    {
        int tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in tmp_dst{};
        tmp_dst.sin_family = AF_INET;
        tmp_dst.sin_port = htons(53);
        inet_pton(AF_INET, ipValue.c_str(), &tmp_dst.sin_addr);
        connect(tmp_sock, (sockaddr*)&tmp_dst, sizeof(tmp_dst));
        sockaddr_in local_addr{};
        socklen_t len = sizeof(local_addr);
        getsockname(tmp_sock, (sockaddr*)&local_addr, &len);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_addr.sin_addr, buf, sizeof(buf));
        local_ip = buf;
        close(tmp_sock);
    }

    uint32_t src_addr = inet_addr(local_ip.c_str());
    uint32_t dst_addr = inet_addr(ipValue.c_str());

    // Send SYN packets
    for (int port : ports) {
        memset(packet, 0, sizeof(packet));

        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htons(54321);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = src_addr;
        iph->daddr = dst_addr;

        iph->check = checksum((unsigned short *)packet, iph->ihl << 2);

        tcph->source = htons(12345);
        tcph->dest = htons(port);
        tcph->seq = htonl(0);
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        pseudo_header psh{};
        psh.src_addr = src_addr;
        psh.dst_addr = dst_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        char pseudo[sizeof(pseudo_header) + sizeof(struct tcphdr)];
        memcpy(pseudo, &psh, sizeof(psh));
        memcpy(pseudo + sizeof(psh), tcph, sizeof(struct tcphdr));

        tcph->check = checksum((unsigned short*)pseudo, sizeof(pseudo));

        if (sendto(raw_sock, packet, iph->tot_len, 0, (sockaddr*)&dst, sizeof(dst)) < 0) {
            perror("sendto");
        }

        scanned_ports.insert(port);
    }

    auto start = std::chrono::steady_clock::now();
    epoll_event events[64];
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Receive the response
    while (true) {
        int nfds = epoll_wait(epfd, events, 64, 500);
        auto now = std::chrono::steady_clock::now();
        float elapsed = std::chrono::duration<float>(now - start).count();

        if (elapsed > timeoutValue)
            break;

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == raw_sock) {
                char buffer[4096];
                sockaddr_in sender{};
                socklen_t sender_len = sizeof(sender);
                
                while (true) {
                    sockaddr_in sender{};
                    socklen_t sender_len = sizeof(sender);
                    int len = recvfrom(raw_sock, buffer, sizeof(buffer), 0, (sockaddr*)&sender, &sender_len);
                    
                    if (len < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        continue;
                    }

                    struct iphdr *iph = (struct iphdr *)buffer;
                    if (iph->protocol != IPPROTO_TCP) continue;

                    int ip_header_len = iph->ihl * 4;
                    if (len < ip_header_len + sizeof(tcphdr)) continue;

                    struct tcphdr *tcph = (struct tcphdr *)(buffer + ip_header_len);

                    if (tcph->syn && tcph->ack) {
                        int sport = ntohs(tcph->source);
                        if (scanned_ports.find(sport) != scanned_ports.end()) {
                            open_ports.push_back(sport);
                            scanned_ports.erase(sport);
                        }
                    }
                }
            }
        }
    }

    close(epfd);
    close(raw_sock);
    return open_ports;
}

bool IsHostUpICMP(const std::string& ipValue) {

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd < 0) {
        logsys.Warning("Operation not permitted. Please run as root.");
        exit(1);
    }

    struct timeval timeout = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ipValue.c_str(), &addr.sin_addr);

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

bool IsValidIP(const std::string& ipValue) {
    sockaddr_in addr;

    return inet_pton(AF_INET, ipValue.c_str(), &(addr.sin_addr)) == 1;
}