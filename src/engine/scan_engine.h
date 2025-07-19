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

// Support for lua scripting
extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

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
#include <errno.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <atomic>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include <ldns/ldns.h>

// Custom libraries
#include "default_ports.h"
#include "../utils/helper_functions.h"

struct HostInstance {
    const std::string ipValue;
    std::vector<int> openPorts;

    HostInstance(const std::string& ip) : ipValue(ip){};
};

struct pseudo_header {
    uint32_t sourceIP;
    uint32_t targetIP;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

unsigned short checksum(unsigned short *ptr, int nbytes);
unsigned short checksum(void* b, int len);
std::string GetLocalIP(const std::string& ipValue);
bool EnumerateLDAP(const std::string& host, int port);
std::string GetReverseDNS(const std::string& ipValue);
std::string TCPServiceProbe(const std::string& ipValue, int port);
std::string DetectDNSService(const std::string& ipValue, int port);
std::string ServiceBannerGrabber(const std::string& ipValue, int port, int timeoutValue);
std::unordered_map<int, std::string> ParseSelectedUDPProbes(
    const std::string& filePath,
    const std::unordered_set<int>& targetPorts
);
std::string SendUDPProbe(const std::string& ip, int port, const std::string& payload, int timeoutSeconds);
bool IsPortOpenTcp(const std::string& ipValue, int port, int timeoutValue);
std::vector<int> PortScanSyn(const std::string& ipValue, const std::vector<int>& ports, float timeoutValue);
bool IsHostUpICMP(const std::string& ipValue);
bool IsHostUpARP(const std::string& ipValue, const std::string& interface);
bool IsValidIP(const std::string& ipValue);
bool RunLuaScript(const std::string& scriptPath, const std::string& targetIP, int port);