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

#include "arg_parser.h"
#include "../utils/helper_functions.h"
#include "../utils/log_system.h"

ParsedArgs ParseArguments(int argc, char* argv[]) {
    ParsedArgs args;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if ((arg == "-i" || arg == "--ip") && i + 1 < argc) {
            std::string value = argv[++i];
            std::stringstream ss(value);
            std::string token;

            if (value.find(',') != std::string::npos) {
                while (std::getline(ss, token, ',')) {
                    args.hosts.emplace_back(HostInstance{token});
                }
            } else if (value.find('/') != std::string::npos) {
                std::string ip;
                std::getline(ss, ip, '/');
                std::getline(ss, token, '/');
                int bits = std::stoi(token);
                in_addr addr{};
                inet_pton(AF_INET, ip.c_str(), &addr);
                uint32_t baseIP = ntohl(addr.s_addr);
                int count = (bits >= 1 && bits <= 30) ? (1u << (32 - bits)) - 2 : (bits == 31 ? 2 : 1);

                for (int j = 1; j <= count; ++j) {
                    uint32_t subnetMask = ~((1u << (32 - bits)) - 1);
                    uint32_t hostIP = (baseIP & subnetMask) + j;
                    addr.s_addr = htonl(hostIP);
                    char ipBuf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr, ipBuf, INET_ADDRSTRLEN);
                    args.hosts.emplace_back(HostInstance(std::string(ipBuf)));
                }

            } else {
                args.hosts.emplace_back(HostInstance{value});
            }

        } else if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            std::string value = argv[++i];
            std::stringstream ss(value);
            std::string token;

            if (value.find(',') != std::string::npos) {
                while (std::getline(ss, token, ',')) {
                    if (isInteger(token)) args.ports.push_back(std::stoi(token));
                }
            } else if (value.find('-') != std::string::npos) {
                int start, end;
                ss >> start;
                ss.ignore(); // skip '-'
                ss >> end;
                for (int j = start; j <= end; ++j) args.ports.push_back(j);
            } else if (isInteger(value)) {
                args.ports.push_back(std::stoi(value));
            }

        } else if ((arg == "-d" || arg == "--delay") && i + 1 < argc) {
            args.portTimeout = std::stoi(argv[++i]);

        } else if (arg == "-S" || arg == "--service") {
            args.enableFindService = true;

        } else if ((arg == "-Tp" || arg == "--top-ports") && i + 1 < argc) {
            int topN = std::stoi(argv[++i]);
            args.ports.assign(common_ports_thousand.begin(), common_ports_thousand.begin() + std::min(topN, (int)common_ports_thousand.size()));

        } else if (arg == "-Ap" || arg == "--all-ports") {
            for (int p = 1; p <= 65535; ++p) args.ports.push_back(p);

        } else if (arg == "-Ts" || arg == "--tcp-scan") {
            args.enableTCPScan = true;

        } else if (arg == "Ar" || arg == "--arp-scan") {
            args.enableARPScan = true;

        } else if (arg == "--interface" && i + 1 < argc) {
            args.interface = argv[++i];

        } else if ((arg == "-Th" || arg == "--threads") && i + 1 < argc) {
            args.threadCount = std::stoi(argv[++i]);

        } else if ((arg == "-L" || arg == "--lua-script") && i + 1 < argc) {
            args.enableLua = true;
            args.luaScripts.push_back(argv[++i]);

        } else if (arg == "-U" || arg == "--udp") {
            args.enableUDP = true;

        } else if (arg == "-h" || arg == "--help") {
            args.showHelp = true;

        } else {
            logsys.Warning("Unknown argument:", arg.c_str());
            args.showHelp = true;
            return args;
        }
    }

    if (args.ports.empty())
        args.ports = common_ports_thousand;

    return args;
}
