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

// C++ libraries
#include <queue>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <functional>

// Custom libraries
#include "interfaces/visuals.hpp"
#include "engine/scan_engine.hpp"

int main(int argc, char* argv[]) {

    int portScan_timeout = 1;
    int servScan_timeout = 1;
    int threadAmount = 100;

    bool isHostUp = false;
    bool enableFindService = false;
    bool enableTCPScan = false;
    bool enableARPScan = false;
    bool enableLUA = false;

    std::string networkInterface;

    std::vector<HostInstance> HostInstances;
    std::vector<int> portsToScan;
    std::vector<std::string> luaScripts;

    std::mutex result_mutex;

    std::atomic<int> scannedServicesCount{0};
    std::atomic<int> scannedPortsCount{0};

    RenderBanner();

    // --- Argument Parsing ---
    for (int i = 1; i < argc; ++i) {

        std::string arg = argv[i];

        // Parse IPs (individual, comma-separated, or CIDR notation)
        if ((arg == "-i" || arg == "--ip") && i + 1 < argc) {

            std::string IPValue = argv[++i];
            std::stringstream ss(IPValue);
            std::string buffer;

            if (IPValue.find(',') != std::string::npos) {
                while (std::getline(ss, buffer, ',')) {
                    HostInstances.emplace_back(HostInstance{buffer});
                }
            } else if (IPValue.find('/') != std::string::npos) {
                std::string ipPart;
                std::getline(ss, ipPart, '/');
                std::getline(ss, buffer, '/');
                int subnetBits = std::stoi(buffer);
                int hostAmount = 0;

                in_addr addr{};
                inet_pton(AF_INET, ipPart.c_str(), &addr);
                uint32_t baseIP = ntohl(addr.s_addr);

                if (subnetBits >= 1 && subnetBits <= 30)
                    hostAmount = (1u << (32 - subnetBits)) - 2;
                else if (subnetBits == 31)
                    hostAmount = 2;
                else if (subnetBits == 32)
                    hostAmount = 1;
                else
                    hostAmount = 0;

                for (int i = 1; i <= hostAmount; ++i) {
                    uint32_t subnetMask = ~((1u << (32 - subnetBits)) - 1);
                    uint32_t hostIP = (baseIP & subnetMask) + i;
                    addr.s_addr = htonl(hostIP);
                    char ipString[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr, ipString, INET_ADDRSTRLEN);
                    HostInstances.emplace_back(HostInstance(std::string(ipString)));
                }

            } else
                HostInstances.emplace_back(HostInstance{IPValue});

            if (IPValue.empty()) {
                logsys.Warning("No IP provided.");
                logsys.Info("Usage: hugin -i <IP> -p <PORT(s)> <options>");
                return 1;
            }

        // Parse ports (single, range, or list)
        } else if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            std::string portValue = argv[++i];
            std::stringstream ss(portValue);
            std::string buffer;

            if (portValue.find(',') != std::string::npos) {
                while (std::getline(ss, buffer, ',')) {
                    if (!isInteger(buffer))
                        return 1;

                    portsToScan.push_back(std::stoi(buffer));
                }
            } else if (portValue.find('-') != std::string::npos) {
                while (std::getline(ss, buffer, '-')) {
                    int start = std::stoi(buffer);
                    
                    std::getline(ss, buffer, '-');
                    int end = std::stoi(buffer);

                    for (int i = start; i <= end; ++i)
                        portsToScan.push_back(i);

                }
            } else {
                if (!isInteger(portValue))
                    return 1;

                portsToScan.push_back(std::stoi(portValue));
            }
        
        // Set timeout delay (in seconds)
        } else if ((arg == "-d" || arg == "--delay") && i + 1 < argc) {
            portScan_timeout = std::stoi(argv[++i]);

        // Enable service banner grabbing
        } else if (arg == "-S" || arg == "--service") {
            enableFindService = true;

        // Use top X most common ports
        } else if ((arg == "-Tp" || arg == "--top-ports") && i + 1 < argc) {
            std::string portQuantArg = argv[++i];

            if (!isInteger(portQuantArg))
                return 1;

            int portAmount = std::stoi(portQuantArg);
            portsToScan.assign(common_ports_thousand.begin(), common_ports_thousand.begin() + std::min(portAmount, (int)common_ports_thousand.size()));

        // Scan all 65535 TCP ports
        } else if (arg == "-Ap" || arg == "--all-ports") {
            std::vector<int> allTcpPorts;

            for (int i = 1; i <= 65535; ++i)
                allTcpPorts.push_back(i);

            portsToScan = allTcpPorts;

        // Enable TCP connect scan
        } else if (arg == "-Ts" || arg == "--tcp-scan") {
            enableTCPScan = true;

        // Enable ARP host discovery
        } else if (arg == "Ar" || arg == "--arp-scan") {
            enableARPScan = true;

        // Set network interface for ARP scan
        } else if ((arg == "--interface") && i + 1 < argc) {
            networkInterface = argv[++i];

        // Set custom thread count
        } else if ((arg == "-Th" || arg == "--threads") && i + 1 < argc) {
            threadAmount = std::stoi(argv[++i]);

        // Add Lua script to run
        } else if ((arg == "-L" || arg == "--lua-script") && i + 1 < argc) {
            enableLUA = true;
            std::string scriptPath = argv[++i];
            luaScripts.push_back(scriptPath);

        // Print help section
        } else if (arg == "-h" || arg == "--help") {
            RenderHelp();
            return 1;

        // Unknown argument fallback
        } else {
            logsys.Warning("Unknown argument was passed.");
            logsys.Info("Usage: hugin -i <IP> -p <PORT(s)> <options>");
            return 1;
        }
    }

    // --- Host Discovery Phase ---
    for (const HostInstance& HostObject : HostInstances) {
        if (!IsValidIP(HostObject.ipValue)) {
            logsys.Warning("Invalid address was provided.");
            return 1;
        }

        if (enableARPScan) {
            if (IsHostUpARP(HostObject.ipValue, networkInterface))
                logsys.Info("The host", HostObject.ipValue, "is up");
            else
                logsys.Warning("The host is down.");
        } else {
            if (IsHostUpICMP(HostObject.ipValue))
                logsys.Info("The host", HostObject.ipValue, "is up");
            else
                logsys.Warning("The host is down or blocking ICMP. Continuing anyways...");
        }
    }

    if (portsToScan.empty()) {
        portsToScan = common_ports_thousand;
    }

    ThreadPool pool(threadAmount);
    auto scanStartTime = std::chrono::steady_clock::now();

    logsys.Info("Using a total of", threadAmount, "threads for the scan.");

    // --- Port Scanning Phase ---
    for (HostInstance& HostObject : HostInstances) {
        auto pOpenPorts = &HostObject.openPorts;

        logsys.Info("Scanning for open ports on host", HostObject.ipValue);

        // TCP connect scan (parallelized)
        if (enableTCPScan) {
            for (int port : portsToScan) {
                pool.enqueue([=, &result_mutex, &scannedPortsCount, &isHostUp]() {
                    bool isPortOpen = IsPortOpenTcp(HostObject.ipValue, port, portScan_timeout);
                    if (isPortOpen) {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        pOpenPorts->push_back(port);
                        isHostUp = true;
                    }
                    ++scannedPortsCount;
                });
            }

            // Wait for all ports to be scanned
            while (scannedPortsCount.load() < portsToScan.size())
                ts.SleepMilliseconds(500);

            scannedPortsCount = 0;
        } else {
            // TCP SYN scan (batch-based)
            std::vector<int> openPort = PortScanSyn(HostObject.ipValue, portsToScan, portScan_timeout);

            logsys.Info("Scanning", portsToScan.size(), "ports via SYN.");

            if (!openPort.empty()) {
                std::lock_guard<std::mutex> lock(result_mutex);
                pOpenPorts->insert(pOpenPorts->end(), openPort.begin(), openPort.end());
                isHostUp = true;

                for (int port : openPort)
                    logsys.NewEvent("Found open port", (std::to_string(port) + "/tcp on host"), HostObject.ipValue);
            } else
                logsys.Warning("No open ports found via SYN.");
        }

        if (!isHostUp)
            logsys.Warning("No open ports were found, is the host online?");

        // --- Service and LUA Scanning Phase ---   
        if (enableFindService || enableLUA && !(HostObject.openPorts.empty())) {
            logsys.Info("Starting service scanner on host", HostObject.ipValue);
            
            std::cout << std::left;
            std::cout << std::setw(12) << "PORT" << std::setw(8) << "STATE" << "SERVICE/VERSION\n";
            for (int port : HostObject.openPorts) {
                if (!enableLUA) {
                    // Adjust timeout for FTP services
                    if (FindIn(common_ftp_ports, port))
                        servScan_timeout = 12;
        
                    // Grab service banner in parallel
                    pool.enqueue([&, port]() {
                        std::string s_service_banner;
                        bool isPortOpen = true;
                        
                        s_service_banner = ServiceBannerGrabber(HostObject.ipValue, port, servScan_timeout);

                        if (s_service_banner.empty())
                            isPortOpen = false;

                        if (isPortOpen) {
                            std::lock_guard<std::mutex> lock(result_mutex);
                            std::cout << std::setw(12) << (std::to_string(port) + "/tcp") 
                                    << std::setw(8) << "open" 
                                    << (s_service_banner.empty() ? "No service found." : s_service_banner) 
                                    << "\n";
                        }
                        scannedServicesCount++;
                    });
                } else {
                    // Run Lua scripts
                    for (const std::string& script : luaScripts) {
                        logsys.Info("Running script", script, "on", HostObject.ipValue, "port", port);
                        RunLuaScript(script, HostObject.ipValue, port);
                    }
                }
            }
            // Wait for service scanning to finish
            while (scannedServicesCount.load() < HostObject.openPorts.size())
                ts.SleepMilliseconds(500);

            if (scannedServicesCount.load() >= HostObject.openPorts.size())
                scannedServicesCount = 0;
        }
    }

    // --- Scan Summary ---
    auto scanEndTime = std::chrono::steady_clock::now();
    auto scanElapsedTime = std::chrono::duration_cast<std::chrono::seconds>(scanEndTime - scanStartTime).count();

    logsys.Info("Scan completed in", scanElapsedTime, "seconds.");
    logsys.Info("A total of", portsToScan.size(), "ports were scanned.");

    return 0;
}