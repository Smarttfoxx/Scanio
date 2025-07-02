// C++ libraries
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <vector>
#include <chrono>

// Custom libraries
#include "interfaces/banner.hpp"
#include "engine/scan_engine.hpp"
#include "engine/default_ports.h"
#include "dependencies/helper_functions.hpp"

int main(int argc, char* argv[])
{
    int timeout_sec = 1;
    int service_timeout_sec = 1;
    int port_amount = 0;

    bool bShow_only_open_port = false;
    bool bShow_closed_filtered = false;
    bool bFind_service = false;
    bool bIs_up = false;

    std::string s_ip;
    std::string s_service_banner;
    std::string s_port_amount;

    std::vector<int> open_ports;
    std::vector<int> ports;
    std::vector<int> all_tcp_ports;

    call_banner();

    // Check if arguments were passed
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if ((arg == "-i" || arg == "--ip") && i + 1 < argc)
        {
            s_ip = argv[++i];

            // If the "ip" variable is empty
            if (s_ip.empty())
            {
                std::cerr << "[!] No IP provided.\n";
                std::cerr << "[*] Default usage: " << argv[0] << " -i <IP> -p <PORT(s)>\n";
                return 1;
            }

        } else if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            std::stringstream ss(argv[++i]);
            std::string token;

            while (std::getline(ss, token, ','))
            {
                if (!isStringInteger(token)) // Check if value passed is not an integer
                    return 1;

                ports.push_back(std::stoi(token));
            }

        } else if ((arg == "-t" || arg == "--timeout") && i + 1 < argc) {
            timeout_sec = std::stoi(argv[++i]);

        } else if (arg == "-S" || arg == "--service") {
            bFind_service = true;

        } else if ((arg == "-Tp" || arg == "--top-ports") && i + 1 < argc) {
            s_port_amount = argv[++i];

            if (!isStringInteger(s_port_amount)) // Check if value passed is not an integer
                return 1;

            port_amount = std::stoi(s_port_amount);
            ports.assign(common_ports_thousand.begin(), common_ports_thousand.begin() + std::min(port_amount, (int)common_ports_thousand.size()));

        } else if (arg == "-Ap" || arg == "--all-ports") {
            for (int i = 1; i <= 65535; ++i) {
                all_tcp_ports.push_back(i);
            }
            ports = all_tcp_ports;

        } else if (arg == "-sI" || arg == "--scan-icmp"){
            if (!IsHostUpICMP(s_ip))
            {
                std::cerr << "[!] ICMP shows that host is down or filtered.\n";
                return 1;
            }
        } else {
            std::cerr << "[!] Unknown argument\n";
            std::cerr << "[*] Default usage: " << argv[0] << " -i <IP> -p <PORT(s)>\n";
            return 1;
        }
    }

    if (!IsValidIP(s_ip))
    {
        std::cerr << "Invalid address was provided.\n";
        return 1;
    }

    // If the "port" variable is empty, use common 1000 TCP ports
    if (ports.empty()) ports = common_ports_thousand;

    // Start port scanner
    std::cout << "[*] Scanning for open ports...\n";
    auto scan_start_time = std::chrono::steady_clock::now();

    for (int port : ports)
    {
        if (IsPortOpen(s_ip, port, timeout_sec))
        {
            std::cout << "[+] Found open port " << port << "/tcp on host " << s_ip << "\n";
            open_ports.push_back(port);
            bIs_up = true;
        } else if (!bIs_up) {
            std::cerr << "No open ports were found, is the host online?\n";
            return 1;
        }

        if (bShow_closed_filtered) 
        {
            std::cerr << "Port " << port << " is CLOSED or FILTERED\n";
        }
    }

    // Call the find services function
    if (bFind_service && !(open_ports.empty()))
    {
        std::cout << "\n[*] Starting service scanner...\n";
        
        std::cout << std::left; // Alings text to the left
        std::cout << std::setw(12) << "PORT" << std::setw(8) << "STATE" << "SERVICE/VERSION\n";

        for (int port : open_ports)
        {
            if (port == 21 || port == 2121) service_timeout_sec = 12; // If the service is FTP, increase wait time to grab header
            else service_timeout_sec = 1;
            s_service_banner = ServiceBannerGrabber(s_ip, port, service_timeout_sec);
            std::cout << std::setw(12) << (std::to_string(port) + "/tcp") << std::setw(8) << "open" << (s_service_banner.empty() ? "No service found" : s_service_banner) << "\n";
        }
    }

    auto scan_end_time = std::chrono::steady_clock::now() - scan_start_time;
    int total_seconds = std::chrono::duration_cast<std::chrono::seconds>(scan_end_time).count();
    int minutes = total_seconds / 60;
    int seconds = total_seconds % 60;
    
    std::cout << "\nA total of " << ports.size() << " ports were scanned in " << minutes << "m:" << seconds << "s\n";

    return 0;
}