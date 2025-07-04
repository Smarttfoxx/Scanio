// C++ libraries
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <vector>
#include <chrono>
#include <thread>

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

    bool bFind_service = false;
    bool bIs_up = false;
    bool bTCP_scan = false;

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

        // Prepare the argument that handles IPs.
        if ((arg == "-i" || arg == "--ip") && i + 1 < argc)
        {
            s_ip = argv[++i];

            // Check if the "s_ip" variable is empty
            if (s_ip.empty())
            {
                std::cerr << "[!] No IP provided.\n";
                std::cerr << "[*] Default usage: " << argv[0] << " -i <IP> -p <PORT(s)>\n";
                return 1;
            }

        // Prepare the argument that handles ports.
        } else if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            std::stringstream ss(argv[++i]);
            std::string token;

            while (std::getline(ss, token, ','))
            {
                // Check if value passed is not an integer.
                // If no integer, break the application.
                if (!isStringInteger(token))
                    return 1;

                ports.push_back(std::stoi(token));
            }
        
        // Prepare the argument that handles timeouts.
        // All the timeout values are defined in seconds.
        } else if ((arg == "-t" || arg == "--timeout") && i + 1 < argc) {
            timeout_sec = std::stoi(argv[++i]);

        // Prepare the argument that enables service scanning.
        } else if (arg == "-S" || arg == "--service") {
            bFind_service = true;

        // Prepare the argument that handles the top ports.
        } else if ((arg == "-Tp" || arg == "--top-ports") && i + 1 < argc) {
            s_port_amount = argv[++i];

            // Check if value passed is not an integer.
            // If no integer, break the application.
            if (!isStringInteger(s_port_amount))
                return 1;

            port_amount = std::stoi(s_port_amount);
            ports.assign(common_ports_thousand.begin(), common_ports_thousand.begin() + std::min(port_amount, (int)common_ports_thousand.size()));

        // Add all known TCP ports to the "ports" variable to scan them.
        } else if (arg == "-Ap" || arg == "--all-ports") {
            for (int i = 1; i <= 65535; ++i) {
                all_tcp_ports.push_back(i);
            }
            ports = all_tcp_ports;

        // Performs TCP scan
        } else if (arg == "-Ts" || arg == "--tcp-scan") {
            bTCP_scan = true;

        // If no valid argument was passed, break.
        } else {
            std::cerr << "[!] Unknown argument\n";
            std::cerr << "[*] Default usage: " << argv[0] << " -i <IP> -p <PORT(s)>\n";
            return 1;
        }
    }

    // Verifies if the value passed to "s_ip" is a valid IP
    if (!IsValidIP(s_ip))
    {
        std::cerr << "Invalid address was provided.\n";
        return 1;
    }

    // Check if host is up via ICMP.
    if (!IsHostUpICMP(s_ip)) {
        std::cerr << "[!] The host is down or blocking ICMP. Continuing...\n";
    } else {
        std::cout << "[*] The host " << s_ip << " is up.\n"; 
    }

    // If the "ports" variable is empty, use common 1000 TCP ports
    if (ports.empty()) ports = common_ports_thousand;

    // Start port scanner
    std::cout << "[*] Scanning for open ports...\n";
    auto scan_start_time = std::chrono::steady_clock::now();

    for (int port : ports)
    {
        if (bTCP_scan) {
            if (IsPortOpenTcp(s_ip, port, timeout_sec)) {
                open_ports.push_back(port);
                bIs_up = true;
            }
        } else {
            if (IsPortOpenSyn(s_ip, port, timeout_sec)) {
                open_ports.push_back(port);
                bIs_up = true;
            }
        }
    }

    // If no ports were found open
    if (!bIs_up) {
        std::cerr << "[!] No open ports were found, is the host online?\n";
    }

    // Call the find services function
    if (bFind_service && !(open_ports.empty()))
    {
        std::cout << "\n[*] Starting service scanner...\n";
        
        std::cout << std::left;
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