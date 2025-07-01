// C++ libraries
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <vector>

// Personal libraries
#include "interfaces/banner.hpp"
#include "engine/scan_engine.hpp"
#include "engine/default_ports.hpp"

int main(int argc, char* argv[])
{
    int timeout_sec = 1;
    int service_timeout_sec = 15;
    int max_banner_width = 50;

    bool show_only_open_port = false;
    bool show_closed_filtered = false;
    bool find_service = false;

    std::string ip;
    std::string banner;

    std::vector<int> open_ports;
    std::vector<int> ports;

    // Check if arguments were passed
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if ((arg == "-i" || arg == "--ip") && i + 1 < argc)
        {
            ip = argv[++i];

        } else if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            std::stringstream ss(argv[++i]);
            std::string token;

            while (std::getline(ss, token, ','))
            {
                ports.push_back(std::stoi(token));
            }

        } else if ((arg == "-t" || arg == "--timeout") && i + 1 < argc) {
            timeout_sec = std::stoi(argv[++i]);

        } else if (arg == "--open") {
            show_only_open_port = true;

        } else if (arg == "--closed") {
            show_closed_filtered = true;

        } else if (arg == "-S" || arg == "--service") {
            find_service = true;
        }
    }

    // If the ip variable is empty
    if (ip.empty())
    {
        call_banner();
        std::cerr << "Usage: " << argv[0] << " -i <IP> -p <PORT(S)> -t <TIMEOUT> \n";
        return 1;
    }

    call_banner();

    // If the port variable is empty, use common 100 TCP ports
    if (ports.empty()) ports = common_ports_hundred;

    // Start port scanner
    std::cout << "[*] Scanning for open ports...\n";
    for (int port : ports)
    {
        if (is_port_open(ip, port, timeout_sec))
        {
            std::cout << "[+] Found open port " << port << "/tcp on host " << ip << "\n";
            open_ports.push_back(port);
        }

        if (show_closed_filtered) 
        {
            std::cerr << "Port " << port << " is CLOSED or FILTERED\n";
        }
    }

    // Call the find services function
    if (find_service && !(open_ports.empty()))
    {
        std::cout << "\n[*] Starting service scanner...\n";
        
        std::cout << std::left;
        std::cout << std::setw(12) << "PORT" << std::setw(8) << "STATE" << "SERVICE/VERSION\n";

        for (int port : open_ports)
        {
            banner = banner_grabber(ip, port, service_timeout_sec);
            while (!banner.empty() && (banner.back() == '\n' || banner.back() == '\r')) banner.pop_back();
            std::cout << std::setw(12) << (std::to_string(port) + "/tcp") << std::setw(8) << "open" << (banner.empty() ? "No service found" : banner) << "\n";
        }
    }

    return 0;
}