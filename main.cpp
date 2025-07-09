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
#include "interfaces/banner.hpp"
#include "engine/scan_engine.hpp"
#include "dependencies/helper_functions.hpp"

int main(int argc, char* argv[]) {

    int timeout_sec = 3;
    int service_timeout_sec = 3;
    int port_amount = 0;
    int thread_amount = 100;
    int total_ports;

    bool bFind_service = false;
    bool bTCP_scan = false;
    bool bIs_up = false;

    std::string s_port_amount;

    std::vector<std::string> s_ip;
    //thread_local std::vector<int> open_ports;
    std::vector<IP_Instance> ip_instances;
    std::vector<int> ports;
    std::vector<int> all_tcp_ports;

    std::mutex result_mutex;

    std::atomic<int> services_scanned{0};
    std::atomic<int> ports_scanned_count{0};

    render_banner();

    // Check and process program arguments
    for (int i = 1; i < argc; ++i) {

        std::string arg = argv[i];

        // Prepare the argument that handles IPs.
        if ((arg == "-i" || arg == "--ip") && i + 1 < argc) {

            std::string buffer = argv[++i];
            std::stringstream ss(buffer);
            std::string token;

            if (buffer.find(',') != std::string::npos) {
                while (std::getline(ss, token, ',')) {
                    ip_instances.emplace_back(IP_Instance{token});
                }
            } else
                ip_instances.emplace_back(IP_Instance{buffer});

            // Check if the "s_ip" variable is empty
            if (buffer.empty()) {
                std::cerr << "[!] No IP provided.\n";
                std::cerr << "[*] Default usage: " << argv[0] << " -i <IP> -p <PORT(s)>\n";
                return 1;
            }

        // Prepare the argument that handles ports.
        } else if ((arg == "-p" || arg == "--ports") && i + 1 < argc) {
            std::string buffer = argv[++i];
            std::stringstream ss(buffer);
            std::string token;

            if (buffer.find(',') != std::string::npos) {
                while (std::getline(ss, token, ',')) {
                    // Check if value passed is not an integer.
                    // If no integer, break the application.
                    if (!isStringInteger(token))
                        return 1;

                    ports.push_back(std::stoi(token));
                }
            } else if (buffer.find('-') != std::string::npos) {
                while (std::getline(ss, token, '-')) {
                    int start = std::stoi(token);
                    
                    std::getline(ss, token, '-');
                    int end = std::stoi(token);

                    for (int i = start; i <= end; ++i)
                        ports.push_back(i);

                }
            } else {
                if (!isStringInteger(buffer))
                    return 1;

                ports.push_back(std::stoi(buffer));
            }
        
        // Prepare the argument that handles timeouts.
        // All the timeout values are defined in seconds.
        } else if ((arg == "-d" || arg == "--delay") && i + 1 < argc) {
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
            for (int i = 1; i <= 65535; ++i)
                all_tcp_ports.push_back(i);

            ports = all_tcp_ports;

        // Performs TCP scan
        } else if (arg == "-Ts" || arg == "--tcp-scan") {
            bTCP_scan = true;

        // Set the amount of threads to be used
        } else if ((arg == "-Th" || arg == "--threads") && i + 1 < argc) {
            thread_amount = std::stoi(argv[++i]);

        // If no valid argument was passed, break.
        } else {
            std::cerr << "[!] Unknown argument was passed.\n";
            std::cerr << "[*] Default usage: " << argv[0] << " -i <IP> -p <PORT(s)>\n";
            return 1;
        }
    }

    for (const IP_Instance& ip_obj : ip_instances) {
        // Verifies if the value passed to "s_ip" is a valid IP
        if (!IsValidIP(ip_obj.ip_value)) {
            std::cerr << "Invalid address was provided.\n";
            return 1;
        }

        // Check if host is up via ICMP.
        if (IsHostUpICMP(ip_obj.ip_value))
            std::cout << "[*] The host " << ip_obj.ip_value << " is up.\n"; 
        else
            std::cerr << "[!] The host is down or blocking ICMP. Continuing anyways...\n";
    }

    // If the "ports" variable is empty, use common 1000 TCP ports
    if (ports.empty())
        ports = common_ports_thousand;

    // Prepare the thread pool system
    ThreadPool pool(thread_amount);
    auto start_time = std::chrono::steady_clock::now();
    std::atomic<bool> bProgress_status{false};

    // We now call the thread to verify the scan status
    /*std::thread port_progress_thread([&]() {
        std::vector<float> durations;
        int last_count = 0;
        auto last_time = std::chrono::steady_clock::now();

        while (!bProgress_status) {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            int current = ports_scanned_count.load();
            int delta = current - last_count;
            auto now = std::chrono::steady_clock::now();
            float seconds_elapsed = std::chrono::duration<float>(now - last_time).count();

            if (delta > 0 && seconds_elapsed > 0) {
                float rate = delta / seconds_elapsed;
                float remaining = (ports.size() - current) / rate;
                float progress = (current * 100.0f) / ports.size();
                std::cout << "\r[!] Port scan progress: " << std::fixed << std::setprecision(1) << progress
                          << "%  |  ETA: " << (int)remaining << "s" << std::flush << "\n\n";
            }

            last_time = now;
            last_count = current;
        }
    });*/

    // Start port scanner
    std::cout << "[*] Using a total of " << thread_amount << " threads for the scan.\n";

    for (IP_Instance& ip_obj : ip_instances) {
        std::string ip = ip_obj.ip_value;
        auto open_ports_ptr = &ip_obj.open_ports;

        std::cout << "\n[*] Scanning for open ports on host " << ip_obj.ip_value << "\n";

        for (int port : ports) {
            pool.enqueue([=, &result_mutex, &ports_scanned_count, &bIs_up]() {
                bool bIs_open = false;

                if (bTCP_scan)
                    bIs_open = IsPortOpenTcp(ip_obj.ip_value, port, timeout_sec);
                else
                    bIs_open = IsPortOpenSyn(ip_obj.ip_value, port, timeout_sec);

                if (bIs_open) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    open_ports_ptr->push_back(port);
                    bIs_up = true;
                }
                ++ports_scanned_count;
            });
        }

        while (ports_scanned_count.load() < ports.size())
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

        if (ports_scanned_count.load() >= ports.size()) {
            ports_scanned_count = 0;
        }

        // If no ports were found open
        if (!bIs_up)
            std::cerr << "[!] No open ports were found, is the host online?\n";

        // Verify if we should call the find services function
        if (bFind_service && !(ip_obj.open_ports.empty())) {
            std::cout << "\n[*] Starting service scanner on host " << ip_obj.ip_value << "\n\n";
            
            std::cout << std::left;
            std::cout << std::setw(12) << "PORT" << std::setw(8) << "STATE" << "SERVICE/VERSION\n";

            for (int port : ip_obj.open_ports) {
                // If the service is FTP, increase wait time to grab header
                if (FindIn(common_ftp_ports, port))
                    service_timeout_sec = 12;
    
                pool.enqueue([&, port]() {
                    std::string s_service_banner;
                    bool bIs_open = true;
                    
                    s_service_banner = ServiceBannerGrabber(ip_obj.ip_value, port, service_timeout_sec);

                    if (s_service_banner.empty())
                        bIs_open = false;

                    if (bIs_open) {
                        std::lock_guard<std::mutex> lock(result_mutex);
                        std::cout << std::setw(12) << (std::to_string(port) + "/tcp") 
                                << std::setw(8) << "open" 
                                << (s_service_banner.empty() ? "No service found." : s_service_banner) 
                                << "\n";
                    }
                    services_scanned++;
                });
            }

            while (services_scanned.load() < ip_obj.open_ports.size())
                std::this_thread::sleep_for(std::chrono::milliseconds(500));

            if (services_scanned.load() >= ip_obj.open_ports.size())
                services_scanned = 0;
        }
    }

    bProgress_status = true;
    //port_progress_thread.join();

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
    total_ports = ports.size();

    std::cout << "\n[*] Scan completed in " << elapsed << " seconds.\n";
    std::cout << "[*] A total of " << total_ports << " ports were scanned.\n";

    return 0;
}