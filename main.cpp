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

int main(int argc, char* argv[])
{
    int timeout_sec = 3;
    int service_timeout_sec = 3;
    int port_amount = 0;

    bool bFind_service = false;
    bool bIs_up = false;
    bool bTCP_scan = false;

    std::string s_ip;
    std::string s_port_amount;

    std::vector<int> open_ports;
    std::vector<int> ports;
    std::vector<int> all_tcp_ports;

    std::mutex result_mutex;

    int thread_amount = 100;

    std::atomic<int> services_scanned{0};
    std::atomic<int> ports_scanned_count{0};

    int total_ports;

    call_banner();

    // Check if arguments were passed
    for (int i = 1; i < argc; ++i) {
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

                    for (int i = start; i <= end; ++i) {
                        ports.push_back(i);
                    }

                }
            } else {
                if (!isStringInteger(buffer)) return 1;
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
            for (int i = 1; i <= 65535; ++i) {
                all_tcp_ports.push_back(i);
            }
            ports = all_tcp_ports;

        // Performs TCP scan
        } else if (arg == "-Ts" || arg == "--tcp-scan") {
            bTCP_scan = true;

        // Set the amount of threads to be used
        } else if ((arg == "-Th" || arg == "--threads") && i + 1 < argc) {
            thread_amount = std::stoi(argv[++i]);

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
    total_ports = ports.size();

    ThreadPool pool(thread_amount);
    auto start_time = std::chrono::steady_clock::now();
    std::atomic<bool> bProgress_status{false};

    std::thread port_progress_thread([&]() {
        std::vector<float> durations;
        int last_count = 0;
        auto last_time = std::chrono::steady_clock::now();

        while (!bProgress_status) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            int current = ports_scanned_count.load();
            int delta = current - last_count;
            auto now = std::chrono::steady_clock::now();
            float seconds_elapsed = std::chrono::duration<float>(now - last_time).count();

            if (delta > 0 && seconds_elapsed > 0) {
                float rate = delta / seconds_elapsed;
                float remaining = (ports.size() - current) / rate;
                float progress = (current * 100.0f) / ports.size();
                std::cout << "\r[!] Port scan progress: " << std::fixed << std::setprecision(1) << progress
                          << "%  |  ETA: " << (int)remaining << "s" << std::flush;
            }

            last_time = now;
            last_count = current;
        }

        std::cout << "\r[!] Port scan progress: 100.0%  |  ETA: 0s" << std::endl;
    });

    // Start port scanner
    std::cout << "[*] Using a total of " << thread_amount << " threads for the scan.\n\n";
    std::cout << "[*] Scanning for open ports...\n";

    for (int port : ports) {
        pool.enqueue([&, port]() {
            bool bIs_open = false;

            if (bTCP_scan)
                bIs_open = IsPortOpenTcp(s_ip, port, timeout_sec);
            else
                bIs_open = IsPortOpenSyn(s_ip, port, timeout_sec);

            if (bIs_open) {
                std::lock_guard<std::mutex> lock(result_mutex);
                open_ports.push_back(port);
                bIs_up = true;
            }
            ++ports_scanned_count;
        });
    }

    while (ports_scanned_count.load() < ports.size())
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

    bProgress_status = true;
    port_progress_thread.join();

    // If no ports were found open
    if (!bIs_up) {
        std::cerr << "[!] No open ports were found, is the host online?\n";
    }

    // Call the find services function
    if (bFind_service && !(open_ports.empty())) {
        int total_services = open_ports.size();
        std::cout << "\n[*] Starting service scanner...\n";
        
        std::cout << std::left;
        std::cout << std::setw(12) << "PORT" << std::setw(8) << "STATE" << "SERVICE/VERSION\n";

        for (int port : open_ports)
        {
            // If the service is FTP, increase wait time to grab header
            if (std::find(common_ftp.begin(), common_ftp.end(), port) != common_ftp.end())
                service_timeout_sec = 12;
 
            pool.enqueue([&, port]() {
                std::string s_service_banner;
                bool bIs_open = true;
                s_service_banner = ServiceBannerGrabber(s_ip, port, service_timeout_sec);

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

        while (services_scanned.load() < total_services)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();
    std::cout << "\n[*] Scan completed in " << elapsed << " seconds.\n";
    std::cout << "[*] A total of " << total_ports << " ports were scanned.\n";

    return 0;
}