#include <iostream>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fcntl.h>
#include <chrono>
#include <thread>

std::string banner_grabber(const std::string& ip, int port, int timeout_sec) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return "";

    struct timeval timeout{};
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sockfd);
        return "";
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

        auto elapsed = std::chrono::steady_clock::now() - start;
        
        if (elapsed > std::chrono::seconds(timeout_sec)) break;

        if (bytes == 0 || (bytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN)) break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    close(sockfd);
    return !banner.empty() ? banner : "";
}

bool is_port_open(const std::string& ip, int port, int timeout_sec) {
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
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int result = connect(sockfd, (sockaddr*)&addr, sizeof(addr));
    close(sockfd);

    return result == 0;
}

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
    std::vector<int> common_ports_hundred = { 
        20, 21, 22, 23, 25, 
        53, 67, 68, 69, 80, 
        110, 111, 119, 123, 
        135, 137, 138, 139, 
        143, 161, 162, 179, 
        389, 443, 445, 465, 
        514, 515, 587, 636, 
        993, 995, 1025, 1080, 
        1194, 1433, 1434, 1521, 
        1723, 2049, 2082, 2083, 
        2095, 2096, 2222, 2375, 
        2376, 2483, 2484, 3128, 
        3260, 3306, 3389, 3690, 
        4333, 4444, 4567, 4657, 
        5000, 5060, 5061, 5432, 
        5500, 5672, 5900, 5984, 
        5985, 5986, 6000, 6001, 
        6002, 6379, 6666, 6667, 
        7000, 7070, 7100, 7199, 
        7443, 7777, 8000, 8008, 
        8080, 8081, 8086, 8089, 
        8443, 8888, 9000, 9001, 
        9042, 9090, 9200, 9300, 
        9418, 9999, 10000, 11211, 
        27017, 27018, 27019, 50070, 50075 
    };

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
        std::cerr << "Usage: " << argv[0] << " -i <IP> -p <PORT(S)> -t <TIMEOUT> \n";
        return 1;
    }

    // If the port variable is empty, use common 100 TCP ports
    if (ports.empty()) ports = common_ports_hundred;

    std::cout << "#### Port Scanner v1.0 ####\n";

    // Start port scanner
    for (int port : ports)
    {
        if (is_port_open(ip, port, timeout_sec))
        {
            std::cout << "Found open port " << port << "/tcp on host " << ip << "\n";
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
        std::cout << "\n[*] Starting service scan...\n";
        
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