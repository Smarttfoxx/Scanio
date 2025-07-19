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
#include <iostream>

inline void RenderBanner() {
    std::cout << "Hugin - Network Scanner 1.0\n";
}

inline void RenderHelp() {
    std::cout << "Usage: ./scanner [options]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -i,  --ip <address>          Target IP address or CIDR block\n";
    std::cout << "  -p,  --ports <range>         Ports to scan (e.g. 80,443 or 1-1000)\n";
    std::cout << "  -Tp, --top-ports <N>         Scan top N common ports\n";
    std::cout << "  -Ap, --all-ports             Scan all 65535 ports\n";
    std::cout << "  -d,  --delay <ms>            Delay (timeout) in milliseconds per port\n";
    std::cout << "  -Th, --threads <N>           Number of threads to use\n";
    std::cout << "  -Ts, --tcp-scan              Enable TCP Connect scan\n";
    std::cout << "  -Ar, --arp-scan              Enable ARP ping (requires interface)\n";
    std::cout << "       --interface <iface>     Specify interface for ARP\n";
    std::cout << "  -S,  --service               Enable service banner grabbing\n";
    std::cout << "  -U,  --udp                   Enable UDP probe scan\n";
    std::cout << "  -L,  --lua-script <file>     Run custom Lua script\n";
    std::cout << "  -h,  --help                  Show this help message\n";
}
