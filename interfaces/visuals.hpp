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

// C++ libraries
#include <iostream>

// Custom libraries
#include "../dependencies/helper_functions.hpp"

void RenderBanner() {
    logsys.CommonText("Hugin - Network Scanner 1.0");
}

void RenderHelp() {
    logsys.CommonText("Usage: hugin -i <IP> -p <PORT(s)> <options>");
    logsys.CommonText("");
    logsys.CommonText("Required arguments:");
    logsys.CommonText("  -i,  --ip <IP>           Target IP address or addresses (comma-separated)");
    logsys.CommonText("  -p,  --ports <PORT(s)>   Ports to scan (e.g., 80,443 or 1-100)");

    logsys.CommonText("");
    logsys.CommonText("Optional arguments:");
    logsys.CommonText("  -d,  --delay <seconds>   Set timeout delay per port (default: 1)");
    logsys.CommonText("  -S,  --service           Enable service banner grabbing");
    logsys.CommonText("  -Tp, --top-ports <N>     Scan top N common ports (e.g., 100)");
    logsys.CommonText("  -Ap, --all-ports         Scan all 65535 TCP ports");
    logsys.CommonText("  -Ts, --tcp-scan          Use TCP connect scan instead of SYN scan");
    logsys.CommonText("  -Th, --threads <N>       Set number of threads to use (default: 100)");
    logsys.CommonText("  -h,  --help              Display this help message");

    logsys.CommonText("");
    logsys.CommonText("Examples:");
    logsys.CommonText("  hugin -i 192.168.1.1 -p 22,80,443 -S");
    logsys.CommonText("  hugin -i 192.168.1.1,192.168.1.2 -Tp 100 -Ts");
    logsys.CommonText("  hugin -i 10.0.0.5 -Ap -d 2 -Th 200");
}
