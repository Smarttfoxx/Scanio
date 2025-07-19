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
#include <vector>
#include <string>
#include "../engine/scan_engine.h"

struct ParsedArgs {
    std::vector<HostInstance> hosts;
    std::vector<int> ports;
    std::vector<std::string> luaScripts;
    std::string interface;
    int threadCount = 100;
    int portTimeout = 1;
    int serviceTimeout = 1;
    bool enableTCPScan = false;
    bool enableARPScan = false;
    bool enableFindService = false;
    bool enableLua = false;
    bool enableUDP = false;
    bool showHelp = false;
};

ParsedArgs ParseArguments(int argc, char* argv[]);
