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

#include "cli/arg_parser.h"
#include "engine/scan_engine.h"
#include "utils/helper_functions.h"
#include "utils/log_system.h"
#include "visuals/visuals.h"
#include "engine/scan_engine.h"

int main(int argc, char* argv[]) {
    RenderBanner();
    ParsedArgs args = ParseArguments(argc, argv);

    if (args.showHelp || args.hosts.empty()) {
        RenderHelp();
        return 0;
    }

    std::vector<HostInstance> validHosts;
    for (auto& host : args.hosts) {
        if (!IsValidIP(host.ipValue)) continue;
        bool up = args.enableARPScan ? IsHostUpARP(host.ipValue, args.interface)
                                     : IsHostUpICMP(host.ipValue);
        if (up) validHosts.push_back(host);
    }

    ThreadPool pool(args.threadCount);

    for (auto& host : validHosts) {
        pool.enqueue([&, host]() {
            logsys.NewEvent("Scanning", host.ipValue);
            std::vector<int> openPorts;

            if (!args.enableTCPScan) {
                openPorts = PortScanSyn(host.ipValue, args.ports, args.portTimeout);
            }

            for (int port : openPorts) {
                std::string banner;
                if (args.enableFindService) {
                    banner = ServiceBannerGrabber(host.ipValue, port, args.serviceTimeout);
                }
                std::string udp_reply;
                if (args.enableUDP) {
                    std::unordered_set<int> portSet(args.ports.begin(), args.ports.end());
                    auto udp_payloads = ParseSelectedUDPProbes("nmap-payloads.txt", portSet);
                    if (udp_payloads.count(port)) {
                        udp_reply = SendUDPProbe(host.ipValue, port, udp_payloads[port], 5);
                    }
                }
                std::string lua_result;
                if (args.enableLua && !args.luaScripts.empty()) {
                    lua_result = RunLuaScript(args.luaScripts[0], host.ipValue, port);
                }

                logsys.Info("Open Port:", port);
                if (!banner.empty()) logsys.CommonText("  Service:", banner);
                if (!udp_reply.empty()) logsys.CommonText("  UDP Reply:", udp_reply);
                if (!lua_result.empty()) logsys.CommonText("  Lua Output:", lua_result);
            }
        });
    }

    return 0;
}