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
#include <vector>

// Custom libraries
#include "../dependencies/helper_functions.hpp"

std::vector<int> common_ports_thousand = ReadFile("/usr/share/hugin/wordlists/hugin-ports-top1000.txt");
std::vector<int> common_web_ports = ReadFile("/usr/share/hugin/wordlists/hugin-ports-topweb.txt");
std::vector<int> common_ftp_ports = ReadFile("/usr/share/hugin/wordlists/hugin-ports-topftp.txt");
std::vector<int> common_ldap_ports = { 389, 363, 3268, 3269 };