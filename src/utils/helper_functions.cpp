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

#include "helper_functions.h"
#include "../utils/log_system.h"

ThreadSleep ts;

/**
 * @brief Checks if a given string is a valid integer.
 * @param str The input string.
 * @return True if the string is a valid integer, false otherwise.
 */
bool isInteger(const std::string& str) {
    std::istringstream iss(str);
    int num;
    char c;

    if (!(iss >> num)) {
        logsys.Warning("Invalid port value. Only integers are accepted.");
        return false;
    }

    if (iss >> c) {
        logsys.Warning("Invalid port value. Only integers are accepted.");
        return false;
    }

    return true;
}

/**
 * @brief Searches for a value in a vector.
 * @param list Vector of integers.
 * @param buf Integer to search for.
 * @return True if found, false otherwise.
 */
bool FindIn(std::vector<int>& list, int buf) {

    if (std::find(list.begin(), list.end(), buf) == list.end())
        return false;
    
    return true;
}

/**
 * @brief Reads a file line-by-line and extracts integers from it.
 * @param filename Path to the file.
 * @return Vector of integers read from the file.
 */
std::vector<int> ReadFile(const std::string& filename) {
    std::vector<int> output;
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()){
        logsys.Error("Could not open file.");
        return output;
    }

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        int n;

        while (ss >> n) {
            output.push_back(n);
        }
    }

    return output;
}