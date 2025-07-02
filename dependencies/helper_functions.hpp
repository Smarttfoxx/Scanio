#pragma once
#include <sstream>

bool isStringInteger(const std::string& str) {
    std::istringstream iss(str);
    int num;
    char c;

    if (!(iss >> num)) {
        std::cout << "[!] Invalid port value. Only integers are accepted.\n";
        return false;
    }

    if (iss >> c) {
        std::cout << "[!] Invalid port value. Only integers are accepted.\n";
        return false;
    }

    return true;
}