#pragma once
#include <sstream>
#include <mutex>
#include <condition_variable>

class ThreadLimiter {
    std::mutex mtx;
    std::condition_variable cv;
    int max_threads;
    int active_threads = 0;

public:
    ThreadLimiter(int max) : max_threads(max) {}

    void acquire() {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]() { return active_threads < max_threads; });
        ++active_threads;
    }

    void release() {
        std::unique_lock<std::mutex> lock(mtx);
        --active_threads;
        cv.notify_one();
    }
};

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