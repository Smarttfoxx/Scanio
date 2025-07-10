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
#include <sstream>
#include <mutex>
#include <condition_variable>
#include <string>
#include <algorithm>

// Custom libraries
#include "../dependencies/log_system.h"

struct ThreadSleep {
    void SleepMilliseconds(int value) {
        return std::this_thread::sleep_for(std::chrono::milliseconds(value));
    }
};
ThreadSleep ts;

class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop(false) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }

                    task();
                }
            });
        }
    }

    void enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.push(std::move(task));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread &worker : workers) worker.join();
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

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

bool FindIn(std::vector<int>& list, int buf) {

    if (std::find(list.begin(), list.end(), buf) == list.end())
        return false;
    
    return true;
}