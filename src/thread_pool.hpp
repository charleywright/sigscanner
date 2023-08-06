#pragma once

#include <functional>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>

class thread_pool
{
public:
    ~thread_pool();

    void create(unsigned int count = 0);
    void destroy();

    void add_task(std::function<void()> &&task);

private:
    void thread_loop();
    std::vector<std::thread> threads;
    std::atomic<bool> active = false;

    std::vector<std::function<void()>> tasks;
    std::mutex tasks_mutex;
};
