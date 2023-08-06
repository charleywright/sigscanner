#pragma once

#include "signature.hpp"
#include "thread_pool.hpp"
#include <filesystem>
#include <mutex>

class scanner
{
public:
    scanner(const signature &sig, thread_pool &pool);

    void scan(const std::filesystem::path &path);
    void recursive_scan(const std::filesystem::path &path, int depth = -1);

private:
    thread_pool &pool;
    const signature &sig;

    std::mutex stdio_mutex;

    void scan_file(const std::filesystem::path &path);
};
