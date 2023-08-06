#pragma once

#include "flags.h"
#include <filesystem>

class file_filter
{
public:
    file_filter(const flags::args &args);

    bool check(const std::filesystem::path &path) const;

private:
    std::vector<std::string> extensions;
    bool check_extension(const std::filesystem::path &path) const;
};
