#include "file_filter.hpp"
#include <algorithm>

file_filter::file_filter(const flags::args &args)
{
  const std::vector<std::string_view> exts = args.values("ext");
  this->extensions = std::vector<std::string>(exts.begin(), exts.end());
}

bool file_filter::check(const std::filesystem::path &path) const
{
  return this->check_extension(path);
}

bool file_filter::check_extension(const std::filesystem::path &path) const
{
  if (this->extensions.empty())
  {
    return true;
  }
  return std::any_of(this->extensions.begin(), this->extensions.end(), [&path](const std::string &ext) {
      return path.extension() == ext;
  });
}
