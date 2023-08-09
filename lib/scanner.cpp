#include "sigscanner/sigscanner.hpp"

sigscanner::scanner::scanner(const sigscanner::signature &signature, std::size_t thread_count)
{
  this->multi_scanner.add_signature(signature);
  this->multi_scanner.set_thread_count(thread_count);
}

void sigscanner::scanner::set_thread_count(std::size_t thread_count)
{
  this->multi_scanner.set_thread_count(thread_count);
}

std::vector<sigscanner::offset> sigscanner::scanner::scan(const sigscanner::byte *data, std::size_t len) const
{
  return this->multi_scanner.scan(data, len).begin()->second;
}

std::vector<sigscanner::offset> sigscanner::scanner::scan_file(const std::filesystem::path &path) const
{
  return this->multi_scanner.scan_file(path).begin()->second;
}

std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>
sigscanner::scanner::scan_directory(const std::filesystem::path &path, std::int64_t max_depth) const
{
  return this->multi_scanner.scan_directory(path, max_depth).begin()->second;
}
