#include "sigscanner/sigscanner.hpp"

sigscanner::scanner::scanner(const sigscanner::signature &signature)
{
  this->multi_scanner.add_signature(signature);
}

std::vector<sigscanner::offset> sigscanner::scanner::scan(const sigscanner::byte *data, std::size_t len, const sigscanner::scan_options &options) const
{
  return this->multi_scanner.scan(data, len, options).begin()->second;
}

std::vector<sigscanner::offset> sigscanner::scanner::reverse_scan(const sigscanner::byte *data, std::size_t len, const sigscanner::scan_options &options) const
{
  return this->multi_scanner.reverse_scan(data, len, options).begin()->second;
}

std::vector<sigscanner::offset> sigscanner::scanner::scan_file(const std::filesystem::path &path, const sigscanner::scan_options &options) const
{
  return this->multi_scanner.scan_file(path, options).begin()->second;
}

std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>
sigscanner::scanner::scan_directory(const std::filesystem::path &path, const sigscanner::scan_options &options) const
{
  return this->multi_scanner.scan_directory(path, options).begin()->second;
}
