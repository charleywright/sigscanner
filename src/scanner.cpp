#include "scanner.hpp"
#include <fstream>
#include <iostream>

scanner::scanner(const signature &sig, thread_pool &pool, const file_filter &filter) : sig(sig), pool(pool), filter(filter)
{

}

void scanner::scan(const std::filesystem::path &path)
{
  return this->recursive_scan(path, 0);
}

void scanner::recursive_scan(const std::filesystem::path &path, int depth)
{
  for (auto i = std::filesystem::recursive_directory_iterator(path); i != std::filesystem::recursive_directory_iterator(); i++)
  {
    if (i.depth() >= depth && depth != -1)
    {
      i.disable_recursion_pending();
      continue;
    }
    if (i->is_regular_file())
    {
      if (!this->filter.check(i->path()))
      {
        continue;
      }
      std::filesystem::path p = i->path();
      this->pool.add_task([p, this]() { this->scan_file(p); });
    }
  }
}

void scanner::scan_file(const std::filesystem::path &path)
{
  const std::streamsize BLOCK_SIZE = 1'048'576; // 1MB
  std::ifstream file(path, std::ios::binary);
  file.unsetf(std::ios::skipws);
  std::vector<std::uint8_t> buffer(BLOCK_SIZE);
  std::uint64_t chunk_offset_in_file = 0;
  std::vector<std::uint64_t> matches;

  while (true)
  {
    file.read(reinterpret_cast<char *>(buffer.data()), BLOCK_SIZE);
    std::uint64_t actual_block_size = file.gcount();
    if (actual_block_size < this->sig.length)
    {
      break;
    }
    for (std::uint64_t i = 0; i < actual_block_size - this->sig.length + 1; i++)
    {
      if (this->sig.compare(buffer, i))
      {
        matches.push_back(chunk_offset_in_file + i);
      }
    }
    if (actual_block_size < BLOCK_SIZE)
    {
      break;
    }
    chunk_offset_in_file += actual_block_size - this->sig.length + 1;
    file.seekg(static_cast<std::fstream::off_type>(chunk_offset_in_file));
  }

  if (!matches.empty())
  {
    std::lock_guard<std::mutex> lock(this->stdio_mutex);
    std::cout << path << "\n";
    for (const auto &match: matches)
    {
      std::cout << "  0x" << std::hex << match << std::dec << "\n";
    }
    std::cout << std::endl;
  }
}
