#include "scanner.hpp"
#include <fstream>
#include <cstdio>

scanner::scanner(const signature &sig, thread_pool &pool) : pool(pool), sig(sig)
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

  std::vector<std::streamsize> matches;

  while (true)
  {
    file.read(reinterpret_cast<char *>(buffer.data()), BLOCK_SIZE);
    std::streamsize actual_block_size = file.gcount();
    for (std::streamsize i = 0; i < actual_block_size - this->sig.length + 1; i++)
    {
      if (this->sig.compare(buffer, i))
      {
        matches.push_back(file.tellg() + i);
      }
    }
    if (actual_block_size < BLOCK_SIZE)
    {
      break;
    }
    file.seekg(-this->sig.length + 1, std::ios::cur);
  }

  if (!matches.empty())
  {
    std::lock_guard<std::mutex> lock(this->stdio_mutex);
    std::printf("%s\n", path.c_str());
    for (const auto &match: matches)
    {
      std::printf("  0x%lx\n", match);
    }
  }
}
