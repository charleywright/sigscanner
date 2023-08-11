#include "sigscanner/sigscanner.hpp"
#include <fstream>
#include <algorithm>
#include <cassert>
#include <limits>

sigscanner::multi_scanner::multi_scanner(const sigscanner::signature &signature)
{
  this->add_signature(signature);
}

sigscanner::multi_scanner::multi_scanner(const std::vector<sigscanner::signature> &signatures)
{
  this->add_signatures(signatures);
}

void sigscanner::multi_scanner::add_signature(const sigscanner::signature &signature)
{
  this->signatures.push_back(signature);
}

void sigscanner::multi_scanner::add_signatures(const std::vector<sigscanner::signature> &sigs)
{
  this->signatures.insert(this->signatures.end(), sigs.begin(), sigs.end());
}

std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>>
sigscanner::multi_scanner::scan(const sigscanner::byte *data, std::size_t len, const scan_options &options) const
{
  std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> results;
  this->thread_pool.create(options.thread_count);
  for (const auto &signature: this->signatures)
  {
    this->thread_pool.add_task([&results, signature, data, len] {
        results.emplace(signature, signature.scan(data, len, 0));
    });
  }
  this->thread_pool.destroy();
  return results;
}

std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>>
sigscanner::multi_scanner::reverse_scan(const sigscanner::byte *data, std::size_t len, const sigscanner::scan_options &options) const
{
  std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> results;
  this->thread_pool.create(options.thread_count);
  for (const auto &signature: this->signatures)
  {
    this->thread_pool.add_task([&results, signature, data, len] {
        results.emplace(signature, signature.reverse_scan(data, len, 0));
    });
  }
  this->thread_pool.destroy();
  return results;
}

std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> sigscanner::multi_scanner::scan_file(const std::filesystem::path &path, const sigscanner::scan_options &options) const
{
  std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> results;
  for (const auto &signature: this->signatures)
  {
    results.emplace(signature, std::vector<sigscanner::offset>());
  }
  if (!std::filesystem::exists(path) || !std::filesystem::is_regular_file(path))
  {
    return results;
  }

  const std::size_t longest_sig = this->longest_sig_length();
  std::unordered_map<sigscanner::signature, std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>> file_results;
  std::mutex file_results_mutex;
  this->thread_pool.create(options.thread_count);
  this->scan_file_internal(path, options, longest_sig, file_results, file_results_mutex);
  this->thread_pool.destroy();

  for (auto &[signature, file]: file_results)
  {
    assert(file.size() == 1 && "File results should only have one entry");
    results[signature] = std::move(file.begin()->second);
  }

  return results;
}

std::unordered_map<sigscanner::signature, std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>>
sigscanner::multi_scanner::scan_directory(const std::filesystem::path &dir, const sigscanner::scan_options &options) const
{
  std::unordered_map<sigscanner::signature, std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>> results;
  for (const auto &signature: this->signatures)
  {
    results.emplace(signature, std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>());
  }
  if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir))
  {
    return results;
  }

  std::mutex results_mutex;
  std::size_t longest_sig = this->longest_sig_length();
  this->thread_pool.create(options.thread_count);

  typedef std::filesystem::recursive_directory_iterator recursive_directory_iterator;
  for (auto it = recursive_directory_iterator(dir); it != recursive_directory_iterator(); it++)
  {
    if (!options.check_depth(it.depth()))
    {
      it.disable_recursion_pending();
      continue;
    }
    if (!it->is_regular_file())
    {
      continue;
    }
    const std::filesystem::path &path = it->path();
    if(!options.check_extension(path) || !options.check_filename(path))
    {
      continue;
    }
    this->scan_file_internal(path, options, longest_sig, results, results_mutex);
  }

  this->thread_pool.destroy();

  return results;
}

/*
 * See https://stackoverflow.com/a/22986486/12282075
 * I kept getting sizes of 9223372036854775807 because tellg() doesn't do
 * what most people think it does
 */
std::int64_t get_file_size(std::fstream &file)
{
  file.ignore(std::numeric_limits<std::streamsize>::max());
  std::streamsize length = file.gcount();
  file.clear();
  file.seekg(0, std::ios_base::beg);
  return static_cast<std::int64_t>(length);
}

void sigscanner::multi_scanner::scan_file_internal(
        const std::filesystem::path &path, const sigscanner::scan_options &options, std::size_t longest_sig,
        std::unordered_map<sigscanner::signature, std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>> &results,
        std::mutex &result_mutex) const
{
  switch (options.threading)
  {
    case scan_options::threading_mode::PER_CHUNK:
    {
      std::fstream file(path, std::ios::in | std::ios::binary);
      file.unsetf(std::ios::skipws);
      const std::int64_t file_size = get_file_size(file);
      if (file_size == 0 || !options.check_file_size(file_size))
      {
        return;
      }
      const std::uint64_t scannable_chunk_size = SIGSCANNER_FILE_BLOCK_SIZE - longest_sig;
      const std::uint64_t chunk_count = (file_size / scannable_chunk_size) + 1;
      for (std::uint64_t i = 0; i < chunk_count; i++)
      {
        const std::uint64_t chunk_offset = i * scannable_chunk_size;
        const std::uint64_t chunk_size = std::min(SIGSCANNER_FILE_BLOCK_SIZE, file_size - chunk_offset);
        std::vector<sigscanner::byte> chunk(chunk_size);
        const std::fstream::pos_type pos = file.tellg();
        assert(pos == chunk_offset && "File at incorrect position");
        file.read(reinterpret_cast<char *>(chunk.data()), static_cast<std::streamsize>(chunk_size));
        const std::streamsize read = file.gcount();
        assert(read == chunk_size && "File read failed");
        file.seekg(-static_cast<std::streamsize>(longest_sig), std::ios::cur);
        this->thread_pool.add_task([&results, chunk = std::move(chunk), chunk_offset, &result_mutex, &path, this] {
            for (const auto &signature: this->signatures)
            {
              std::vector<sigscanner::offset> offsets = signature.scan(chunk.data(), chunk.size(), chunk_offset);
              if (!offsets.empty())
              {
                std::lock_guard<std::mutex> lock(result_mutex);
                std::vector<sigscanner::offset> &file_results = results[signature][path];
                file_results.insert(file_results.end(), offsets.begin(), offsets.end());
              }
            }
        });
      }
      file.close();
      break;
    }
    case scan_options::threading_mode::PER_FILE:
    {
      this->thread_pool.add_task([path, longest_sig, &result_mutex, &results, &options, this] {
          std::fstream file(path, std::ios::in | std::ios::binary);
          file.unsetf(std::ios::skipws);
          const std::int64_t file_size = get_file_size(file);
          if (file_size == 0 || !options.check_file_size(file_size))
          {
            return;
          }
          const std::uint64_t scannable_chunk_size = SIGSCANNER_FILE_BLOCK_SIZE - longest_sig;
          const std::uint64_t chunk_count = (file_size / scannable_chunk_size) + 1;
          std::vector<sigscanner::byte> chunk(SIGSCANNER_FILE_BLOCK_SIZE);
          for (std::uint64_t i = 0; i < chunk_count; i++)
          {
            const std::uint64_t chunk_offset = i * scannable_chunk_size;
            const std::uint64_t chunk_size = std::min(SIGSCANNER_FILE_BLOCK_SIZE, file_size - chunk_offset);
            std::fstream::pos_type pos = file.tellg();
            assert(pos == chunk_offset && "File at incorrect position");
            file.read(reinterpret_cast<char *>(chunk.data()), static_cast<std::streamsize>(chunk_size));
            assert(file.gcount() == chunk_size && "File read failed");
            file.seekg(-static_cast<std::streamsize>(longest_sig), std::ios::cur);
            for (const auto &signature: this->signatures)
            {
              std::vector<sigscanner::offset> offsets = signature.scan(chunk.data(), chunk.size(), chunk_offset);
              if (!offsets.empty())
              {
                std::lock_guard<std::mutex> lock(result_mutex);
                std::vector<sigscanner::offset> &file_results = results[signature][path];
                file_results.insert(file_results.end(), offsets.begin(), offsets.end());
              }
            }
          }
      });
      break;
    }
  }
}

std::size_t sigscanner::multi_scanner::longest_sig_length() const
{
  return std::max_element(this->signatures.begin(), this->signatures.end(), [](const sigscanner::signature &a, const sigscanner::signature &b) {
      return a.size() < b.size();
  })->size();
}
