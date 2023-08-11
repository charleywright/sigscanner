#include "flags.h"
#include "sigscanner/sigscanner.hpp"
#include <iostream>
#include <filesystem>
#include <string>

static std::string binary_name;

void print_help()
{
  std::cout << "Recursively scan all files for a given signature\n\n"
               "Usage: " << binary_name <<
            " <signature> [path] [options]\n"
            "The signature should be an IDA-style pattern e.g. '?? A7 98 52 ?? 32 AD 72'\n"
            "If a path is not specified the current directory will be used\n\n"
            "Flags:\n"
            "--depth <int>          - How many levels of subdirectory should be scanned. 1 for example means scan the directory and the directories in it\n"
            "--no-recurse           - Only scan files in this directory\n"
            "-j <int>               - Number of threads to use for scanning\n"
            "--ext <extension>      - Filter by file extension. Can be specified 0 or more times. Should include the dot or empty for no extension: --ext '' --ext '.so'"
            << std::endl;
}

int main(int argc, char **argv)
{
  binary_name = std::filesystem::path(argv[0]).filename().string();
  const flags::args args(argc, argv);

  if (args.get<bool>("h") || args.get<bool>("help"))
  {
    print_help();
    return 0;
  }

  const std::vector<std::string_view> &positional_args = args.positional();
  if (positional_args.empty())
  {
    std::cerr << "Error: No signature specified" << std::endl;
    print_help();
    return 1;
  }

  const sigscanner::signature sig(positional_args[0]);
  if (sig.size() == 0)
  {
    std::cerr << "Error: Invalid signature" << std::endl;
    print_help();
    return 1;
  }

  std::filesystem::path path = positional_args.size() > 1 ? positional_args[1] : std::filesystem::current_path();
  if (!std::filesystem::exists(path))
  {
    std::cerr << "Error: Path does not exist" << std::endl;
    print_help();
    return 1;
  }
  path = std::filesystem::canonical(path);

  std::size_t thread_count = args.get("j", 1);
  sigscanner::scanner scanner(sig);
  sigscanner::scan_options scan_options;
  scan_options.set_thread_count(thread_count);
  scan_options.add_extensions(args.values("ext"));

  if (std::filesystem::is_directory(path))
  {
    int depth = args.get("depth", -1);
    if (args.get<bool>("no-recurse"))
    {
      depth = 0;
    }
    scan_options.set_max_depth(depth);
    const auto results = scanner.scan_directory(path, scan_options);
    for (const auto &[file, file_results]: results)
    {
      std::cout << file << "\n";
      for (const auto &offset: file_results)
      {
        std::cout << "  0x" << std::hex << offset << "\n";
      }
    }
    std::cout << std::endl;
  } else if (std::filesystem::is_regular_file(path))
  {
    const auto results = scanner.scan_file(path, scan_options);
    for (const auto &offset: results)
    {
      std::cout << "0x" << std::hex << offset << "\n";
    }
    std::cout << std::endl;
  } else
  {
    std::cerr << "File of invalid type specified" << std::endl;
    return 1;
  }
}