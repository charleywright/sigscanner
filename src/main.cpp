#include <filesystem>
#include "flags.h"
#include "signature.hpp"
#include "thread_pool.hpp"
#include "scanner.hpp"
#include "file_filter.hpp"

void print_help(const std::filesystem::path &binary)
{
  std::printf("Recursively scan all files for a given signature\n\n"
              "Usage: %s <signature> [path] [options]\n"
              "The signature should be an IDA-style pattern e.g. '?? A7 98 52 ?? 32 AD 72'\n"
              "If a path is not specified the current directory will be used\n\n"
              "Flags:\n"
              "--depth <int>          - How many levels of subdirectory should be scanned. 1 for example means scan the directory and the directories in it\n"
              "--no-recurse           - Only scan files in this directory\n"
              "-j <int>               - Number of threads to use for scanning\n"
              "--ext <extension>      - Filter by file extension. Can be specified multiple times. Should include the dot or empty for no extension: --ext '' --ext '.so'\n",
              binary.filename().c_str());
}

int main(int argc, char **argv)
{
  const flags::args args(argc, argv);
  const std::filesystem::path binary = argv[0];

  if (args.get<bool>("h") || args.get<bool>("help"))
  {
    print_help(binary);
    return 0;
  }

  const std::vector<std::string_view> &positional_args = args.positional();
  if (positional_args.empty())
  {
    std::fprintf(stderr, "Error: No signature specified\n");
    print_help(binary);
    return 1;
  }

  const signature sig(positional_args[0]);
  if (!sig.valid())
  {
    std::fprintf(stderr, "Error: Invalid signature\n");
    print_help(binary);
    return 1;
  }

  std::filesystem::path path = positional_args.size() > 1 ? positional_args[1] : std::filesystem::current_path();
  if (!std::filesystem::exists(path))
  {
    std::fprintf(stderr, "Error: Path does not exist\n");
    print_help(binary);
    return 1;
  }
  path = std::filesystem::canonical(path);

  thread_pool pool;
  pool.create(args.get<unsigned int>("j", 0));

  file_filter filter(args);

  scanner scanner(sig, pool, filter);
  if (args.get<int>("depth").has_value())
  {
    int depth = args.get<int>("depth").value();
    scanner.recursive_scan(path, depth);
    return 0;
  }
  if (args.get<bool>("no-recurse"))
  {
    scanner.scan(path);
    return 0;
  }
  scanner.recursive_scan(path);
}
