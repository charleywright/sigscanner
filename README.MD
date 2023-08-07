# SigScanner

A simple CLI signature scanner written in C++. It is designed to be easy to use and fast enough, however could certainly
be improved. Tested on Linux and Windows, however I would guess unicode characters in path names wouldn't be supported.

## Usage

```
Recursively scan all files for a given signature

Usage: sig-scanner <signature> [path] [options]
The signature should be an IDA-style pattern e.g. '?? A7 98 52 ?? 32 AD 72'
If a path is not specified the current directory will be used

Flags:
--depth <int>          - How many levels of subdirectory should be scanned. 1 for example means scan the directory and the directories in it
--no-recurse           - Only scan files in this directory
-j <int>               - Number of threads to use for scanning
--ext <extension>      - Filter by file extension. Can be specified 0 or more times. Should include the dot or empty for no extension: --ext '' --ext '.so'
```

## Building

This project uses cmake, so create a build directory, configure, then build

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j 4
```

The only dependency is [sailormoon/flags](https://github.com/sailormoon/flags) however due to a bug we keep our own local version. This will be removed once the bug is fixed (once I get around to submitting a pull request).
