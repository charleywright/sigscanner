cmake_minimum_required(VERSION 3.6)
project(sigscanner)
include(FetchContent)
set(CMAKE_CXX_STANDARD 17)

set(EXEC_TARGET sig-scanner)

add_executable(${EXEC_TARGET}
        src/main.cpp
        src/signature.cpp
        src/thread_pool.cpp
        src/scanner.cpp
        src/file_filter.cpp
)
target_include_directories(${EXEC_TARGET} PRIVATE include src)
