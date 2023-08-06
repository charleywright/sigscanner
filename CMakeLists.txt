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
        src/scanner.hpp
)
target_include_directories(${EXEC_TARGET} PRIVATE include src)

FetchContent_Declare(flags URL https://raw.githubusercontent.com/sailormoon/flags/master/include/flags.h DOWNLOAD_NO_EXTRACT YES)
FetchContent_MakeAvailable(flags)
target_include_directories(${EXEC_TARGET} PRIVATE ${flags_SOURCE_DIR})
