cmake_minimum_required(VERSION 3.6)
project(sigscanner)
set(CMAKE_CXX_STANDARD 17)

option(SIG_SCANNER_SHARED_LIB "Build a sigscanner library" OFF)
option(SIG_SCANNER_STATIC_LIB "Build a static sigscanner library" OFF)
option(SIG_SCANNER_BUILD_EXEC "Build the sigscanner executable" ON)

set(SIG_SCANNER_LIB_SOURCES lib/thread_pool.cpp lib/signature.cpp lib/multi_scanner.cpp lib/scanner.cpp)

if(SIG_SCANNER_SHARED_LIB)
    set(SIG_SCANNER_SHARED_LIB sig-scanner-shared PARENT_SCOPE)
    set(SIG_SCANNER_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include PARENT_SCOPE)
    add_library(${SIG_SCANNER_SHARED_LIB} SHARED ${SIG_SCANNER_LIB_SOURCES})
    target_include_directories(${SIG_SCANNER_LIBS} PUBLIC ${SIG_SCANNER_INCLUDE_DIRS})
endif()

if(SIG_SCANNER_STATIC_LIB)
    set(SIG_SCANNER_SHARED_LIB sig-scanner-static PARENT_SCOPE)
    set(SIG_SCANNER_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include PARENT_SCOPE)
    add_library(${SIG_SCANNER_STATIC_LIB} STATIC ${SIG_SCANNER_LIB_SOURCES})
    target_include_directories(${SIG_SCANNER_STATIC_LIB} PUBLIC ${SIG_SCANNER_INCLUDE_DIRS})
endif()

if(SIG_SCANNER_BUILD_EXEC)
    set(SIG_SCANNER_EXEC_NAME sig-scanner)
    add_executable(${SIG_SCANNER_EXEC_NAME} src/main.cpp ${SIG_SCANNER_LIB_SOURCES})
    target_include_directories(${SIG_SCANNER_EXEC_NAME} PRIVATE src include)
endif()
