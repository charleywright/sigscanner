#pragma once

#include <string_view>
#include <utility>
#include <vector>
#include <filesystem>
#include <cstdint>
#include <unordered_map>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

#ifndef SIGSCANNER_FILE_BLOCK_SIZE
#define SIGSCANNER_FILE_BLOCK_SIZE static_cast<std::uint64_t>(1'048'576ull) // 1MB
#endif

namespace sigscanner
{
    typedef std::uint8_t byte;
    typedef std::uint64_t offset;

    class thread_pool
    {
    public:
        thread_pool() = default;
        ~thread_pool();

        void create(std::size_t count);
        void destroy(bool force = false);

        void add_task(std::function<void()> &&task);

    private:
        void thread_loop();
        std::vector<std::thread> threads;
        std::atomic<bool> running = false;
        std::atomic<bool> force_stop = false;

        std::vector<std::function<void()>> tasks;
        std::mutex tasks_mutex;
    };

    class signature
    {
    public:
        // Constructors
        signature() = default;
        signature(std::string_view pattern); // IDA-Style: "AA BB CC ?? ?? ?? DD EE FF"
        signature(std::string_view pattern, std::string_view mask); // Code-Style: "\xAA\xBB\x00\x00\xEE\xFF" "xx??xx"
        signature(const sigscanner::signature &copy);
        signature &operator=(const sigscanner::signature &copy);
        signature(sigscanner::signature &&move) noexcept;
        signature &operator=(sigscanner::signature &&move) noexcept;

        // Comparison
        bool operator==(const signature &rhs) const;
        bool operator!=(const signature &rhs) const;

        // Output
        explicit operator std::string() const;

        friend std::ostream &operator<<(std::ostream &os, const sigscanner::signature &signature)
        {
          os << static_cast<std::string>(signature);
          return os;
        }

        // Members
        bool check(const sigscanner::byte *data, std::size_t size) const;
        std::vector<sigscanner::offset> scan(const sigscanner::byte *data, std::size_t size, sigscanner::offset base) const;
        std::size_t size() const;

        // Allow std::hash to not hash on every call
        template<typename T> friend
        class std::hash;

    public:
        enum class mask_type : bool
        {
            WILDCARD = false,
            BYTE = true
        };

    private:
        std::vector<sigscanner::byte> pattern;
        std::vector<sigscanner::signature::mask_type> mask;
        std::size_t length = 0;
        std::size_t hash = 0;

        void update_hash();
    };

    class multi_scanner
    {
    public:
        multi_scanner() = default;
        explicit multi_scanner(std::size_t thread_count);
        explicit multi_scanner(const sigscanner::signature &signature);
        explicit multi_scanner(const std::vector<sigscanner::signature> &signatures);
        multi_scanner(const sigscanner::signature &signature, std::size_t thread_count);
        multi_scanner(const std::vector<sigscanner::signature> &signatures, std::size_t thread_count);

        /*
         * Set the number of threads to use when scanning a directory. Default 1.
         */
        void set_thread_count(std::size_t count);

        /*
         * Add a signature to the scanner. Doing so while scanning is undefined behavior.
         */
        void add_signature(const sigscanner::signature &signature);
        void add_signatures(const std::vector<sigscanner::signature> &signatures);

        [[nodiscard]] std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> scan(const sigscanner::byte *data, std::size_t len) const;
        [[nodiscard]] std::unordered_map<sigscanner::signature, std::vector<sigscanner::offset>> scan_file(const std::filesystem::path &path) const;
        // Max depth of -1 means no limit. 0 means scan just the directory. 1 means scan the directory and its immediate children, etc.
        [[nodiscard]] std::unordered_map<sigscanner::signature, std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>>
        scan_directory(const std::filesystem::path &path, std::int64_t max_depth = -1) const;

    private:
        // TODO: Implement and benchmark different threading modes
        enum class file_scan_type
        {
            PER_CHUNK, // New task for each chunk
            PER_FILE // New task for each file
        };

        /*
         * Scan a file for a signature. this->thread_pool must already be initialized.
         * One of results_ptr or directory_results_ptr must be non-null.
         * The results map must have all keys initialized.
         */
        void scan_file_internal(const std::filesystem::path &path, sigscanner::multi_scanner::file_scan_type scan_type, std::size_t longest_sig,
                                std::unordered_map<sigscanner::signature, std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>> &results,
                                std::mutex &result_mutex) const;

    private:
        std::vector<sigscanner::signature> signatures;
        std::size_t thread_count = 1;
        mutable sigscanner::thread_pool thread_pool;
        // TODO: settings mutex

        std::size_t longest_sig_length() const;
    };

    class scanner
    {
    public:
        explicit scanner(const sigscanner::signature &signature, std::size_t thread_count = 1);

        /*
         * Set the number of threads to use when scanning a directory. Default 1.
         */
        void set_thread_count(std::size_t thread_count);

        [[nodiscard]] std::vector<sigscanner::offset> scan(const sigscanner::byte *data, std::size_t len) const;
        [[nodiscard]] std::vector<sigscanner::offset> scan_file(const std::filesystem::path &path) const;
        // Max depth of -1 means no limit. 0 means scan just the directory. 1 means scan the directory and its immediate children, etc.
        [[nodiscard]] std::unordered_map<std::filesystem::path, std::vector<sigscanner::offset>>
        scan_directory(const std::filesystem::path &path, std::int64_t max_depth = -1) const;

    private:
        sigscanner::multi_scanner multi_scanner;
    };
}

namespace std
{
    template<>
    struct hash<sigscanner::signature>
    {
        std::size_t operator()(const sigscanner::signature &signature) const noexcept
        {
          return signature.hash;
        }
    };
}
