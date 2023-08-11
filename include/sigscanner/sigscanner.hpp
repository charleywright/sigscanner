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
#include <initializer_list>

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
        signature(const signature &copy);
        signature &operator=(const signature &copy);
        signature(signature &&move) noexcept;
        signature &operator=(signature &&move) noexcept;

        // Comparison
        bool operator==(const signature &rhs) const;
        bool operator!=(const signature &rhs) const;

        // Output
        explicit operator std::string() const;

        friend std::ostream &operator<<(std::ostream &os, const signature &signature)
        {
          os << static_cast<std::string>(signature);
          return os;
        }

        // Members
        bool check(const byte *data, std::size_t size) const;
        std::vector<offset> scan(const byte *data, std::size_t size, offset base) const;
        std::vector<offset> reverse_scan(const byte *data, std::size_t size, offset base) const;
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
        std::vector<byte> pattern;
        std::vector<mask_type> mask;
        std::size_t length = 0;
        std::size_t hash = 0;

        void update_hash();
    };

    class multi_scanner;
    class scanner;

    class scan_options
    {
    public:
        scan_options() = default;
        scan_options(const scan_options &copy) = default;
        scan_options &operator=(const scan_options &copy) = default;
        scan_options(scan_options &&move) noexcept = default;
        scan_options &operator=(scan_options &&move) noexcept = default;

        void set_max_depth(int depth); // -1 for infinite (default). 0 would scan only the given directory
        void set_file_size_min(std::int64_t size); // -1 to disable (default)
        void set_file_size_max(std::int64_t size); // -1 to disable (default)
        void set_thread_count(std::size_t count);
        enum class threading_mode;
        void set_threading_mode(threading_mode mode);

        enum class extension_checking_mode;
        void set_extension_checking_mode(extension_checking_mode mode);
        void add_extension(std::string_view extension);
        void add_extensions(std::initializer_list<std::string_view> extensions);
        void add_extensions(const std::vector<std::string_view> &extensions);
        void remove_extension(std::string_view extension);
        void remove_extensions(std::initializer_list<std::string_view> extensions);
        void remove_extensions(const std::vector<std::string_view> &extensions);

        enum class filename_checking_mode;
        void set_filename_checking_mode(filename_checking_mode mode);
        void add_filename(std::string_view filename);
        void add_filenames(std::initializer_list<std::string_view> filenames);
        void add_filenames(const std::vector<std::string_view> &filenames);
        void remove_filename(std::string_view filename);
        void remove_filenames(std::initializer_list<std::string_view> filenames);
        void remove_filenames(const std::vector<std::string_view> &filenames);

    public:
        enum class threading_mode
        {
            PER_CHUNK, // New task for each chunk. Better for a small number of files
            PER_FILE // New task for each file. Better for a large number of files (default)
        };

        // For either modes if no extensions are specified, all files are scanned
        enum class extension_checking_mode
        {
            WHITELIST, // Only scan files with the given extensions (default)
            BLACKLIST // Scan all files except those with the given extensions
        };

        enum class filename_checking_mode
        {
            EXACT, // Filename must match exactly (default)
            INCLUDES // Filename must include one of the provided case-sensitive strings
        };

    private:
        int max_depth = -1;
        std::int64_t min_size = -1;
        std::int64_t max_size = -1;
        std::size_t thread_count = 1;
        threading_mode threading = threading_mode::PER_FILE;
        extension_checking_mode extension_checking = extension_checking_mode::WHITELIST;
        std::vector<std::string_view> extensions;
        filename_checking_mode filename_checking = filename_checking_mode::EXACT;
        std::vector<std::string_view> filenames;

        bool check_depth(int depth) const;
        bool check_file_size(std::int64_t size) const;
        bool check_extension(const std::filesystem::path &path) const;
        bool check_filename(const std::filesystem::path &path) const;

        friend multi_scanner;
        friend scanner;
    };

    class multi_scanner
    {
    public:
        multi_scanner() = default;
        explicit multi_scanner(const signature &signature);
        explicit multi_scanner(const std::vector<signature> &signatures);

        /*
         * Add a signature to the scanner. Doing so while scanning is undefined behavior.
         */
        void add_signature(const signature &signature);
        void add_signatures(const std::vector<signature> &signatures);

        [[nodiscard]] std::unordered_map<signature, std::vector<offset>>
        scan(const byte *data, std::size_t len, const scan_options &options = scan_options()) const;
        [[nodiscard]] std::unordered_map<signature, std::vector<offset>>
        reverse_scan(const byte *data, std::size_t len, const scan_options &options = scan_options()) const;
        [[nodiscard]] std::unordered_map<signature, std::vector<offset>> scan_file(const std::filesystem::path &path, const scan_options &options = scan_options()) const;
        [[nodiscard]] std::unordered_map<signature, std::unordered_map<std::filesystem::path, std::vector<offset>>>
        scan_directory(const std::filesystem::path &path, const scan_options &options = scan_options()) const;

    private:
        /*
         * Scan a file for a signature. this->thread_pool must already be initialized.
         * One of results_ptr or directory_results_ptr must be non-null.
         * The results map must have all keys initialized.
         */
        void scan_file_internal(const std::filesystem::path &path, const scan_options &options, std::size_t longest_sig,
                                std::unordered_map<signature, std::unordered_map<std::filesystem::path, std::vector<offset>>> &results,
                                std::mutex &result_mutex) const;

    private:
        std::vector<signature> signatures;
        std::size_t longest_sig_length() const;
        mutable sigscanner::thread_pool thread_pool;
    };

    class scanner
    {
    public:
        explicit scanner(const signature &signature);

        [[nodiscard]] std::vector<offset> scan(const byte *data, std::size_t len, const scan_options &options = scan_options()) const;
        [[nodiscard]] std::vector<offset> reverse_scan(const byte *data, std::size_t len, const scan_options &options = scan_options()) const;
        [[nodiscard]] std::vector<offset> scan_file(const std::filesystem::path &path, const scan_options &options = scan_options()) const;
        [[nodiscard]] std::unordered_map<std::filesystem::path, std::vector<offset>>
        scan_directory(const std::filesystem::path &path, const scan_options &options = scan_options()) const;

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
