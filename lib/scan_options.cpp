#include "sigscanner/sigscanner.hpp"

void sigscanner::scan_options::set_max_depth(int depth)
{
  this->max_depth = depth;
}

void sigscanner::scan_options::set_file_size_min(std::int64_t size)
{
  this->min_size = size;
}

void sigscanner::scan_options::set_file_size_max(std::int64_t size)
{
  this->max_size = size;
}

void sigscanner::scan_options::set_thread_count(std::size_t count)
{
  this->thread_count = count;
}

void sigscanner::scan_options::set_threading_mode(sigscanner::scan_options::threading_mode mode)
{
  this->threading = mode;
}

void sigscanner::scan_options::set_extension_checking_mode(sigscanner::scan_options::extension_checking_mode mode)
{
  this->extension_checking = mode;
}

void sigscanner::scan_options::add_extension(std::string_view new_extension)
{
  this->extensions.push_back(new_extension);
}

void sigscanner::scan_options::add_extensions(std::initializer_list<std::string_view> new_extensions)
{
  this->extensions.insert(this->extensions.end(), new_extensions.begin(), new_extensions.end());
}

void sigscanner::scan_options::add_extensions(const std::vector<std::string_view> &new_extensions)
{
  this->extensions.insert(this->extensions.end(), new_extensions.begin(), new_extensions.end());
}

void sigscanner::scan_options::remove_extension(std::string_view remove_extension)
{
  this->extensions.erase(std::remove(this->extensions.begin(), this->extensions.end(), remove_extension), this->extensions.end());
}

void sigscanner::scan_options::remove_extensions(std::initializer_list<std::string_view> remove_extensions)
{
  this->extensions.erase(std::remove_if(this->extensions.begin(), this->extensions.end(), [&remove_extensions](const std::string_view &extension) {
      return std::find(remove_extensions.begin(), remove_extensions.end(), extension) != remove_extensions.end();
  }), this->extensions.end());
}

void sigscanner::scan_options::remove_extensions(const std::vector<std::string_view> &remove_extensions)
{
  this->extensions.erase(std::remove_if(this->extensions.begin(), this->extensions.end(), [&remove_extensions](const std::string_view &extension) {
      return std::find(remove_extensions.begin(), remove_extensions.end(), extension) != remove_extensions.end();
  }), this->extensions.end());
}

void sigscanner::scan_options::set_filename_checking_mode(sigscanner::scan_options::filename_checking_mode mode)
{
  this->filename_checking = mode;
}

void sigscanner::scan_options::add_filename(std::string_view new_filename)
{
  this->filenames.push_back(new_filename);
}

void sigscanner::scan_options::add_filenames(std::initializer_list<std::string_view> new_filenames)
{
  this->filenames.insert(this->filenames.end(), new_filenames.begin(), new_filenames.end());
}

void sigscanner::scan_options::add_filenames(const std::vector<std::string_view> &new_filenames)
{
  this->filenames.insert(this->filenames.end(), new_filenames.begin(), new_filenames.end());
}

void sigscanner::scan_options::remove_filename(std::string_view remove_filename)
{
  this->filenames.erase(std::remove(this->filenames.begin(), this->filenames.end(), remove_filename), this->filenames.end());
}

void sigscanner::scan_options::remove_filenames(std::initializer_list<std::string_view> remove_filenames)
{
  this->filenames.erase(std::remove_if(this->filenames.begin(), this->filenames.end(), [&remove_filenames](const std::string_view &filename) {
      return std::find(remove_filenames.begin(), remove_filenames.end(), filename) != remove_filenames.end();
  }), this->filenames.end());
}

void sigscanner::scan_options::remove_filenames(const std::vector<std::string_view> &remove_filenames)
{
  this->filenames.erase(std::remove_if(this->filenames.begin(), this->filenames.end(), [&remove_filenames](const std::string_view &filename) {
      return std::find(remove_filenames.begin(), remove_filenames.end(), filename) != remove_filenames.end();
  }), this->filenames.end());
}

bool sigscanner::scan_options::check_depth(int depth) const
{
  return !(this->max_depth > -1 && depth > this->max_depth);
}

bool sigscanner::scan_options::check_file_size(std::int64_t size) const
{
  if (this->min_size > -1 && size < this->min_size)
    return false;
  if (this->max_size > -1 && size > this->max_size)
    return false;
  return true;
}

bool sigscanner::scan_options::check_extension(const std::filesystem::path &path) const
{
  if (this->extension_checking == sigscanner::scan_options::extension_checking_mode::WHITELIST)
  {
    if (this->extensions.empty())
      return true;
    return std::find(this->extensions.begin(), this->extensions.end(), path.extension().string()) != this->extensions.end();
  } else if (this->extension_checking == sigscanner::scan_options::extension_checking_mode::BLACKLIST)
  {
    if (this->extensions.empty())
      return true;
    return std::find(this->extensions.begin(), this->extensions.end(), path.extension().string()) == this->extensions.end();
  }
  return true;
}

bool sigscanner::scan_options::check_filename(const std::filesystem::path &path) const
{
  if (this->filename_checking == sigscanner::scan_options::filename_checking_mode::EXACT)
  {
    if (this->filenames.empty())
      return true;
    return std::find(this->filenames.begin(), this->filenames.end(), path.filename().string()) != this->filenames.end();
  } else if (this->filename_checking == sigscanner::scan_options::filename_checking_mode::INCLUDES)
  {
    if (this->filenames.empty())
      return true;
    const std::string &filename = path.filename().string();
    return std::find_if(this->filenames.begin(), this->filenames.end(), [&filename](const std::string_view &filename_to_check) {
        return filename.find(filename_to_check) != std::string::npos;
    }) != this->filenames.end();
  }
  return true;
}
