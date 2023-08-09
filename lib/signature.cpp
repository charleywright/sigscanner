#include "sigscanner/sigscanner.hpp"
#include <sstream>

sigscanner::signature::signature(std::string_view pattern)
{
  if (pattern.size() % 3 != 2)
  {
    return;
  }

  for (std::size_t i = 0; i < pattern.size(); i += 3)
  {
    if (pattern[i] == '?')
    {
      this->pattern.push_back(0);
      this->mask.push_back(mask_type::WILDCARD);
    } else
    {
      this->pattern.push_back(static_cast<std::uint8_t>(std::strtoul(pattern.substr(i, 2).data(), nullptr, 16) & 0xFF));
      this->mask.push_back(mask_type::BYTE);
    }
  }

  this->length = this->mask.size();
  this->update_hash();
}

sigscanner::signature::signature(std::string_view pattern, std::string_view mask)
{
  if (pattern.size() != mask.size())
  {
    return;
  }

  for (std::size_t i = 0; i < this->length; i++)
  {
    if (mask[i] == '?')
    {
      this->pattern.push_back(0);
      this->mask.push_back(mask_type::WILDCARD);
    } else
    {
      this->pattern.push_back(static_cast<std::uint8_t>(std::strtoul(pattern.substr(i, 2).data(), nullptr, 16) & 0xFF));
      this->mask.push_back(mask_type::BYTE);
    }
  }

  this->length = this->mask.size();
  this->update_hash();
}

sigscanner::signature::signature(const sigscanner::signature &copy)
{
  this->pattern = copy.pattern;
  this->mask = copy.mask;
  this->length = copy.length;
  this->hash = copy.hash;
}

sigscanner::signature &sigscanner::signature::operator=(const sigscanner::signature &copy)
= default;

sigscanner::signature::signature(sigscanner::signature &&move) noexcept
{
  this->pattern = std::move(move.pattern);
  this->mask = std::move(move.mask);
  this->length = move.length;
  this->hash = move.hash;

  move.pattern.clear();
  move.mask.clear();
  move.length = 0;
  move.hash = 0;
}

sigscanner::signature &sigscanner::signature::operator=(sigscanner::signature &&move) noexcept
{
  this->pattern = std::move(move.pattern);
  this->mask = std::move(move.mask);
  this->length = move.length;
  this->hash = move.hash;

  move.pattern.clear();
  move.mask.clear();
  move.length = 0;
  move.hash = 0;

  return *this;
}

bool sigscanner::signature::operator==(const sigscanner::signature &rhs) const
{
  return this->hash == rhs.hash;
}

bool sigscanner::signature::operator!=(const sigscanner::signature &rhs) const
{
  return !(*this == rhs);
}

sigscanner::signature::operator std::string() const
{
  std::stringstream ss;
  for (std::size_t i = 0; i < this->length; i++)
  {
    if (i > 0)
    {
      ss << " ";
    }
    if (this->mask[i] == mask_type::WILDCARD)
    {
      ss << "??";
    } else
    {
      ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<std::uint32_t>(this->pattern[i]);
    }
  }
  return ss.str();
}

bool sigscanner::signature::check(const sigscanner::byte *data, std::size_t size) const
{
  if (size < this->length)
  {
    return false;
  }

  for (std::size_t i = 0; i < this->length; i++)
  {
    if (this->mask[i] == mask_type::BYTE && this->pattern[i] != data[i])
    {
      return false;
    }
  }

  return true;
}

std::vector<sigscanner::offset> sigscanner::signature::scan(const sigscanner::byte *data, std::size_t size, sigscanner::offset base) const
{
  std::vector<sigscanner::offset> offsets;
  if (size < this->length)
  {
    return offsets;
  }

  for (std::size_t i = 0; i < size - this->length; i++)
  {
    if (this->check(data + i, size - i))
    {
      offsets.push_back(base + i);
    }
  }

  return offsets;
}

std::size_t sigscanner::signature::size() const
{
  return this->length;
}

void sigscanner::signature::update_hash()
{
  std::size_t h1 = std::hash<std::string_view>{}(std::string_view(reinterpret_cast<const char *>(this->pattern.data()), this->length));
  std::size_t h2 = std::hash<std::string_view>{}(std::string_view(reinterpret_cast<const char *>(this->mask.data()), this->length));
  this->hash = h1 ^ (h2 << 1);
}
