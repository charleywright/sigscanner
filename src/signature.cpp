#include "signature.hpp"

signature::signature(const std::string_view &pattern)
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
      this->mask.push_back(MaskType::PLACEHOLDER);
    } else
    {
      this->pattern.push_back(static_cast<std::uint8_t>(std::strtoul(pattern.substr(i, 2).data(), nullptr, 16) & 0xFF));
      this->mask.push_back(MaskType::BYTE);
    }
  }

  this->length = this->pattern.size();
}

bool signature::valid() const
{
  return this->pattern.size() == this->mask.size() && this->length > 0;
}

bool signature::compare(const std::vector<std::uint8_t> &data, std::size_t offset) const
{
  if (offset + this->pattern.size() > data.size())
  {
    return false;
  }

  for (std::size_t i = 0; i < this->pattern.size(); ++i)
  {
    if (this->mask[i] == MaskType::BYTE && this->pattern[i] != data[offset + i])
    {
      return false;
    }
  }

  return true;
}
