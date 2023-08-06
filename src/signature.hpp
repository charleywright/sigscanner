#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

class signature
{
public:
    signature(const std::string_view &pattern);

    enum class MaskType : bool
    {
        PLACEHOLDER,
        BYTE
    };

    bool valid() const;
    [[nodiscard]] bool compare(const std::vector<std::uint8_t> &data, std::size_t offset) const;

    std::vector<std::uint8_t> pattern;
    std::vector<MaskType> mask;
    std::size_t length = 0;
};
