#pragma once

#include <array>
#include <cstddef>
#include <string>

namespace Sothoth::Core
{
enum class ForensicSection : std::size_t
{
    OperatingSystem = 0,
    UserAccounts,
    NetworkShares,
    BitLocker,
    Count
};

constexpr std::size_t kForensicSectionCount = static_cast<std::size_t>(ForensicSection::Count);

constexpr std::size_t ToIndex(ForensicSection section)
{
    return static_cast<std::size_t>(section);
}

class ForensicCollector
{
public:
    std::wstring CollectSection(ForensicSection section) const;
};
} // namespace Sothoth::Core
