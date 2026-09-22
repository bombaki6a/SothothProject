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

/// Converts the stable category enumeration to its array index.
constexpr std::size_t ToIndex(ForensicSection section)
{
    return static_cast<std::size_t>(section);
}

inline constexpr std::array<const wchar_t*, kForensicSectionCount> kSectionLabels = {
    L"SYSTEM", L"USERS", L"NETWORK", L"ENCRYPTION"
};

/// Returns a display name for a valid category or a fallback for an invalid index.
inline const wchar_t* SectionLabel(std::size_t index)
{
    return index < kSectionLabels.size() ? kSectionLabels[index] : L"Unknown Section";
}

/// Routes category requests to independent collectors.
class ForensicCollector
{
public:
    /// Collects one category and returns its formatted snapshot or diagnostic text.
    std::wstring CollectSection(ForensicSection section) const;
};
} // namespace Sothoth::Core
