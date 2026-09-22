#pragma once

#include "../ForensicCollector.h"
#include <array>
#include <string>

namespace Sothoth::Core
{
/// Owns one report's selection and collected snapshots; the worker writes it before the UI reads it.
struct CollectionReport
{
    std::array<bool, kForensicSectionCount> selected{};
    std::array<bool, kForensicSectionCount> loaded{};
    std::array<std::wstring, kForensicSectionCount> sections{};
    std::array<std::wstring, kForensicSectionCount> collectedAt{};
    std::wstring name;
    bool saved = false;
};
} // namespace Sothoth::Core
