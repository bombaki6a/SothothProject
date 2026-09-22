#pragma once

#include <string>

namespace Sothoth::Core
{
/// Collects the operating-system report independently of the GUI.
class SystemCollector
{
public:
    /// Returns a plain-text snapshot, including diagnostics when system queries fail.
    std::wstring Collect() const;
};
} // namespace Sothoth::Core
