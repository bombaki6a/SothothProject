#pragma once

#include <string>

namespace Sothoth::Core
{
/// Collects the interactive-user report independently of the GUI.
class UserCollector
{
public:
    /// Returns a plain-text snapshot, including diagnostics when system queries fail.
    std::wstring Collect() const;
};
} // namespace Sothoth::Core
