#pragma once

#include <string>

namespace Sothoth::Core
{
/// Collects the active-network and shared-folder report independently of the GUI.
class NetworkCollector
{
public:
    /// Returns a plain-text snapshot, including diagnostics when system queries fail.
    std::wstring Collect() const;
};
} // namespace Sothoth::Core
