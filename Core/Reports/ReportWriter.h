#pragma once

#include "CollectionReport.h"

namespace Sothoth::Core
{
/// Exports collected snapshots without depending on any window or dialog.
class ReportWriter
{
public:
    /// Saves a new report folder beside the executable; returns an error without overwriting an existing folder.
    static bool Save(const CollectionReport& report, std::wstring& error);
    /// Checks the sanitized report destination before collection begins.
    static bool Exists(const std::wstring& name);
    /// Returns a local timestamp for report generation and category collection.
    static std::wstring FormatLocalTimestamp();
};
} // namespace Sothoth::Core
