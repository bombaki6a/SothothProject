#include "ForensicCollector.h"
#include "Collectors/SystemCollector.h"
#include "Collectors/UserCollector.h"
#include "Collectors/NetworkCollector.h"
#include "Collectors/EncryptionCollector.h"

namespace Sothoth::Core
{
/// Dispatches a category request to its dedicated collector without owning UI state.
std::wstring ForensicCollector::CollectSection(ForensicSection section) const
{
    switch (section)
    {
    case ForensicSection::OperatingSystem:
        return SystemCollector{}.Collect();
    case ForensicSection::UserAccounts:
        return UserCollector{}.Collect();
    case ForensicSection::NetworkShares:
        return NetworkCollector{}.Collect();
    case ForensicSection::BitLocker:
        return EncryptionCollector{}.Collect();
    default:
        return L"Unsupported forensic section.";
    }
}
} // namespace Sothoth::Core
