#include <winsock2.h>
#include <ws2tcpip.h>

#include "framework.h"
#include "NetworkCollector.h"
#include "../Support/CollectorSupport.h"

#include <iphlpapi.h>
#include <lm.h>
#include <wlanapi.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

namespace Sothoth::Core
{
using namespace Support;
namespace
{
/// Formats a socket address numerically without initiating a DNS lookup.
std::wstring SockaddrToAddressString(const SOCKADDR* address)
{
    if (address == nullptr)
    {
        return {};
    }

    wchar_t buffer[NI_MAXHOST]{};
    const int length = address->sa_family == AF_INET
        ? static_cast<int>(sizeof(SOCKADDR_IN))
        : static_cast<int>(sizeof(SOCKADDR_IN6));

    if (GetNameInfoW(address, length, buffer, static_cast<DWORD>(std::size(buffer)), nullptr, 0, NI_NUMERICHOST) != 0)
    {
        return {};
    }

    return NormalizeDisplayText(buffer);
}

/// Appends an address only if a case-insensitive equivalent has not already been collected.
void AddUniqueValue(std::vector<std::wstring>& values, const std::wstring& value)
{
    if (value.empty())
    {
        return;
    }

    for (const auto& existingValue : values)
    {
        if (EqualsIgnoreCase(existingValue, value.c_str()))
        {
            return;
        }
    }

    values.push_back(value);
}

/// Combines multiple addresses for display, or returns the supplied empty-list fallback.
std::wstring JoinValues(const std::vector<std::wstring>& values, const wchar_t* fallback = L"Unavailable")
{
    if (values.empty())
    {
        return fallback;
    }

    std::wstring result;
    for (std::size_t index = 0; index < values.size(); ++index)
    {
        if (index > 0)
        {
            result += L", ";
        }
        result += values[index];
    }

    return NormalizeDisplayText(result);
}

/// Formats the adapter's physical address as uppercase hexadecimal octets.
std::wstring FormatMacAddress(const BYTE* addressBytes, ULONG addressLength)
{
    if (addressBytes == nullptr || addressLength == 0)
    {
        return L"Unavailable";
    }

    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setfill(L'0');

    for (ULONG index = 0; index < addressLength; ++index)
    {
        if (index > 0)
        {
            stream << L'-';
        }

        stream << std::setw(2) << static_cast<unsigned int>(addressBytes[index]);
    }

    return NormalizeDisplayText(stream.str());
}

/// Maps Windows adapter types to the WiFi, LAN, or Other labels used by the UI.
std::wstring AdapterTypeToString(ULONG ifType)
{
    if (ifType == IF_TYPE_IEEE80211)
    {
        return L"WiFi";
    }

    if (ifType == IF_TYPE_ETHERNET_CSMACD)
    {
        return L"LAN";
    }

    return L"Other";
}

/// Normalizes adapter names for matching IP Helper and WLAN interface descriptions.
std::wstring NormalizeLookupKey(std::wstring value)
{
    value = NormalizeDisplayText(value);

    std::wstring normalized;
    normalized.reserve(value.size());

    for (wchar_t ch : value)
    {
        if (iswalnum(ch))
        {
            normalized.push_back(static_cast<wchar_t>(towlower(ch)));
        }
    }

    return normalized;
}

/// Decodes SSID bytes as UTF-8 where possible and falls back to the Windows code page.
std::wstring DecodeSsid(const DOT11_SSID& ssid)
{
    if (ssid.uSSIDLength == 0)
    {
        return L"(hidden)";
    }

    const std::string raw(reinterpret_cast<const char*>(ssid.ucSSID), ssid.uSSIDLength);

    int wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>(raw.size()), nullptr, 0);
    if (wideLength > 0)
    {
        std::wstring decoded(static_cast<std::size_t>(wideLength), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>(raw.size()), decoded.data(), wideLength);
        return NormalizeDisplayText(decoded);
    }

    wideLength = MultiByteToWideChar(CP_ACP, 0, raw.data(), static_cast<int>(raw.size()), nullptr, 0);
    if (wideLength > 0)
    {
        std::wstring decoded(static_cast<std::size_t>(wideLength), L'\0');
        MultiByteToWideChar(CP_ACP, 0, raw.data(), static_cast<int>(raw.size()), decoded.data(), wideLength);
        return NormalizeDisplayText(decoded);
    }

    std::wstring decoded;
    decoded.reserve(raw.size());
    for (unsigned char ch : raw)
    {
        decoded.push_back(static_cast<wchar_t>(ch));
    }
    return NormalizeDisplayText(decoded);
}

/// Looks up the SSID of a connected WLAN interface and releases all WLAN API allocations.
std::wstring QueryWifiNetworkName(const std::wstring& adapterFriendlyName)
{
    HANDLE clientHandle = nullptr;
    DWORD negotiatedVersion = 0;
    if (WlanOpenHandle(2, nullptr, &negotiatedVersion, &clientHandle) != ERROR_SUCCESS)
    {
        return {};
    }

    PWLAN_INTERFACE_INFO_LIST interfaceList = nullptr;
    if (WlanEnumInterfaces(clientHandle, nullptr, &interfaceList) != ERROR_SUCCESS || interfaceList == nullptr)
    {
        if (interfaceList != nullptr)
        {
            WlanFreeMemory(interfaceList);
        }
        WlanCloseHandle(clientHandle, nullptr);
        return {};
    }

    const std::wstring normalizedAdapterName = NormalizeLookupKey(adapterFriendlyName);
    std::wstring firstConnectedSsid;

    for (DWORD index = 0; index < interfaceList->dwNumberOfItems; ++index)
    {
        const WLAN_INTERFACE_INFO& interfaceInfo = interfaceList->InterfaceInfo[index];
        if (interfaceInfo.isState != wlan_interface_state_connected)
        {
            continue;
        }

        DWORD dataSize = 0;
        WLAN_OPCODE_VALUE_TYPE valueType = wlan_opcode_value_type_invalid;
        PWLAN_CONNECTION_ATTRIBUTES connectionAttributes = nullptr;

        const DWORD status = WlanQueryInterface(
            clientHandle,
            &interfaceInfo.InterfaceGuid,
            wlan_intf_opcode_current_connection,
            nullptr,
            &dataSize,
            reinterpret_cast<PVOID*>(&connectionAttributes),
            &valueType);

        if (status != ERROR_SUCCESS || connectionAttributes == nullptr)
        {
            if (connectionAttributes != nullptr)
            {
                WlanFreeMemory(connectionAttributes);
            }
            continue;
        }

        const std::wstring ssid = DecodeSsid(connectionAttributes->wlanAssociationAttributes.dot11Ssid);
        if (firstConnectedSsid.empty())
        {
            firstConnectedSsid = ssid;
        }

        const std::wstring interfaceDescription = NormalizeLookupKey(interfaceInfo.strInterfaceDescription);
        WlanFreeMemory(connectionAttributes);

        if (!normalizedAdapterName.empty() && normalizedAdapterName == interfaceDescription)
        {
            WlanFreeMemory(interfaceList);
            WlanCloseHandle(clientHandle, nullptr);
            return ssid;
        }
    }

    WlanFreeMemory(interfaceList);
    WlanCloseHandle(clientHandle, nullptr);
    return firstConnectedSsid;
}

/// Requests the public address from the specified endpoint using bounded HTTP timeouts.
std::wstring QueryPublicIpAddress(const wchar_t* hostName)
{
    HINTERNET session = WinHttpOpen(
        L"Tenta Trace/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (session == nullptr)
    {
        return L"Unavailable";
    }

    WinHttpSetTimeouts(session, 2000, 2000, 3000, 3000);

    HINTERNET connection = WinHttpConnect(session, hostName, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (connection == nullptr)
    {
        WinHttpCloseHandle(session);
        return L"Unavailable";
    }

    HINTERNET request = WinHttpOpenRequest(
        connection,
        L"GET",
        L"/",
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (request == nullptr)
    {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return L"Unavailable";
    }

    std::wstring result = L"Unavailable";
    if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(request, nullptr))
    {
        std::string response;

        for (;;)
        {
            DWORD availableBytes = 0;
            if (!WinHttpQueryDataAvailable(request, &availableBytes) || availableBytes == 0)
            {
                break;
            }

            std::vector<char> buffer(availableBytes);
            DWORD downloadedBytes = 0;
            if (!WinHttpReadData(request, buffer.data(), availableBytes, &downloadedBytes) || downloadedBytes == 0)
            {
                break;
            }

            response.append(buffer.data(), buffer.data() + downloadedBytes);
            if (response.size() > 128)
            {
                break;
            }
        }

        if (!response.empty())
        {
            std::wstring decoded = DecodeConsoleBytes(response);
            decoded = TrimTrailingWhitespace(decoded);
            if (!decoded.empty())
            {
                result = decoded;
            }
        }
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return result;
}

/// Accepts active, non-loopback adapters with at least one unicast address.
bool IsCandidateNetworkAdapter(const IP_ADAPTER_ADDRESSES* adapter)
{
    if (adapter == nullptr)
    {
        return false;
    }

    if (adapter->OperStatus != IfOperStatusUp)
    {
        return false;
    }

    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL)
    {
        return false;
    }

    return adapter->FirstUnicastAddress != nullptr;
}

/// Ranks local IPv6 candidates so the most suitable identifying address is displayed.
int GetIpv6AddressPriority(const IP_ADAPTER_UNICAST_ADDRESS* address)
{
    if (address == nullptr || address->Address.lpSockaddr == nullptr || address->Address.lpSockaddr->sa_family != AF_INET6)
    {
        return (std::numeric_limits<int>::max)();
    }

    const auto* ipv6Address = reinterpret_cast<const SOCKADDR_IN6*>(address->Address.lpSockaddr);
    if (IN6_IS_ADDR_LOOPBACK(&ipv6Address->sin6_addr) || IN6_IS_ADDR_MULTICAST(&ipv6Address->sin6_addr))
    {
        return (std::numeric_limits<int>::max)();
    }

    const UCHAR* bytes = ipv6Address->sin6_addr.u.Byte;
    const bool isUniqueLocal = (bytes[0] & 0xFE) == 0xFC;
    const bool isLinkLocal = IN6_IS_ADDR_LINKLOCAL(&ipv6Address->sin6_addr) != 0;
    const bool isTemporary = address->SuffixOrigin == IpSuffixOriginRandom;
    const bool isPreferred = address->DadState == IpDadStatePreferred;

    int score = 30;
    if (isUniqueLocal)
    {
        score = 0;
    }
    else if (isLinkLocal)
    {
        score = 10;
    }
    else
    {
        score = 20;
    }

    if (isTemporary)
    {
        score += 5;
    }

    if (!isPreferred)
    {
        score += 2;
    }

    return score;
}

struct ActiveNetworkSnapshot
{
    std::wstring adapterName;
    std::wstring adapterType;
    std::wstring macAddress;
    std::wstring networkName;
    std::wstring ipv4Address;
    std::wstring ipv6Address;
    std::wstring defaultGateway;
    std::wstring publicIpv4Address;
    std::wstring publicIpv6Address;
    std::wstring diagnostic;
    bool hasPublicAddressLookup = false;
};

/// Selects an active adapter and queries public addresses only for a LAN or Wi-Fi candidate.
ActiveNetworkSnapshot QueryActiveNetworkSnapshot()
{
    ActiveNetworkSnapshot snapshot;

    ULONG bufferSize = 0;
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &bufferSize);
    if (result != ERROR_BUFFER_OVERFLOW)
    {
        snapshot.diagnostic = L"GetAdaptersAddresses failed: " + FormatStatusCode(result);
        return snapshot;
    }

    std::vector<BYTE> buffer(bufferSize);
    auto* adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &bufferSize);
    if (result != NO_ERROR)
    {
        snapshot.diagnostic = L"GetAdaptersAddresses failed: " + FormatStatusCode(result);
        return snapshot;
    }

    DWORD bestInterfaceIndex = 0;
    IN_ADDR internetProbeAddress{};
    if (InetPtonW(AF_INET, L"8.8.8.8", &internetProbeAddress) != 1 ||
        GetBestInterface(internetProbeAddress.S_un.S_addr, &bestInterfaceIndex) != NO_ERROR)
    {
        bestInterfaceIndex = 0;
    }

    PIP_ADAPTER_ADDRESSES chosenAdapter = nullptr;
    PIP_ADAPTER_ADDRESSES fallbackWithGateway = nullptr;
    PIP_ADAPTER_ADDRESSES fallbackAdapter = nullptr;

    for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next)
    {
        if (!IsCandidateNetworkAdapter(adapter))
        {
            continue;
        }

        if (fallbackAdapter == nullptr)
        {
            fallbackAdapter = adapter;
        }

        if (adapter->FirstGatewayAddress != nullptr && fallbackWithGateway == nullptr)
        {
            fallbackWithGateway = adapter;
        }

        if (bestInterfaceIndex != 0 &&
            (adapter->IfIndex == bestInterfaceIndex || adapter->Ipv6IfIndex == bestInterfaceIndex))
        {
            chosenAdapter = adapter;
            break;
        }
    }

    if (chosenAdapter == nullptr)
    {
        chosenAdapter = fallbackWithGateway != nullptr ? fallbackWithGateway : fallbackAdapter;
    }

    if (chosenAdapter == nullptr)
    {
        snapshot.diagnostic = L"No active network adapter found.";
        return snapshot;
    }

    snapshot.adapterName = chosenAdapter->FriendlyName != nullptr ? chosenAdapter->FriendlyName : L"Unavailable";
    snapshot.adapterType = AdapterTypeToString(chosenAdapter->IfType);
    snapshot.macAddress = FormatMacAddress(chosenAdapter->PhysicalAddress, chosenAdapter->PhysicalAddressLength);
    snapshot.hasPublicAddressLookup =
        chosenAdapter->IfType == IF_TYPE_IEEE80211 ||
        chosenAdapter->IfType == IF_TYPE_ETHERNET_CSMACD;

    std::vector<std::wstring> ipv4Addresses;
    std::wstring bestIpv6Address;
    int bestIpv6Priority = (std::numeric_limits<int>::max)();
    for (auto* address = chosenAdapter->FirstUnicastAddress; address != nullptr; address = address->Next)
    {
        const std::wstring addressText = SockaddrToAddressString(address->Address.lpSockaddr);
        if (addressText.empty())
        {
            continue;
        }

        if (address->Address.lpSockaddr->sa_family == AF_INET)
        {
            AddUniqueValue(ipv4Addresses, addressText);
        }
        else if (address->Address.lpSockaddr->sa_family == AF_INET6)
        {
            const int priority = GetIpv6AddressPriority(address);
            if (priority < bestIpv6Priority)
            {
                bestIpv6Priority = priority;
                bestIpv6Address = addressText;
            }
        }
    }

    snapshot.ipv4Address = JoinValues(ipv4Addresses);
    snapshot.ipv6Address = DefaultIfEmpty(bestIpv6Address, L"Unavailable");

    if (chosenAdapter->FirstGatewayAddress != nullptr)
    {
        snapshot.defaultGateway = SockaddrToAddressString(chosenAdapter->FirstGatewayAddress->Address.lpSockaddr);
    }
    if (snapshot.defaultGateway.empty())
    {
        snapshot.defaultGateway = L"Unavailable";
    }

    if (chosenAdapter->IfType == IF_TYPE_IEEE80211)
    {
        snapshot.networkName = DefaultIfEmpty(QueryWifiNetworkName(snapshot.adapterName), L"Unavailable");
    }
    else
    {
        snapshot.networkName = L"Not applicable";
    }

    if (snapshot.hasPublicAddressLookup)
    {
        snapshot.publicIpv4Address = QueryPublicIpAddress(L"api4.ipify.org");
        snapshot.publicIpv6Address = QueryPublicIpAddress(L"api6.ipify.org");
    }

    return snapshot;
}

/// Excludes administrative and non-disk shares from the shared-folder report.
bool IsUserCreatedShare(const SHARE_INFO_2& share)
{
    if ((share.shi2_type & STYPE_SPECIAL) != 0)
    {
        return false;
    }

    if ((share.shi2_type & 0xFF) != STYPE_DISKTREE)
    {
        return false;
    }

    if (share.shi2_netname == nullptr || *share.shi2_netname == L'\0')
    {
        return false;
    }

    if (wcschr(share.shi2_netname, L'$') != nullptr)
    {
        return false;
    }

    return true;
}

/// Enumerates user disk shares across all API result pages and appends their paths and remarks.
void AppendSharedFolders(std::wostringstream& stream)
{
    AppendHeader(stream, L"Shared Resources", L'=');

    SHARE_INFO_2* shares = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    DWORD totalCollected = 0;

    NET_API_STATUS status = NERR_Success;
    do
    {
        status = NetShareEnum(
            nullptr,
            2,
            reinterpret_cast<LPBYTE*>(&shares),
            MAX_PREFERRED_LENGTH,
            &entriesRead,
            &totalEntries,
            &resumeHandle);

        if (status != NERR_Success && status != ERROR_MORE_DATA)
        {
            stream << L"NetShareEnum failed: " << FormatStatusCode(status) << L"\r\n";
            return;
        }

        for (DWORD i = 0; i < entriesRead; ++i)
        {
            const SHARE_INFO_2& share = shares[i];
            if (!IsUserCreatedShare(share))
            {
                continue;
            }

            if (totalCollected > 0)
            {
                stream << L"\r\n";
            }

            AppendField(stream, L"Name", share.shi2_netname ? share.shi2_netname : L"(unknown)", L"(unknown)");
            AppendField(stream, L"Path", share.shi2_path && *share.shi2_path ? share.shi2_path : L"(not applicable)", L"(not applicable)");
            AppendField(stream, L"Remark", share.shi2_remark && *share.shi2_remark ? share.shi2_remark : L"(none)", L"(none)");
            ++totalCollected;
        }

        if (shares != nullptr)
        {
            NetApiBufferFree(shares);
            shares = nullptr;
        }
    } while (status == ERROR_MORE_DATA);

    if (totalCollected == 0)
    {
        stream << L"No user shared folders found.\r\n";
    }
}
} // namespace

/// Collects and formats this category using the existing filtering and display rules.
std::wstring NetworkCollector::Collect() const
{
    std::wostringstream stream;
    AppendHeader(stream, L"Active Network", L'=');

    WSADATA winsockData{};
    const int winsockResult = WSAStartup(MAKEWORD(2, 2), &winsockData);
    if (winsockResult != 0)
    {
        stream << L"WSAStartup failed: " << winsockResult << L"\r\n";
        return NormalizeDisplayText(stream.str());
    }

    const ActiveNetworkSnapshot snapshot = QueryActiveNetworkSnapshot();
    if (!snapshot.diagnostic.empty())
    {
        stream << snapshot.diagnostic << L"\r\n";
    }
    else
    {
        AppendField(stream, L"Adapter Type", snapshot.adapterType, L"Unavailable");
        AppendField(stream, L"MAC Address", snapshot.macAddress, L"Unavailable");
        AppendField(stream, L"Network Name", snapshot.networkName, L"Unavailable");
        AppendField(stream, L"Local IPv4 Address", snapshot.ipv4Address, L"Unavailable");
        AppendField(stream, L"Local IPv6 Address", snapshot.ipv6Address, L"Unavailable");
        if (snapshot.hasPublicAddressLookup)
        {
            AppendField(stream, L"Public IPv4 Address", snapshot.publicIpv4Address, L"Unavailable");
            AppendField(stream, L"Public IPv6 Address", snapshot.publicIpv6Address, L"Unavailable");
        }
    }

    AppendSharedFolders(stream);

    WSACleanup();

    return NormalizeDisplayText(stream.str());
}
} // namespace Sothoth::Core
