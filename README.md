<div align="center">
  <img src="Assets/app.ico" alt="Tenta Trace icon" width="96" height="96">
  <h1>Tenta Trace</h1>
  <p><strong>Lightweight native Windows forensic information collector</strong></p>
  <p>Version 2.0.0 &bull; C++ &bull; Win32 API &bull; No third-party dependencies</p>
</div>

---

## Overview

Tenta Trace collects a focused snapshot of the Windows computer on which it is executed. The operator chooses one or more categories, gives the report a name, and receives both an on-screen result and a self-contained HTML report.

The application is designed to remain small and portable. It uses native Windows APIs, the Windows Registry, and built-in system tools instead of external libraries or services. Data is collected only after the operator confirms the selected categories.

| Category | Collected information |
| --- | --- |
| 🖥️ `SYSTEM` | Computer identity, Windows version, installation and regional information, system model, and physical memory. |
| 👤 `USERS` | Local interactive user accounts, account privilege, and locally cached Microsoft account identity. |
| 🌐 `NETWORK` | Active LAN/Wi-Fi connection, MAC and IP addresses, Wi-Fi name, public addresses, and user-created shares. |
| 🔐 `ENCRYPTION` | Encrypted BitLocker volumes, protection and lock state, and numerical-password protector information. |

## Collection Workflow

1. Tenta Trace checks whether the process is elevated and offers a single UAC relaunch through the Windows `runas` verb.
2. If elevation is declined, the application continues with standard user rights. The `ENCRYPTION` category remains unavailable.
3. The startup dialog presents all available categories, selected by default.
4. After a report name is entered, the selected collectors run sequentially in a worker thread.
5. Results are displayed in the main window and exported to a new folder beside `TT.exe`.
6. The generated HTML file contains one tab for each selected category. Collected values are escaped before being inserted into the document.

Existing report folders are never overwritten. Cancelling the startup dialog closes the application without collecting information.

## Data Collection Modules

### 🖥️ SYSTEM

Implemented by `SystemCollector`, this module reads local operating-system and hardware metadata. It does not start a command-line process and does not contact the network.

| Information | Source and method |
| --- | --- |
| Host name | `GetComputerNameExW` with the physical DNS host-name format. |
| Domain or workgroup | `NetGetJoinInformation`; the DNS domain name is used as a fallback. |
| OS name | `ProductName` and `CurrentBuildNumber` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`. Build 22000 and later are identified as Windows 11 even when the registry product label still says Windows 10. |
| OS version | `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `CurrentBuildNumber`, and `UBR` from the same registry key. |
| Original install date | Registry `InstallDate`, converted from a Unix timestamp to local time. |
| Registered owner and organization | `RegisteredOwner` and `RegisteredOrganization` from the Windows current-version registry key. |
| Current date and time | `GetLocalTime`. |
| System and input locale | `GetSystemDefaultLocaleName`, `GetKeyboardLayout`, `LCIDToLocaleName`, and `GetLocaleInfoEx`. |
| Time zone | `GetDynamicTimeZoneInformation`, including the currently effective UTC offset. |
| System model | `SystemProductName` from `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, with `BaseBoardProduct` as fallback. |
| Physical memory | `GetPhysicallyInstalledSystemMemory`, with `GlobalMemoryStatusEx` as fallback. |

The collected fields are arranged into Machine Identity, Operating System, Regional Settings, and Hardware groups.

### 👤 USERS

Implemented by `UserCollector`, this module enumerates local accounts and deliberately filters built-in, service, application-created, disabled, and non-interactive identities. It does not query Microsoft or any other online identity provider.

| Operation | Source and method |
| --- | --- |
| Enumerate local accounts | `NetUserEnum` from the Windows Network Management API. |
| Read account details | `NetUserGetInfo` levels 3 and 23 for the account name, full name, privilege, flags, and SID. |
| Match a Windows profile | Account SID lookup under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`. |
| Identify human profiles | Account-name and well-known SID filtering, followed by checks for a normal profile directory and interactive-profile markers. |
| Detect a Microsoft account | Local cache entries under `HKLM\SOFTWARE\Microsoft\IdentityStore\LogonCache`. The cached identity is matched to the local account and profile. |

For each accepted account, the report contains `Name`, `Full Name`, `Privilege`, and `Type`. The type is shown as a local account or as a Microsoft account with the cached email address when one is available.

The filtering is intentionally conservative. It reduces noise from system and application accounts, but it is heuristic and should not be treated as a complete identity audit.

### 🌐 NETWORK

Implemented by `NetworkCollector`, this module combines the IP Helper, Native Wi-Fi, Network Management, and WinHTTP APIs.

| Information | Source and method |
| --- | --- |
| Active adapter | `GetAdaptersAddresses`; only operational, non-loopback adapters with a unicast address are considered. LAN and Wi-Fi adapters are preferred. |
| Adapter type | Windows interface type mapped to `LAN`, `WiFi`, or `Other`. |
| MAC address | Physical adapter address returned by `GetAdaptersAddresses`, formatted as hexadecimal octets. |
| Wi-Fi network name | `WlanOpenHandle`, `WlanEnumInterfaces`, and `WlanQueryInterface` retrieve the SSID for the connected wireless interface. |
| Local IPv4 address | Unicast IPv4 address of the selected active adapter. |
| Local IPv6 address | The best usable local IPv6 candidate, preferring an address suitable for identifying the device on its network. |
| Public IPv4 address | HTTPS request to `api4.ipify.org` through WinHTTP. |
| Public IPv6 address | HTTPS request to `api6.ipify.org` through WinHTTP. |
| Shared folders | `NetShareEnum`; only user-created disk shares are displayed. Administrative and non-disk shares are excluded. |

Public address requests use short connection and response timeouts. They are attempted only when the selected active adapter is LAN or Wi-Fi. If the computer is offline, the module skips those requests. The two ipify requests are the only intentional outbound network communication performed by Tenta Trace.

### 🔐 ENCRYPTION

Implemented by `EncryptionCollector`, this module uses the Windows-provided `manage-bde.exe` command-line tool. Commands run in a hidden child process, and their standard output and error streams are captured through an anonymous pipe.

The collector first executes `manage-bde -status`, parses the returned volume sections, and keeps only encrypted volumes or volumes currently undergoing encryption or decryption. For every retained volume it reports:

- Volume and size
- Protection Status
- Lock Status
- Recovery Protector ID for a `Numerical Password` protector
- Recovery Key when Windows returns it and the volume is not locked

Protector details are queried per volume with `manage-bde -protectors -get <volume>`. The recovery key is omitted from the displayed result when the volume is locked. The category is enabled only for an elevated x64 process and remains disabled in Win32 builds.

> [!CAUTION]
> BitLocker recovery information is sensitive. Generated reports must be stored, transferred, and deleted according to the evidence-handling policy of the investigation.

## Supporting Modules

| Module | Responsibility |
| --- | --- |
| `App/SothothProject.cpp` | Win32 application entry point and top-level startup flow. |
| `App/ElevationService` | Detects administrator-group membership and performs the single optional UAC relaunch. A command-line marker prevents relaunch loops. |
| `Core/ForensicCollector` | Maps a selected category to its dedicated collector without owning UI state. |
| `Core/Support/CollectorSupport` | Shared registry readers, text decoding, normalization, formatting, and status-code helpers. |
| `Core/Reports/CollectionReport` | In-memory snapshot containing selected categories, collected text, timestamps, report name, and save state. |
| `Core/Reports/ReportWriter` | Sanitizes report names, escapes collected content, builds the tabbed HTML document, and writes it as UTF-8 beside the executable. |
| `UI/StartupDialog` | Category selection, report naming, collection progress, worker synchronization, and automatic report creation. |
| `UI/ReportNameDialog` | Validates the report name and prevents confirmation while the field is empty. |
| `UI/MainWindow` | Displays completed results and category navigation. Navigation is hidden when only one category was collected. |

## Source Layout

```text
SothothProject/
|-- App/                    Application entry point and elevation
|-- Assets/                 Application icon
|-- Core/
|   |-- Collectors/         SYSTEM, USERS, NETWORK, and ENCRYPTION
|   |-- Reports/            Report state and HTML export
|   `-- Support/            Shared collection utilities
|-- UI/                     Native Win32 dialogs and result window
|-- SothothProject.vcxproj  Visual Studio project
`-- SothothProject.rc       Windows resources and version metadata
```

## Permissions and Privacy

- Standard user rights are sufficient for `SYSTEM`, `USERS`, and most `NETWORK` data.
- Some account, share, or registry information can be unavailable because of local security policy.
- `ENCRYPTION` requires administrator rights and is available only in the x64 build.
- Tenta Trace does not install a service, driver, browser component, or persistent background task.
- Tenta Trace does not upload generated reports.
- Public IP discovery discloses the requesting public address to `api4.ipify.org` and `api6.ipify.org`.
- All other collection is performed locally using Windows facilities.

Unavailable data is reported explicitly instead of stopping the complete collection process.

## Compatibility

The project targets Windows 7 or newer on a best-effort basis. Newer Windows versions expose more complete API and BitLocker information, so individual fields can be unavailable on older systems.

Release builds use the static Microsoft C++ runtime and have no third-party runtime dependencies. Windows system DLLs and `manage-bde.exe` are supplied by the operating system.

## Building

Open `SothothProject.vcxproj` in Visual Studio with the Desktop development with C++ workload installed, then select `Release` and the required platform.

Command-line examples from a Visual Studio developer environment:

```powershell
msbuild SothothProject.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild SothothProject.vcxproj /p:Configuration=Release /p:Platform=Win32
```

Build outputs are written to:

```text
Build/x64/Release/TT.exe
Build/Win32/Release/TT.exe
```

For normal distribution, use the x64 build so the BitLocker category can be available. Distribute `TT.exe` together with the `LICENSE` file.

## License

Tenta Trace is released under the [MIT License](LICENSE).
