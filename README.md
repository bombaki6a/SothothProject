# Tenta Trace

Version **2.0.0**.

**Tenta Trace** is a lightweight Win32 C++ forensic collection tool for quickly reviewing basic information from the machine where it is executed.

## Overview

| Section | Description |
| --- | --- |
| 🖥️ `SYSTEM` | Host, operating system, locale, time zone, memory, domain and current date/time. |
| 👤 `USERS` | Local human user accounts, including account type and Microsoft account identity when available. |
| 🌐 `NETWORK` | Active LAN/Wi-Fi details, MAC address, local/public IP addresses and user-created shared folders. |
| 🔐 `ENCRYPTION` | BitLocker volume summary for encrypted drives when the application is running with administrator rights. |

## Behavior

- ⚡ Choose categories in the startup dialog. All available categories are selected by default; collection begins after confirming a report name.
- 🛡️ The app attempts to relaunch with administrator rights on startup, but continues without elevation if the prompt is declined.
- 🔒 `ENCRYPTION` is disabled in Win32 builds and requires administrator rights in x64 builds.
- 📄 Selected categories are collected sequentially and automatically saved as an HTML report with tabs, in a named folder beside the executable.
- The results window displays only the selected categories, with category buttons hidden for a single selection. Cancel in the startup dialog closes the application.
- 📦 Release builds are configured to output `TT.exe`.

## Compatibility

The project targets Windows 7 or newer on a best-effort basis and has no external runtime dependencies beyond Windows system libraries.

## Source Layout

- `App/`: application entry point and elevation handling.
- `Core/Collectors/`: separate SYSTEM, USERS, NETWORK, and ENCRYPTION collectors.
- `Core/Support/`: shared formatting, registry, and decoding helpers.
- `Core/Reports/`: collected snapshots and HTML export.
- `UI/`: startup dialog, report-name dialog, and results window.
- `Assets/`: application icon.

Build outputs are written to `Build/<platform>/<configuration>/`. Release uses a static runtime; distribute `TT.exe` with `LICENSE`.
