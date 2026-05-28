# Tenta Trace

**Tenta Trace** is a lightweight Win32 C++ forensic collection tool for quickly reviewing basic information from the machine where it is executed.

## Overview

| Section | Description |
| --- | --- |
| 🖥️ `SYSTEM` | Host, operating system, locale, time zone, memory, domain and current date/time. |
| 👤 `USERS` | Local human user accounts, including account type and Microsoft account identity when available. |
| 🌐 `NETWORK` | Active LAN/Wi-Fi details, MAC address, local/public IP addresses and user-created shared folders. |
| 🔐 `ENCRYPTION` | BitLocker volume summary for encrypted drives when the application is running with administrator rights. |

## Behavior

- ⚡ Information is collected lazily: a section is queried only when its button is clicked.
- 🛡️ The app attempts to relaunch with administrator rights on startup, but continues without elevation if the prompt is declined.
- 🔒 `ENCRYPTION` is disabled in Win32 builds and requires administrator rights in x64 builds.
- 📄 Reports can be generated as HTML after at least one section has been collected.
- 📦 Release builds are configured to output `TT.exe`.

## Compatibility

The project targets Windows 7 or newer on a best-effort basis and has no external runtime dependencies beyond Windows system libraries.
