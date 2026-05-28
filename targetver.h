#pragma once

// Build against a Windows 7 API baseline while still using the newest installed SDK.
#include <WinSDKVer.h>

#ifndef WINVER
#define WINVER 0x0601
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06010000
#endif

#include <SDKDDKVer.h>
