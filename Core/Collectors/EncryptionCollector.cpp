#include "framework.h"
#include "EncryptionCollector.h"
#include "../Support/CollectorSupport.h"


#include <algorithm>
#include <array>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace Sothoth::Core
{
using namespace Support;
namespace
{
/// Trims surrounding whitespace before comparing or displaying a collected value.
std::wstring TrimWhitespace(std::wstring value)
{
    value = TrimTrailingWhitespace(std::move(value));

    std::size_t index = 0;
    while (index < value.size())
    {
        const wchar_t ch = value[index];
        if (ch != L' ' && ch != L'\t' && ch != L'\r' && ch != L'\n')
        {
            break;
        }
        ++index;
    }

    return index == 0 ? value : value.substr(index);
}

/// Runs a hidden command with redirected output and returns decoded output together with any exit error.
std::wstring RunCommandCapture(const std::wstring& command)
{
    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &securityAttributes, 0))
    {
        return L"Unable to create capture pipe.\r\n" + FormatErrorMessage(GetLastError());
    }

    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    startupInfo.wShowWindow = SW_HIDE;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = writePipe;
    startupInfo.hStdError = writePipe;

    PROCESS_INFORMATION processInfo{};
    std::wstring commandLine = L"cmd.exe /d /c \"" + command + L"\"";

    const BOOL created = CreateProcessW(
        nullptr,
        commandLine.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startupInfo,
        &processInfo);

    CloseHandle(writePipe);
    writePipe = nullptr;

    if (!created)
    {
        CloseHandle(readPipe);
        return L"Unable to start command:\r\n" + command + L"\r\n\r\n" + FormatErrorMessage(GetLastError());
    }

    std::string outputBytes;
    std::array<char, 4096> buffer{};
    DWORD bytesRead = 0;
    while (ReadFile(readPipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) && bytesRead > 0)
    {
        outputBytes.append(buffer.data(), bytesRead);
        bytesRead = 0;
    }

    CloseHandle(readPipe);
    readPipe = nullptr;

    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);

    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    std::wstring output = DecodeConsoleBytes(outputBytes);
    output = TrimTrailingWhitespace(output);

    if (output.empty())
    {
        std::wostringstream stream;
        stream << L"Command returned no output: " << command;
        if (exitCode != 0)
        {
            stream << L"\r\nExit code: " << exitCode;
        }
        return stream.str();
    }

    if (exitCode != 0)
    {
        std::wostringstream stream;
        stream << output << L"\r\n\r\nExit code: " << exitCode;
        return stream.str();
    }

    return output;
}

struct BitLockerVolumeSummary
{
    std::wstring volume;
    std::wstring size;
    std::wstring conversionStatus;
    std::wstring percentageEncrypted;
    std::wstring protectionStatus;
    std::wstring lockStatus;
    std::wstring recoveryProtectorId;
    std::wstring recoveryPassword;
};

/// Extracts the text following a recognized command-output label and colon.
std::wstring ExtractLabeledValue(const std::wstring& line, const wchar_t* label)
{
    if (!StartsWithIgnoreCase(line, label))
    {
        return {};
    }

    const std::size_t separator = line.find(L':');
    if (separator == std::wstring::npos)
    {
        return {};
    }

    return TrimWhitespace(line.substr(separator + 1));
}

/// Identifies volumes that are encrypted or undergoing conversion using status and percentage fields.
bool IsEncryptedBitLockerVolume(const BitLockerVolumeSummary& volume)
{
    const std::wstring normalizedStatus = ToLowerInvariant(volume.conversionStatus);
    if (!normalizedStatus.empty())
    {
        if (normalizedStatus.find(L"decryption") != std::wstring::npos)
        {
            return true;
        }

        if (normalizedStatus.find(L"encrypted") != std::wstring::npos ||
            normalizedStatus.find(L"encryption") != std::wstring::npos)
        {
            return true;
        }

        if (normalizedStatus.find(L"decrypted") != std::wstring::npos)
        {
            return false;
        }
    }

    const std::wstring normalizedPercentage = TrimWhitespace(volume.percentageEncrypted);
    return !normalizedPercentage.empty() && normalizedPercentage != L"0%" && normalizedPercentage != L"0.0%";
}

/// Recognizes a locked volume while avoiding a false match on the word unlocked.
bool IsLockedBitLockerVolume(const BitLockerVolumeSummary& volume)
{
    const std::wstring normalizedLockStatus = ToLowerInvariant(volume.lockStatus);
    return normalizedLockStatus.find(L"locked") != std::wstring::npos &&
        normalizedLockStatus.find(L"unlocked") == std::wstring::npos;
}

/// Adds the current encrypted volume to the result and resets parser state for the next volume.
void FinalizeBitLockerVolume(BitLockerVolumeSummary& currentVolume, std::vector<BitLockerVolumeSummary>& encryptedVolumes)
{
    if (!currentVolume.volume.empty() && IsEncryptedBitLockerVolume(currentVolume))
    {
        encryptedVolumes.push_back(currentVolume);
    }

    currentVolume = {};
}

/// Parses supported manage-bde status labels into encrypted-volume summaries.
std::vector<BitLockerVolumeSummary> ParseBitLockerStatusOutput(const std::wstring& statusOutput)
{
    std::vector<BitLockerVolumeSummary> encryptedVolumes;
    std::wistringstream input(statusOutput);
    std::wstring line;
    BitLockerVolumeSummary currentVolume;

    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == L'\r')
        {
            line.pop_back();
        }

        const std::wstring trimmedLine = TrimWhitespace(line);
        if (trimmedLine.empty())
        {
            continue;
        }

        if (StartsWithIgnoreCase(trimmedLine, L"Volume "))
        {
            FinalizeBitLockerVolume(currentVolume, encryptedVolumes);
            currentVolume.volume = trimmedLine;
            continue;
        }

        if (currentVolume.volume.empty())
        {
            continue;
        }

        if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Size"); !value.empty())
        {
            currentVolume.size = value;
        }
        else if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Conversion Status"); !value.empty())
        {
            currentVolume.conversionStatus = value;
        }
        else if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Percentage Encrypted"); !value.empty())
        {
            currentVolume.percentageEncrypted = value;
        }
        else if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Protection Status"); !value.empty())
        {
            currentVolume.protectionStatus = value;
        }
        else if (const std::wstring value = ExtractLabeledValue(trimmedLine, L"Lock Status"); !value.empty())
        {
            currentVolume.lockStatus = value;
        }
    }

    FinalizeBitLockerVolume(currentVolume, encryptedVolumes);
    return encryptedVolumes;
}

/// Removes the command's Volume prefix for a concise display label.
std::wstring FormatBitLockerVolumeLabel(const std::wstring& volumeHeader)
{
    std::wstring value = TrimWhitespace(volumeHeader);

    if (StartsWithIgnoreCase(value, L"Volume "))
    {
        value = TrimWhitespace(value.substr(wcslen(L"Volume ")));
    }

    return DefaultIfEmpty(value, L"Unavailable");
}

/// Extracts the mount-point token used by the protector query.
std::wstring ExtractVolumeMountPoint(const std::wstring& volumeHeader)
{
    std::wistringstream stream(volumeHeader);
    std::wstring keyword;
    std::wstring mountPoint;
    stream >> keyword >> mountPoint;
    return mountPoint;
}

struct BitLockerRecoveryProtector
{
    std::wstring id;
    std::wstring password;
};

/// Reads the numerical-password protector details from manage-bde output for the selected volume.
BitLockerRecoveryProtector QueryRecoveryProtector(const std::wstring& volumeHeader)
{
    BitLockerRecoveryProtector protector;

    const std::wstring mountPoint = ExtractVolumeMountPoint(volumeHeader);
    if (mountPoint.empty())
    {
        return protector;
    }

    const std::wstring output = NormalizeDisplayText(RunCommandCapture(L"manage-bde -protectors -get " + mountPoint));
    if (output.empty() || output.find(L"ERROR:") != std::wstring::npos)
    {
        return protector;
    }

    std::wistringstream input(output);
    std::wstring line;

    bool inNumericalPassword = false;
    bool waitingForPasswordValue = false;

    while (std::getline(input, line))
    {
        if (!line.empty() && line.back() == L'\r')
        {
            line.pop_back();
        }

        const std::wstring trimmedLine = TrimWhitespace(line);
        if (trimmedLine.empty())
        {
            continue;
        }

        if (StartsWithIgnoreCase(trimmedLine, L"Numerical Password"))
        {
            inNumericalPassword = true;
            waitingForPasswordValue = true;

            continue;
        }

        if (!inNumericalPassword)
        {
            continue;
        }

        if (const std::wstring id = ExtractLabeledValue(trimmedLine, L"ID"); !id.empty())
        {
            protector.id = id;
            continue;
        }

        if (StartsWithIgnoreCase(trimmedLine, L"Password"))
        {
            const std::wstring passwordOnSameLine = ExtractLabeledValue(trimmedLine, L"Password");

            if (!passwordOnSameLine.empty())
            {
                protector.password = passwordOnSameLine;
                waitingForPasswordValue = false;
            }
            else
            {
                waitingForPasswordValue = true;
            }

            continue;
        }

        if (waitingForPasswordValue)
        {
            protector.password = trimmedLine;
            waitingForPasswordValue = false;
            continue;
        }

        if (trimmedLine.back() == L'.' && !StartsWithIgnoreCase(trimmedLine, L"ID") && !StartsWithIgnoreCase(trimmedLine, L"Password"))
        {
            break;
        }
    }

    return protector;
}
} // namespace

/// Collects and formats this category using the existing filtering and display rules.
std::wstring EncryptionCollector::Collect() const
{
    const std::wstring output = NormalizeDisplayText(RunCommandCapture(L"manage-bde -status"));
    if (output.empty())
    {
        return L"No BitLocker data available.";
    }

    if (output.find(L"ERROR:") != std::wstring::npos && output.find(L"Volume ") == std::wstring::npos)
    {
        return output;
    }

    std::vector<BitLockerVolumeSummary> encryptedVolumes = ParseBitLockerStatusOutput(output);

    std::wostringstream stream;
    AppendHeader(stream, L"Encrypted Volumes", L'=');

    if (encryptedVolumes.empty())
    {
        stream << L"No encrypted volumes found.\r\n";
        return NormalizeDisplayText(stream.str());
    }

    for (std::size_t index = 0; index < encryptedVolumes.size(); ++index)
    {
        if (index > 0)
        {
            stream << L"\r\n";
        }

        BitLockerVolumeSummary& volume = encryptedVolumes[index];
        if (volume.recoveryProtectorId.empty() || volume.recoveryPassword.empty())
        {
            const BitLockerRecoveryProtector protector = QueryRecoveryProtector(volume.volume);

            volume.recoveryProtectorId = protector.id;
            volume.recoveryPassword = protector.password;
        }

        AppendField(stream, L"Volume", FormatBitLockerVolumeLabel(volume.volume), L"Unavailable");
        AppendField(stream, L"Size", volume.size, L"Unavailable");
        AppendField(stream, L"Protection Status", volume.protectionStatus, L"Unavailable");
        AppendField(stream, L"Lock Status", volume.lockStatus, L"Unavailable");
        AppendField(stream, L"Recovery Protector ID", volume.recoveryProtectorId, L"Not found");
        if (!IsLockedBitLockerVolume(volume))
        {
            AppendField(stream, L"Recovery Key", volume.recoveryPassword, L"Not found");
        }
    }

    return NormalizeDisplayText(stream.str());
}
} // namespace Sothoth::Core
