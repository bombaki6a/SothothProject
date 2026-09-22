#include "ReportWriter.h"
#include "framework.h"
#include <array>
#include <vector>
#include <sstream>

namespace Sothoth::Core
{
namespace
{
struct ReportSectionData
{
    std::wstring title;
    std::wstring content;
    std::wstring collectedAt;
};

/// Trims user-supplied report names before sanitizing their file-system representation.
std::wstring TrimWhitespace(std::wstring value)
{
    while (!value.empty() && iswspace(value.back()))
    {
        value.pop_back();
    }

    std::size_t start = 0;
    while (start < value.size() && iswspace(value[start]))
    {
        ++start;
    }

    return start == 0 ? value : value.substr(start);
}

/// Escapes collected text before inserting it into HTML so values cannot become markup or script.
std::wstring HtmlEscape(const std::wstring& value)
{
    std::wstring escaped;
    escaped.reserve(value.size());

    for (wchar_t ch : value)
    {
        switch (ch)
        {
        case L'&':
            escaped += L"&amp;";
            break;
        case L'<':
            escaped += L"&lt;";
            break;
        case L'>':
            escaped += L"&gt;";
            break;
        case L'"':
            escaped += L"&quot;";
            break;
        case L'\'':
            escaped += L"&#39;";
            break;
        default:
            escaped.push_back(ch);
            break;
        }
    }

    return escaped;
}

/// Replaces characters unsuitable for file names and removes trailing dots and spaces.
std::wstring SanitizeFileSystemName(std::wstring value)
{
    value = TrimWhitespace(std::move(value));

    for (wchar_t& ch : value)
    {
        switch (ch)
        {
        case L'<':
        case L'>':
        case L':':
        case L'"':
        case L'/':
        case L'\\':
        case L'|':
        case L'?':
        case L'*':
            ch = L'_';
            break;
        default:
            break;
        }
    }

    while (!value.empty() && (value.back() == L'.' || value.back() == L' '))
    {
        value.pop_back();
    }

    return value.empty() ? L"Report" : value;
}

/// Resolves the executable's directory, which is the base location for exported reports.
std::wstring GetExecutableDirectory()
{
    std::array<wchar_t, 32768> buffer{};
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size())
    {
        return L".";
    }

    std::wstring path(buffer.data(), length);
    const std::size_t separator = path.find_last_of(L"\\/");
    return separator == std::wstring::npos ? L"." : path.substr(0, separator);
}

/// Joins a directory and leaf name without introducing duplicate path separators.
std::wstring CombinePath(const std::wstring& left, const std::wstring& right)
{
    if (left.empty())
    {
        return right;
    }

    if (left.back() == L'\\' || left.back() == L'/')
    {
        return left + right;
    }

    return left + L'\\' + right;
}

/// Checks whether the destination path already exists before report creation.
bool PathExists(const std::wstring& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES;
}

/// Converts report text from UTF-16 to UTF-8 for the exported HTML document.
std::string EncodeUtf8(const std::wstring& value)
{
    if (value.empty())
    {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0)
    {
        return {};
    }

    std::string bytes(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), bytes.data(), size, nullptr, nullptr);
    return bytes;
}

/// Writes a UTF-8 HTML file with a byte-order mark and checks for incomplete writes.
bool WriteUtf8File(const std::wstring& filePath, const std::wstring& content, std::wstring& errorMessage)
{
    HANDLE fileHandle = CreateFileW(
        filePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        errorMessage = L"Unable to create report file.";
        return false;
    }

    const BYTE bom[] = {0xEF, 0xBB, 0xBF};
    DWORD written = 0;
    if (!WriteFile(fileHandle, bom, static_cast<DWORD>(sizeof(bom)), &written, nullptr) || written != sizeof(bom))
    {
        CloseHandle(fileHandle);
        errorMessage = L"Unable to write report file.";
        return false;
    }

    const std::string utf8Content = EncodeUtf8(content);
    const DWORD contentSize = static_cast<DWORD>(utf8Content.size());
    const BOOL writeResult = contentSize == 0
        ? TRUE
        : WriteFile(fileHandle, utf8Content.data(), contentSize, &written, nullptr);

    CloseHandle(fileHandle);

    if (!writeResult || (contentSize != 0 && written != contentSize))
    {
        errorMessage = L"Unable to write report file.";
        return false;
    }

    return true;
}

/// Builds a self-contained HTML document with one escaped tab per collected section.
std::wstring BuildReportHtml(const std::wstring& reportName, const std::vector<ReportSectionData>& sections)
{
    std::wostringstream html;
    html << L"<!DOCTYPE html>\n"
         << L"<html lang=\"en\">\n"
         << L"<head>\n"
         << L"  <meta charset=\"utf-8\">\n"
         << L"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
         << L"  <title>" << HtmlEscape(reportName) << L"</title>\n"
         << L"  <style>\n"
         << L"    body { font-family: Segoe UI, sans-serif; margin: 0; background: #f3f5f7; color: #1f2933; }\n"
         << L"    .page { max-width: 1100px; margin: 0 auto; padding: 28px; }\n"
         << L"    h1 { margin: 0 0 8px; font-size: 32px; }\n"
         << L"    .meta { color: #52606d; margin-bottom: 20px; }\n"
         << L"    .tabs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px; }\n"
         << L"    .tab-button { border: 0; background: #d9e2ec; color: #102a43; padding: 10px 16px; border-radius: 10px; cursor: pointer; font-size: 14px; }\n"
         << L"    .tab-button.active { background: #102a43; color: #f0f4f8; }\n"
         << L"    .tab-panel { display: none; background: #ffffff; border-radius: 16px; padding: 20px; box-shadow: 0 12px 28px rgba(15, 23, 42, 0.08); }\n"
         << L"    .tab-panel.active { display: block; }\n"
         << L"    .section-meta { color: #52606d; margin-bottom: 16px; font-size: 14px; }\n"
         << L"    pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-family: Consolas, monospace; font-size: 14px; line-height: 1.5; }\n"
         << L"  </style>\n"
         << L"</head>\n"
         << L"<body>\n"
         << L"  <div class=\"page\">\n"
         << L"    <h1>" << HtmlEscape(reportName) << L"</h1>\n"
         << L"    <div class=\"meta\">Generated at: " << HtmlEscape(ReportWriter::FormatLocalTimestamp()) << L"</div>\n"
         << L"    <div class=\"tabs\">\n";

    for (std::size_t index = 0; index < sections.size(); ++index)
    {
        html << L"      <button class=\"tab-button" << (index == 0 ? L" active" : L"") << L"\" data-tab=\"tab-" << index << L"\">"
             << HtmlEscape(sections[index].title) << L"</button>\n";
    }

    html << L"    </div>\n";

    for (std::size_t index = 0; index < sections.size(); ++index)
    {
        html << L"    <section id=\"tab-" << index << L"\" class=\"tab-panel" << (index == 0 ? L" active" : L"") << L"\">\n"
             << L"      <h2>" << HtmlEscape(sections[index].title) << L"</h2>\n"
             << L"      <div class=\"section-meta\">Collected at: " << HtmlEscape(sections[index].collectedAt.empty() ? L"Unavailable" : sections[index].collectedAt) << L"</div>\n"
             << L"      <pre>" << HtmlEscape(sections[index].content) << L"</pre>\n"
             << L"    </section>\n";
    }

    html << L"  </div>\n"
         << L"  <script>\n"
         << L"    const buttons = document.querySelectorAll('.tab-button');\n"
         << L"    const panels = document.querySelectorAll('.tab-panel');\n"
         << L"    buttons.forEach((button) => {\n"
         << L"      button.addEventListener('click', () => {\n"
         << L"        const tabId = button.getAttribute('data-tab');\n"
         << L"        buttons.forEach((item) => item.classList.toggle('active', item === button));\n"
         << L"        panels.forEach((panel) => panel.classList.toggle('active', panel.id === tabId));\n"
         << L"      });\n"
         << L"    });\n"
         << L"  </script>\n"
         << L"</body>\n"
         << L"</html>\n";

    return html.str();
}
} // namespace

/// Captures the machine's local time as a stable, human-readable collection timestamp.
std::wstring ReportWriter::FormatLocalTimestamp()
{
    SYSTEMTIME localTime{};
    GetLocalTime(&localTime);

    wchar_t buffer[64]{};
    swprintf_s(
        buffer,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        localTime.wYear,
        localTime.wMonth,
        localTime.wDay,
        localTime.wHour,
        localTime.wMinute,
        localTime.wSecond);

    return buffer;
}

/// Creates a fresh destination and records a complete HTML snapshot, reporting file-system failures.
bool ReportWriter::Save(const CollectionReport& report, std::wstring& error)
{
    error.clear();
    std::vector<ReportSectionData> sections;
    for (std::size_t i = 0; i < report.loaded.size(); ++i)
        if (report.loaded[i]) sections.push_back({SectionLabel(i), report.sections[i], report.collectedAt[i]});
    const std::wstring safeName = SanitizeFileSystemName(report.name);
    const std::wstring folder = CombinePath(GetExecutableDirectory(), safeName);
    const std::wstring file = CombinePath(folder, safeName + L".html");
    if (!CreateDirectoryW(folder.c_str(), nullptr))
    {
        error = L"Unable to create report folder. It may already exist or be inaccessible.";
        return false;
    }
    if (!WriteUtf8File(file, BuildReportHtml(report.name, sections), error))
    {
        DeleteFileW(file.c_str());
        RemoveDirectoryW(folder.c_str());
        return false;
    }
    return true;
}

/// Checks the same sanitized destination that Save uses.
bool ReportWriter::Exists(const std::wstring& name)
{
    return PathExists(CombinePath(GetExecutableDirectory(), SanitizeFileSystemName(name)));
}
} // namespace Sothoth::Core
