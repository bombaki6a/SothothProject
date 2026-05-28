#include "MainWindow.h"

#include "ElevationService.h"
#include "Resource.h"

#include <algorithm>
#include <array>
#include <CommCtrl.h>
#include <cwctype>
#include <memory>
#include <process.h>
#include <richedit.h>
#include <sstream>
#include <string>
#include <vector>

namespace
{
constexpr int kMargin = 12;
constexpr int kStatusLabelId = 1002;
constexpr int kOutputControlId = 1004;
constexpr int kPlaceholderLabelId = 1005;
constexpr int kReportButtonId = 1006;
constexpr int kSectionButtonBaseId = 1100;
constexpr int kCategoryButtonHeight = 42;
constexpr int kReportButtonHeight = 34;
constexpr int kReportButtonWidth = 180;
constexpr int kButtonGap = 8;
constexpr int kInitialWindowWidth = 900;
constexpr int kInitialWindowHeight = 750;

constexpr UINT kCollectionCompleteMessage = WM_APP + 1;
constexpr wchar_t kDefaultWindowTitle[] = L"Tenta Trace";
constexpr wchar_t kDefaultWindowClass[] = L"SothothForensicCollectorWindow";
constexpr wchar_t kInitialPlaceholderText[] = L"Press a category button to collect information.";
constexpr wchar_t kReportNamePlaceholderText[] = L"Choose report name";

const std::array<const wchar_t*, Sothoth::Core::kForensicSectionCount> kSectionLabels = {
    L"SYSTEM",
    L"USERS",
    L"NETWORK",
    L"ENCRYPTION"
};

struct SectionCollectionRequest
{
    HWND ownerWindow = nullptr;
    std::size_t sectionIndex = 0;
};

struct SectionCollectionResult
{
    std::size_t sectionIndex = 0;
    std::wstring content;
    std::wstring collectedAt;
};

struct ReportSectionData
{
    std::wstring title;
    std::wstring content;
    std::wstring collectedAt;
};

struct ReportNameDialogState
{
    std::wstring reportName;
};

std::wstring FormatLocalTimestamp()
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

std::wstring BuildDefaultReportName()
{
    return L"Report_" + FormatLocalTimestamp();
}

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

bool PathExists(const std::wstring& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES;
}

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
    if (!WriteFile(fileHandle, bom, static_cast<DWORD>(sizeof(bom)), &written, nullptr))
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

    if (!writeResult)
    {
        errorMessage = L"Unable to write report file.";
        return false;
    }

    return true;
}

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
         << L"    <div class=\"meta\">Generated at: " << HtmlEscape(FormatLocalTimestamp()) << L"</div>\n"
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

INT_PTR CALLBACK ReportNameDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam)
{
    auto* state = reinterpret_cast<ReportNameDialogState*>(GetWindowLongPtrW(dialog, GWLP_USERDATA));

    switch (message)
    {
    case WM_INITDIALOG:
        state = reinterpret_cast<ReportNameDialogState*>(lParam);
        SetWindowLongPtrW(dialog, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        SendDlgItemMessageW(dialog, IDC_REPORT_NAME_EDIT, EM_SETCUEBANNER, FALSE, reinterpret_cast<LPARAM>(kReportNamePlaceholderText));
        SetDlgItemTextW(dialog, IDC_REPORT_NAME_EDIT, L"");
        EnableWindow(GetDlgItem(dialog, IDOK), FALSE);
        if (state != nullptr && !state->reportName.empty())
        {
            SetDlgItemTextW(dialog, IDC_REPORT_NAME_EDIT, state->reportName.c_str());
            SendDlgItemMessageW(dialog, IDC_REPORT_NAME_EDIT, EM_SETSEL, 0, -1);
            EnableWindow(GetDlgItem(dialog, IDOK), TRUE);
        }
        return static_cast<INT_PTR>(TRUE);

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_REPORT_NAME_EDIT && HIWORD(wParam) == EN_CHANGE)
        {
            wchar_t buffer[260]{};
            GetDlgItemTextW(dialog, IDC_REPORT_NAME_EDIT, buffer, static_cast<int>(std::size(buffer)));
            const std::wstring reportName = TrimWhitespace(buffer);
            EnableWindow(GetDlgItem(dialog, IDOK), reportName.empty() ? FALSE : TRUE);
            return static_cast<INT_PTR>(TRUE);
        }

        switch (LOWORD(wParam))
        {
        case IDOK:
            if (state != nullptr)
            {
                wchar_t buffer[260]{};
                GetDlgItemTextW(dialog, IDC_REPORT_NAME_EDIT, buffer, static_cast<int>(std::size(buffer)));
                state->reportName = TrimWhitespace(buffer);
                if (state->reportName.empty())
                {
                    MessageBoxW(dialog, L"Please enter a report name or press Cancel.", L"Create Report", MB_OK | MB_ICONINFORMATION);
                    return static_cast<INT_PTR>(TRUE);
                }
            }
            EndDialog(dialog, IDOK);
            return static_cast<INT_PTR>(TRUE);

        case IDCANCEL:
            EndDialog(dialog, IDCANCEL);
            return static_cast<INT_PTR>(TRUE);

        default:
            break;
        }
        break;

    default:
        break;
    }

    return static_cast<INT_PTR>(FALSE);
}

const wchar_t* SectionLabel(std::size_t index)
{
    return index < kSectionLabels.size() ? kSectionLabels[index] : L"Unknown Section";
}
} // namespace

MainWindow::MainWindow(HINSTANCE instance, bool isElevated)
    : instance_(instance), isElevated_(isElevated)
{
    wchar_t buffer[100]{};
    if (LoadStringW(instance_, IDS_APP_TITLE, buffer, static_cast<int>(std::size(buffer))) > 0)
    {
        title_ = buffer;
    }
    if (title_.empty())
    {
        title_ = kDefaultWindowTitle;
    }

    if (LoadStringW(instance_, IDC_SOTHOTHPROJECT, buffer, static_cast<int>(std::size(buffer))) > 0)
    {
        className_ = buffer;
    }
    if (className_.empty())
    {
        className_ = kDefaultWindowClass;
    }
}

MainWindow::~MainWindow()
{
    if (monoFont_ != nullptr)
    {
        DeleteObject(monoFont_);
        monoFont_ = nullptr;
    }

    if (placeholderFont_ != nullptr)
    {
        DeleteObject(placeholderFont_);
        placeholderFont_ = nullptr;
    }

    if (richEditModule_ != nullptr)
    {
        FreeLibrary(richEditModule_);
        richEditModule_ = nullptr;
    }
}

bool MainWindow::Create(int showCommand)
{
    richEditModule_ = LoadLibraryW(L"Msftedit.dll");

    if (!RegisterWindowClass())
    {
        return false;
    }

    window_ = CreateWindowW(
        className_.c_str(),
        title_.c_str(),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        0,
        kInitialWindowWidth,
        kInitialWindowHeight,
        nullptr,
        nullptr,
        instance_,
        this);

    if (window_ == nullptr)
    {
        return false;
    }

    RECT windowRect{};
    if (GetWindowRect(window_, &windowRect))
    {
        minWindowWidth_ = windowRect.right - windowRect.left;
        minWindowHeight_ = windowRect.bottom - windowRect.top;
    }

    ShowWindow(window_, showCommand);
    UpdateWindow(window_);
    return true;
}

int MainWindow::MessageLoop() const
{
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0))
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(message.wParam);
}

LRESULT CALLBACK MainWindow::WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    MainWindow* self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));

    if (message == WM_NCCREATE)
    {
        auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
        self = static_cast<MainWindow*>(createStruct->lpCreateParams);
        self->window_ = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }

    if (self != nullptr)
    {
        return self->HandleMessage(message, wParam, lParam);
    }

    return DefWindowProcW(window, message, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        CreateControls();
        LayoutControls();
        SetStatusText(L"");
        UpdateSectionButtons();
        UpdateReportButtonState();
        UpdateOutputForSelectedSection();
        return 0;

    case WM_SIZE:
        LayoutControls();
        return 0;

    case WM_GETMINMAXINFO:
    {
        auto* minMaxInfo = reinterpret_cast<MINMAXINFO*>(lParam);
        minMaxInfo->ptMinTrackSize.x = minWindowWidth_;
        minMaxInfo->ptMinTrackSize.y = minWindowHeight_;
        return 0;
    }

    case WM_COMMAND:
    {
        const int controlId = LOWORD(wParam);
        if (controlId >= kSectionButtonBaseId &&
            controlId < kSectionButtonBaseId + static_cast<int>(Sothoth::Core::kForensicSectionCount))
        {
            SelectSection(static_cast<std::size_t>(controlId - kSectionButtonBaseId));
            return 0;
        }

        switch (controlId)
        {
        case kReportButtonId:
            CreateReport();
            return 0;
        default:
            break;
        }
        break;
    }

    case kCollectionCompleteMessage:
    {
        std::unique_ptr<SectionCollectionResult> result(reinterpret_cast<SectionCollectionResult*>(lParam));
        if (result != nullptr && result->sectionIndex < Sothoth::Core::kForensicSectionCount)
        {
            sections_[result->sectionIndex] = std::move(result->content);
            collectedAt_[result->sectionIndex] = std::move(result->collectedAt);
            loaded_[result->sectionIndex] = true;
            loading_[result->sectionIndex] = false;
            isCollecting_ = false;
            collectingSectionIndex_ = Sothoth::Core::kForensicSectionCount;

            SetStatusText(std::wstring(SectionLabel(result->sectionIndex)) + L" collected at: " + collectedAt_[result->sectionIndex]);
            UpdateSectionButtons();
            UpdateReportButtonState();
            UpdateOutputForSelectedSection();
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_NCDESTROY:
    {
        HWND currentWindow = window_;
        SetWindowLongPtrW(window_, GWLP_USERDATA, 0);
        window_ = nullptr;
        return DefWindowProcW(currentWindow, message, wParam, lParam);
    }

    default:
        break;
    }

    return DefWindowProcW(window_, message, wParam, lParam);
}

bool MainWindow::RegisterWindowClass()
{
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = &MainWindow::WindowProc;
    windowClass.hInstance = instance_;
    windowClass.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_SOTHOTHPROJECT));
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszMenuName = nullptr;
    windowClass.lpszClassName = className_.c_str();
    windowClass.hIconSm = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_SOTHOTHPROJECT));

    const ATOM registeredClass = RegisterClassExW(&windowClass);
    return registeredClass != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

void MainWindow::CreateControls()
{
    monoFont_ = CreateFontW(
        -18,
        0,
        0,
        0,
        FW_NORMAL,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        FIXED_PITCH | FF_MODERN,
        L"Consolas");

    placeholderFont_ = CreateFontW(
        -32,
        0,
        0,
        0,
        FW_SEMIBOLD,
        FALSE,
        FALSE,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        VARIABLE_PITCH | FF_SWISS,
        L"Segoe UI");

    statusLabel_ = CreateWindowExW(
        0,
        L"STATIC",
        L"",
        WS_CHILD | WS_VISIBLE,
        0,
        0,
        0,
        0,
        window_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kStatusLabelId)),
        instance_,
        nullptr);

    for (std::size_t index = 0; index < sectionButtons_.size(); ++index)
    {
        sectionButtons_[index] = CreateWindowExW(
            0,
            L"BUTTON",
            kSectionLabels[index],
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0,
            0,
            0,
            0,
            window_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSectionButtonBaseId + static_cast<int>(index))),
            instance_,
            nullptr);
    }

    placeholderLabel_ = CreateWindowExW(
        0,
        L"STATIC",
        kInitialPlaceholderText,
        WS_CHILD | SS_CENTER | SS_CENTERIMAGE,
        0,
        0,
        0,
        0,
        window_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPlaceholderLabelId)),
        instance_,
        nullptr);

    reportButton_ = CreateWindowExW(
        0,
        L"BUTTON",
        L"Create Report",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        0,
        0,
        0,
        0,
        window_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kReportButtonId)),
        instance_,
        nullptr);

    outputControl_ = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        richEditModule_ != nullptr ? MSFTEDIT_CLASS : L"EDIT",
        L"",
        WS_CHILD | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0,
        0,
        0,
        0,
        window_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kOutputControlId)),
        instance_,
        nullptr);

    SendMessageW(outputControl_, EM_SETLIMITTEXT, 0, 0);

    if (monoFont_ != nullptr)
    {
        SendMessageW(outputControl_, WM_SETFONT, reinterpret_cast<WPARAM>(monoFont_), TRUE);
        SendMessageW(statusLabel_, WM_SETFONT, reinterpret_cast<WPARAM>(monoFont_), TRUE);
        for (HWND button : sectionButtons_)
        {
            if (button != nullptr)
            {
                SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(monoFont_), TRUE);
            }
        }
        if (reportButton_ != nullptr)
        {
            SendMessageW(reportButton_, WM_SETFONT, reinterpret_cast<WPARAM>(monoFont_), TRUE);
        }
    }

    if (placeholderFont_ != nullptr && placeholderLabel_ != nullptr)
    {
        SendMessageW(placeholderLabel_, WM_SETFONT, reinterpret_cast<WPARAM>(placeholderFont_), TRUE);
    }

    EnableWindow(reportButton_, FALSE);
    ShowWindow(placeholderLabel_, SW_SHOW);
    ShowWindow(outputControl_, SW_HIDE);
}

void MainWindow::LayoutControls()
{
    if (statusLabel_ == nullptr || placeholderLabel_ == nullptr || outputControl_ == nullptr || reportButton_ == nullptr)
    {
        return;
    }

    RECT clientRect{};
    GetClientRect(window_, &clientRect);

    const int clientWidth = clientRect.right - clientRect.left;
    const int clientHeight = clientRect.bottom - clientRect.top;

    MoveWindow(statusLabel_, kMargin, kMargin + 4, clientWidth - (kMargin * 2), 22, TRUE);

    const int buttonRowY = kMargin + 34;
    const int totalGapWidth = kButtonGap * static_cast<int>(sectionButtons_.size() - 1);
    const int buttonWidth = (std::max)(120, (clientWidth - (kMargin * 2) - totalGapWidth) / static_cast<int>(sectionButtons_.size()));

    int buttonX = kMargin;
    for (HWND button : sectionButtons_)
    {
        if (button != nullptr)
        {
            MoveWindow(button, buttonX, buttonRowY, buttonWidth, kCategoryButtonHeight, TRUE);
        }
        buttonX += buttonWidth + kButtonGap;
    }

    const int outputY = buttonRowY + kCategoryButtonHeight + kMargin;
    const int reportButtonY = clientHeight - kMargin - kReportButtonHeight;
    const int outputHeight = (std::max)(160, reportButtonY - outputY - kButtonGap);
    MoveWindow(placeholderLabel_, kMargin, outputY, clientWidth - (kMargin * 2), outputHeight, TRUE);
    MoveWindow(outputControl_, kMargin, outputY, clientWidth - (kMargin * 2), outputHeight, TRUE);
    MoveWindow(reportButton_, clientWidth - kMargin - kReportButtonWidth, reportButtonY, kReportButtonWidth, kReportButtonHeight, TRUE);
}

void MainWindow::SelectSection(std::size_t index)
{
    if (index >= Sothoth::Core::kForensicSectionCount)
    {
        return;
    }

    if (index == Sothoth::Core::ToIndex(Sothoth::Core::ForensicSection::BitLocker) && !IsEncryptionAvailable())
    {
#ifdef _WIN64
        SetStatusText(L"ENCRYPTION requires administrator rights.");
#else
        SetStatusText(L"ENCRYPTION is not available in Win32 builds.");
#endif
        return;
    }

    selectedSectionIndex_ = index;
    UpdateSectionButtons();
    UpdateOutputForSelectedSection();

    if (!loaded_[index] && !loading_[index])
    {
        StartCollectionForSection(index);
        return;
    }

    if (loading_[index])
    {
        SetStatusText(std::wstring(SectionLabel(index)) + L" is being collected.");
    }
    else if (loaded_[index] && !collectedAt_[index].empty())
    {
        SetStatusText(std::wstring(SectionLabel(index)) + L" collected at: " + collectedAt_[index]);
    }
}

void MainWindow::StartCollectionForSection(std::size_t index)
{
    if (index >= Sothoth::Core::kForensicSectionCount)
    {
        return;
    }

    if (index == Sothoth::Core::ToIndex(Sothoth::Core::ForensicSection::BitLocker) && !IsEncryptionAvailable())
    {
#ifdef _WIN64
        SetStatusText(L"ENCRYPTION requires administrator rights.");
#else
        SetStatusText(L"ENCRYPTION is not available in Win32 builds.");
#endif
        return;
    }

    if (loading_[index])
    {
        SetStatusText(std::wstring(SectionLabel(index)) + L" is already being collected.");
        UpdateOutputForSelectedSection();
        return;
    }

    if (loaded_[index])
    {
        SetStatusText(std::wstring(SectionLabel(index)) + L" is already loaded.");
        UpdateOutputForSelectedSection();
        return;
    }

    if (isCollecting_)
    {
        SetStatusText(std::wstring(SectionLabel(collectingSectionIndex_)) + L" is already being collected.");
        UpdateOutputForSelectedSection();
        return;
    }

    auto* request = new SectionCollectionRequest{};
    request->ownerWindow = window_;
    request->sectionIndex = index;

    isCollecting_ = true;
    collectingSectionIndex_ = index;
    loading_[index] = true;
    SetStatusText(std::wstring(L"Collecting ") + SectionLabel(index) + L"...");
    UpdateSectionButtons();
    UpdateOutputForSelectedSection();

    const uintptr_t threadHandle = _beginthreadex(
        nullptr,
        0,
        [](void* parameter) -> unsigned
        {
            std::unique_ptr<SectionCollectionRequest> request(static_cast<SectionCollectionRequest*>(parameter));
            Sothoth::Core::ForensicCollector collector;

            auto* result = new SectionCollectionResult{};
            result->sectionIndex = request->sectionIndex;
            result->content = collector.CollectSection(static_cast<Sothoth::Core::ForensicSection>(request->sectionIndex));
            result->collectedAt = FormatLocalTimestamp();

            if (!PostMessageW(request->ownerWindow, kCollectionCompleteMessage, 0, reinterpret_cast<LPARAM>(result)))
            {
                delete result;
            }

            return 0;
        },
        request,
        0,
        nullptr);

    if (threadHandle == 0)
    {
        delete request;
        isCollecting_ = false;
        collectingSectionIndex_ = Sothoth::Core::kForensicSectionCount;
        loading_[index] = false;
        SetStatusText(std::wstring(L"Unable to start collection for ") + SectionLabel(index) + L'.');
        UpdateSectionButtons();
        UpdateOutputForSelectedSection();
        return;
    }

    CloseHandle(reinterpret_cast<HANDLE>(threadHandle));
}

bool MainWindow::CanCreateReport() const
{
    return std::any_of(loaded_.begin(), loaded_.end(), [](bool loaded) { return loaded; });
}

void MainWindow::UpdateReportButtonState()
{
    if (reportButton_ != nullptr)
    {
        EnableWindow(reportButton_, CanCreateReport() ? TRUE : FALSE);
    }
}

void MainWindow::CreateReport()
{
    if (!CanCreateReport())
    {
        SetStatusText(L"No collected sections are available for report creation.");
        return;
    }

    ReportNameDialogState dialogState{};

    const INT_PTR dialogResult = DialogBoxParamW(
        instance_,
        MAKEINTRESOURCEW(IDD_REPORT_NAME),
        window_,
        &ReportNameDialogProc,
        reinterpret_cast<LPARAM>(&dialogState));

    if (dialogResult == -1)
    {
        SetStatusText(L"Unable to open report dialog.");
        return;
    }

    if (dialogResult != IDOK)
    {
        SetStatusText(L"Report creation cancelled.");
        return;
    }

    std::vector<ReportSectionData> reportSections;
    for (std::size_t index = 0; index < loaded_.size(); ++index)
    {
        if (!loaded_[index])
        {
            continue;
        }

        reportSections.push_back({
            SectionLabel(index),
            sections_[index],
            collectedAt_[index]
        });
    }

    if (reportSections.empty())
    {
        SetStatusText(L"No collected sections are available for report creation.");
        UpdateReportButtonState();
        return;
    }

    const std::wstring reportDisplayName = TrimWhitespace(dialogState.reportName);
    const std::wstring safeName = SanitizeFileSystemName(reportDisplayName);
    const std::wstring appDirectory = GetExecutableDirectory();

    const std::wstring reportFolderPath = CombinePath(appDirectory, safeName);
    const std::wstring reportFilePath = CombinePath(reportFolderPath, safeName + L".html");
    if (PathExists(reportFolderPath) || PathExists(reportFilePath))
    {
        MessageBoxW(window_, L"A report with this name already exists and cannot be created again.", L"Create Report", MB_OK | MB_ICONWARNING);
        SetStatusText(L"Report already exists and was not created.");
        return;
    }

    if (!CreateDirectoryW(reportFolderPath.c_str(), nullptr))
    {
        SetStatusText(L"Unable to create report folder.");
        return;
    }

    const std::wstring html = BuildReportHtml(reportDisplayName, reportSections);

    std::wstring errorMessage;
    if (!WriteUtf8File(reportFilePath, html, errorMessage))
    {
        SetStatusText(errorMessage);
        return;
    }

    SetStatusText(L"Report created successfully.");
}

void MainWindow::UpdateSectionButtons()
{
    for (std::size_t index = 0; index < sectionButtons_.size(); ++index)
    {
        HWND button = sectionButtons_[index];
        if (button == nullptr)
        {
            continue;
        }

        const bool isSelected = index == selectedSectionIndex_;
        const bool isEncryptionButton = index == Sothoth::Core::ToIndex(Sothoth::Core::ForensicSection::BitLocker);
        EnableWindow(button, !isEncryptionButton || IsEncryptionAvailable());
        SendMessageW(button, BM_SETSTYLE, isSelected ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON, TRUE);
    }
}

void MainWindow::UpdateOutputForSelectedSection()
{
    const bool hasLoadedContent = std::any_of(loaded_.begin(), loaded_.end(), [](bool loaded) { return loaded; });
    const bool showInitialPlaceholder =
        !hasLoadedContent &&
        !isCollecting_ &&
        selectedSectionIndex_ >= Sothoth::Core::kForensicSectionCount;

    ShowWindow(placeholderLabel_, showInitialPlaceholder ? SW_SHOW : SW_HIDE);

    if (selectedSectionIndex_ >= Sothoth::Core::kForensicSectionCount)
    {
        ShowWindow(outputControl_, SW_HIDE);
        return;
    }

    if (loaded_[selectedSectionIndex_])
    {
        SetWindowTextW(outputControl_, sections_[selectedSectionIndex_].c_str());
        ShowWindow(outputControl_, SW_SHOW);
        return;
    }

    ShowWindow(outputControl_, SW_HIDE);
}

void MainWindow::SetStatusText(const std::wstring& baseText)
{
    const std::wstring privilegeState = Sothoth::App::BuildPrivilegeStateText(isElevated_);
    const std::wstring text = baseText.empty() ? privilegeState : baseText + L" | " + privilegeState;
    SetWindowTextW(statusLabel_, text.c_str());
}

bool MainWindow::IsEncryptionAvailable() const
{
#ifdef _WIN64
    return isElevated_;
#else
    return false;
#endif
}
