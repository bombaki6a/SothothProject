#include "MainWindow.h"

#include "ElevationService.h"
#include "Resource.h"
#include "StartupDialog.h"

#include <algorithm>
#include <array>
#include <CommCtrl.h>
#include <richedit.h>
#include <string>

namespace
{
constexpr int kMargin = 12;
constexpr int kStatusLabelId = 1002;
constexpr int kOutputControlId = 1004;
constexpr int kSectionButtonBaseId = 1100;
constexpr int kCategoryButtonHeight = 42;
constexpr int kButtonGap = 8;
constexpr int kInitialWindowWidth = 900;
constexpr int kInitialWindowHeight = 750;

constexpr wchar_t kDefaultWindowTitle[] = L"Tenta Trace";
constexpr wchar_t kDefaultWindowClass[] = L"SothothForensicCollectorWindow";

} // namespace

using Sothoth::Core::SectionLabel;
using Sothoth::Core::kSectionLabels;

/// Stores process context and loads the application title and native class name.
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

/// Releases fonts and the dynamically loaded Rich Edit module after the window closes.
MainWindow::~MainWindow()
{
    if (monoFont_ != nullptr)
    {
        DeleteObject(monoFont_);
        monoFont_ = nullptr;
    }

    if (richEditModule_ != nullptr)
    {
        FreeLibrary(richEditModule_);
        richEditModule_ = nullptr;
    }
}

/// Runs the startup workflow, then creates the results window only after collection has finished.
bool MainWindow::Create(int showCommand)
{
    StartupDialog startup(instance_, isElevated_, report_);
    if (!startup.Show()) return false;

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

    for (std::size_t i = 0; i < report_.loaded.size(); ++i)
    {
        if (report_.loaded[i]) { selectedSectionIndex_ = i; break; }
    }
    UpdateSectionButtons();
    LayoutControls();
    UpdateOutputForSelectedSection();
    SetStatusText(report_.saved ? L"Report created successfully." : L"Report was not saved.");
    ShowWindow(window_, showCommand);
    UpdateWindow(window_);
    return true;
}

/// Dispatches native window messages until the results window closes.
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

/// Associates the native window with its C++ owner and forwards messages to the instance.
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

/// Handles result navigation, layout, minimum sizing, and application shutdown.
LRESULT MainWindow::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        CreateControls();
        LayoutControls();
        SetStatusText(L"");
        UpdateSectionButtons();
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

        break;
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

/// Registers the results window class with the application icon and default cursor.
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

/// Creates the read-only result display and category navigation using the established visual style.
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
    }

    ShowWindow(outputControl_, SW_HIDE);
}

/// Sizes the result area and removes the navigation row when only one category was selected.
void MainWindow::LayoutControls()
{
    if (statusLabel_ == nullptr || outputControl_ == nullptr)
    {
        return;
    }

    RECT clientRect{};
    GetClientRect(window_, &clientRect);

    const int clientWidth = clientRect.right - clientRect.left;
    const int clientHeight = clientRect.bottom - clientRect.top;

    MoveWindow(statusLabel_, kMargin, kMargin + 4, clientWidth - (kMargin * 2), 22, TRUE);

    const int buttonRowY = kMargin + 34;
    const int count = (std::max)(1, static_cast<int>(std::count(report_.selected.begin(), report_.selected.end(), true)));
    const int totalGapWidth = kButtonGap * (count - 1);
    const int buttonWidth = (std::max)(120, (clientWidth - (kMargin * 2) - totalGapWidth) / count);

    int buttonX = kMargin;
    for (std::size_t i = 0; i < sectionButtons_.size(); ++i)
    {
        HWND button = sectionButtons_[i];
        if (!report_.selected[i]) continue;
        if (button != nullptr)
        {
            MoveWindow(button, buttonX, buttonRowY, buttonWidth, kCategoryButtonHeight, TRUE);
        }
        buttonX += buttonWidth + kButtonGap;
    }

    const int outputY = count > 1 ? buttonRowY + kCategoryButtonHeight + kMargin : buttonRowY;
    const int outputHeight = (std::max)(160, clientHeight - kMargin - outputY);
    MoveWindow(outputControl_, kMargin, outputY, clientWidth - (kMargin * 2), outputHeight, TRUE);
}

/// Displays an already collected category without running additional system queries.
void MainWindow::SelectSection(std::size_t index)
{
    if (index >= report_.loaded.size() || !report_.loaded[index]) return;
    selectedSectionIndex_ = index;
    UpdateSectionButtons();
    UpdateOutputForSelectedSection();
}

/// Shows navigation only for multiple selected categories and marks the active one.
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
        const bool showCategories = std::count(report_.selected.begin(), report_.selected.end(), true) > 1;
        ShowWindow(button, showCategories && report_.selected[index] ? SW_SHOW : SW_HIDE);
        EnableWindow(button, report_.loaded[index]);
        SendMessageW(button, BM_SETSTYLE, isSelected ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON, TRUE);
    }
}

/// Copies the selected snapshot to the read-only output control.
void MainWindow::UpdateOutputForSelectedSection()
{
    if (selectedSectionIndex_ >= Sothoth::Core::kForensicSectionCount)
    {
        ShowWindow(outputControl_, SW_HIDE);
        return;
    }

    if (report_.loaded[selectedSectionIndex_])
    {
        SetWindowTextW(outputControl_, report_.sections[selectedSectionIndex_].c_str());
        ShowWindow(outputControl_, SW_SHOW);
        return;
    }

    ShowWindow(outputControl_, SW_HIDE);
}

/// Combines report status with the process privilege indicator.
void MainWindow::SetStatusText(const std::wstring& baseText)
{
    const std::wstring privilegeState = Sothoth::App::BuildPrivilegeStateText(isElevated_);
    const std::wstring text = baseText.empty() ? privilegeState : baseText + L" | " + privilegeState;
    SetWindowTextW(statusLabel_, text.c_str());
}
