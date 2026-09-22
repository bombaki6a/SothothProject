#include "StartupDialog.h"
#include "ReportNameDialog.h"
#include "Resource.h"
#include "../Core/Reports/ReportWriter.h"
#include <algorithm>
#include <process.h>

using namespace Sothoth::Core;

namespace
{
constexpr UINT kCollectionProgressMessage = WM_APP + 1;
}

/// Binds the dialog to the report that will later be displayed by the main window.
StartupDialog::StartupDialog(HINSTANCE instance, bool isElevated, CollectionReport& report)
    : instance_(instance), isElevated_(isElevated), report_(report)
{
}

/// Keeps all initial interaction inside a modal dialog until the report has been processed.
bool StartupDialog::Show()
{
    const INT_PTR result = DialogBoxParamW(instance_, MAKEINTRESOURCEW(IDD_STARTUP),
        nullptr, DialogProc, reinterpret_cast<LPARAM>(this));
    startupDialog_ = nullptr;
    if (result == -1)
        MessageBoxW(nullptr, L"Unable to open startup dialog.", L"Tenta Trace", MB_OK | MB_ICONERROR);
    return result == IDOK;
}

/// Rejects existing destinations before beginning collection; cancellation returns to category selection.
bool StartupDialog::ChooseReportName(HWND owner)
{
    std::wstring name;
    while (ReportNameDialog::Show(instance_, owner, name))
    {
        if (ReportWriter::Exists(name))
        {
            MessageBoxW(owner, L"A report with this name already exists.", L"Create Report", MB_OK | MB_ICONWARNING);
            continue;
        }
        report_.name = std::move(name);
        return true;
    }
    return false;
}

/// Retains collected snapshots when saving fails so a different destination can be tried.
bool StartupDialog::SaveReport()
{
    std::wstring error;
    report_.saved = ReportWriter::Save(report_, error);
    if (!report_.saved)
        MessageBoxW(startupDialog_, error.c_str(), L"Create Report", MB_OK | MB_ICONERROR);
    return report_.saved;
}

/// Processes category choices and polls the worker handle before exposing its collected data to the UI.
INT_PTR CALLBACK StartupDialog::DialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam)
{
    auto* self = reinterpret_cast<StartupDialog*>(GetWindowLongPtrW(dialog, GWLP_USERDATA));
    if (message == WM_INITDIALOG)
    {
        self = reinterpret_cast<StartupDialog*>(lParam);
        SetWindowLongPtrW(dialog, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->startupDialog_ = dialog;
        RECT logoRect{};
        GetClientRect(GetDlgItem(dialog, IDC_STARTUP_LOGO), &logoRect);
        const int size = (std::min)(logoRect.right, logoRect.bottom);
        self->startupIcon_ = reinterpret_cast<HICON>(LoadImageW(self->instance_,
            MAKEINTRESOURCEW(IDI_SOTHOTHPROJECT), IMAGE_ICON, size, size, 0));
        SendDlgItemMessageW(dialog, IDC_STARTUP_LOGO, STM_SETICON, reinterpret_cast<WPARAM>(self->startupIcon_), 0);
        SendMessageW(dialog, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(LoadIconW(self->instance_, MAKEINTRESOURCEW(IDI_SOTHOTHPROJECT))));
        for (std::size_t i = 0; i < self->report_.selected.size(); ++i)
        {
            const bool available = i != Sothoth::Core::ToIndex(Sothoth::Core::ForensicSection::BitLocker) || self->IsEncryptionAvailable();
            self->report_.selected[i] = available;
            CheckDlgButton(dialog, IDC_CATEGORY_FIRST + static_cast<int>(i), available ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(GetDlgItem(dialog, IDC_CATEGORY_FIRST + static_cast<int>(i)), available);
        }
        RECT rect{}, work{};
        GetWindowRect(dialog, &rect);
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
        SetWindowPos(dialog, nullptr, work.left + (work.right - work.left - rect.right + rect.left) / 2,
            work.top + (work.bottom - work.top - rect.bottom + rect.top) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        return TRUE;
    }
    if (!self) return FALSE;
    if (message == kCollectionProgressMessage)
    {
        SetDlgItemTextW(dialog, IDC_STARTUP_STATUS, (std::wstring(L"Collecting ") + SectionLabel(wParam) + L"...").c_str());
        return TRUE;
    }
    if (message == WM_TIMER && wParam == 1 && self->collectionThread_ &&
        WaitForSingleObject(self->collectionThread_, 0) == WAIT_OBJECT_0)
    {
        KillTimer(dialog, 1);
        CloseHandle(self->collectionThread_);
        self->collectionThread_ = nullptr;
        self->isCollecting_ = false;
        SetDlgItemTextW(dialog, IDC_STARTUP_STATUS, L"Saving report...");
        bool saved = self->SaveReport();
        while (!saved && MessageBoxW(dialog, L"Retry saving with another report name? Collected results are retained.",
            L"Create Report", MB_RETRYCANCEL | MB_ICONQUESTION) == IDRETRY)
        {
            if (!self->ChooseReportName(dialog)) break;
            saved = self->SaveReport();
        }
        EndDialog(dialog, IDOK);
        return TRUE;
    }
    if (message == WM_CLOSE || (message == WM_COMMAND && LOWORD(wParam) == IDCANCEL))
    {
        if (!self->isCollecting_) EndDialog(dialog, IDCANCEL);
        return TRUE;
    }
    if (message == WM_DESTROY)
    {
        if (self->startupIcon_) { DestroyIcon(self->startupIcon_); self->startupIcon_ = nullptr; }
        return TRUE;
    }
    if (message != WM_COMMAND || self->isCollecting_) return FALSE;
    if (LOWORD(wParam) >= IDC_CATEGORY_FIRST && LOWORD(wParam) < IDC_CATEGORY_FIRST + 4)
    {
        for (std::size_t i = 0; i < self->report_.selected.size(); ++i)
            self->report_.selected[i] = IsDlgButtonChecked(dialog, IDC_CATEGORY_FIRST + static_cast<int>(i)) == BST_CHECKED;
        EnableWindow(GetDlgItem(dialog, IDOK), std::any_of(self->report_.selected.begin(), self->report_.selected.end(), [](bool v) { return v; }));
        return TRUE;
    }
    if (LOWORD(wParam) == IDOK)
    {
        if (!std::any_of(self->report_.selected.begin(), self->report_.selected.end(), [](bool v) { return v; }) ||
            !self->ChooseReportName(dialog)) return TRUE;
        if (!SetTimer(dialog, 1, 100, nullptr))
        {
            MessageBoxW(dialog, L"Unable to start collection.", L"Tenta Trace", MB_OK | MB_ICONERROR);
            return TRUE;
        }
        self->isCollecting_ = true;
        self->collectionThread_ = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0,
            [](void* parameter) -> unsigned
            {
                auto* app = static_cast<StartupDialog*>(parameter);
                Sothoth::Core::ForensicCollector collector;
                for (std::size_t i = 0; i < app->report_.selected.size(); ++i)
                {
                    if (!app->report_.selected[i]) continue;
                    PostMessageW(app->startupDialog_, kCollectionProgressMessage, i, 0);
                    try
                    {
                        app->report_.sections[i] = collector.CollectSection(static_cast<Sothoth::Core::ForensicSection>(i));
                        app->report_.collectedAt[i] = ReportWriter::FormatLocalTimestamp();
                    }
                    catch (...)
                    {
                        app->report_.sections[i] = L"Unable to collect this category.";
                    }
                    app->report_.loaded[i] = true;
                }
                return 0;
            }, self, 0, nullptr));
        if (!self->collectionThread_)
        {
            self->isCollecting_ = false;
            KillTimer(dialog, 1);
            MessageBoxW(dialog, L"Unable to start collection.", L"Tenta Trace", MB_OK | MB_ICONERROR);
            return TRUE;
        }
        for (int i = 0; i < 4; ++i) EnableWindow(GetDlgItem(dialog, IDC_CATEGORY_FIRST + i), FALSE);
        EnableWindow(GetDlgItem(dialog, IDOK), FALSE);
        EnableWindow(GetDlgItem(dialog, IDCANCEL), FALSE);
        EnableMenuItem(GetSystemMenu(dialog, FALSE), SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
        return TRUE;
    }
    return FALSE;
}

/// Enforces the supported build and elevation requirements for BitLocker collection.
bool StartupDialog::IsEncryptionAvailable() const
{
#ifdef _WIN64
    return isElevated_;
#else
    return false;
#endif
}
