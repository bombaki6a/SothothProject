#include "ReportNameDialog.h"
#include "Resource.h"
#include <CommCtrl.h>
#include <cwctype>
#include <iterator>

namespace
{
constexpr wchar_t kReportNamePlaceholderText[] = L"Choose report name";
struct ReportNameDialogState
{
    std::wstring reportName;
};

/// Trims surrounding whitespace before comparing or displaying a collected value.
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
} // namespace

/// Processes name edits and confirmation while preserving the caller's cancellation choice.
INT_PTR CALLBACK ReportNameDialog::DialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM lParam)
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

/// Opens the name prompt and returns the accepted value to the caller.
bool ReportNameDialog::Show(HINSTANCE instance, HWND owner, std::wstring& name)
{
    ReportNameDialogState state{name};
    const INT_PTR result = DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_REPORT_NAME),
        owner, DialogProc, reinterpret_cast<LPARAM>(&state));
    if (result == -1)
        MessageBoxW(owner, L"Unable to open report name dialog.", L"Tenta Trace", MB_OK | MB_ICONERROR);
    if (result != IDOK) return false;
    name = std::move(state.reportName);
    return true;
}
