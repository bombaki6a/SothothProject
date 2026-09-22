#pragma once

#include <array>
#include <string>

#include "framework.h"
#include "../Core/Reports/CollectionReport.h"

class MainWindow
{
public:
    /// Stores application instance and privilege information.
    MainWindow(HINSTANCE instance, bool isElevated);
    /// Releases owned GUI resources.
    ~MainWindow();

    /// Runs the startup workflow, then creates the results window only after collection has finished.
    bool Create(int showCommand);
    /// Dispatches native window messages until the results window closes.
    int MessageLoop() const;

private:
    /// Associates the native window with its C++ owner and forwards messages to the instance.
    static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam);

    /// Handles result navigation, layout, minimum sizing, and application shutdown.
    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    /// Registers the results window class with the application icon and default cursor.
    bool RegisterWindowClass();
    /// Creates the read-only result display and category navigation using the established visual style.
    void CreateControls();
    /// Sizes the result area and removes the navigation row when only one category was selected.
    void LayoutControls();
    /// Displays an already collected category without running additional system queries.
    void SelectSection(std::size_t index);
    /// Shows navigation only for multiple selected categories and marks the active one.
    void UpdateSectionButtons();
    /// Copies the selected snapshot to the read-only output control.
    void UpdateOutputForSelectedSection();
    /// Combines report status with the process privilege indicator.
    void SetStatusText(const std::wstring& baseText);

    Sothoth::Core::CollectionReport report_;
    HINSTANCE instance_ = nullptr;
    HWND window_ = nullptr;
    HWND statusLabel_ = nullptr;
    HWND outputControl_ = nullptr;
    std::array<HWND, Sothoth::Core::kForensicSectionCount> sectionButtons_{};
    HFONT monoFont_ = nullptr;
    HMODULE richEditModule_ = nullptr;
    bool isElevated_ = false;
    std::size_t selectedSectionIndex_ = Sothoth::Core::kForensicSectionCount;
    int minWindowWidth_ = 900;
    int minWindowHeight_ = 750;
    std::wstring title_;
    std::wstring className_;
};
