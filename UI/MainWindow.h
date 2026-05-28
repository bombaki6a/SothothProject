#pragma once

#include <array>
#include <string>

#include "framework.h"
#include "ForensicCollector.h"

class MainWindow
{
public:
    MainWindow(HINSTANCE instance, bool isElevated);
    ~MainWindow();

    bool Create(int showCommand);
    int MessageLoop() const;

private:
    static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam);

    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    bool RegisterWindowClass();
    void CreateControls();
    void LayoutControls();
    void SelectSection(std::size_t index);
    void StartCollectionForSection(std::size_t index);
    bool CanCreateReport() const;
    void UpdateReportButtonState();
    void CreateReport();
    void UpdateSectionButtons();
    void UpdateOutputForSelectedSection();
    void SetStatusText(const std::wstring& baseText);
    bool IsEncryptionAvailable() const;

    HINSTANCE instance_ = nullptr;
    HWND window_ = nullptr;
    HWND statusLabel_ = nullptr;
    HWND placeholderLabel_ = nullptr;
    HWND outputControl_ = nullptr;
    HWND reportButton_ = nullptr;
    std::array<HWND, Sothoth::Core::kForensicSectionCount> sectionButtons_{};
    HFONT monoFont_ = nullptr;
    HFONT placeholderFont_ = nullptr;
    HMODULE richEditModule_ = nullptr;
    bool isCollecting_ = false;
    bool isElevated_ = false;
    std::size_t selectedSectionIndex_ = Sothoth::Core::kForensicSectionCount;
    std::size_t collectingSectionIndex_ = Sothoth::Core::kForensicSectionCount;
    std::array<std::wstring, Sothoth::Core::kForensicSectionCount> sections_{};
    std::array<std::wstring, Sothoth::Core::kForensicSectionCount> collectedAt_{};
    std::array<bool, Sothoth::Core::kForensicSectionCount> loaded_{};
    std::array<bool, Sothoth::Core::kForensicSectionCount> loading_{};
    int minWindowWidth_ = 900;
    int minWindowHeight_ = 750;
    std::wstring title_;
    std::wstring className_;
};
