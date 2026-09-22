#include "framework.h"

#include "ElevationService.h"
#include "MainWindow.h"

/// Attempts elevation, runs the initial report workflow, and dispatches the results window.
int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE previousInstance, _In_ LPWSTR commandLine, _In_ int showCommand)
{
    UNREFERENCED_PARAMETER(previousInstance);

    if (Sothoth::App::TryRelaunchElevatedAndExitCurrentIfAccepted(commandLine))
    {
        return 0;
    }

    const bool isElevated = Sothoth::App::CurrentProcessHasAdministratorRights();

    MainWindow mainWindow(instance, isElevated);
    if (!mainWindow.Create(showCommand))
    {
        return FALSE;
    }

    return mainWindow.MessageLoop();
}
