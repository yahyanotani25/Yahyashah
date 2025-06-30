/*
 * com_handler_regsvr.c (final enhanced)
 *
 * Simple COM DLL that pops a message box when loaded (for demo purposes).
 * Exports DllRegisterServer so it can be registered via regsvr32 or via COM hijack.
 *
 * Compile (MinGW-w64):
 *   x86_64-w64-mingw32-gcc com_handler_regsvr.c -o com_handler.dll -shared -Wl,--kill-at
 */

#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "Bismillah COM Hijack Triggered!", "Alert", MB_OK | MB_ICONWARNING);
            break;
        case DLL_PROCESS_DETACH:
            break;
        default:
            break;
    }
    return TRUE;
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void)
{
    /* Registration stub: nothing to register for this demo */
    return S_OK;
}

__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void)
{
    /* Unregistration stub */
    return S_OK;
}
