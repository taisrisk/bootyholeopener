#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include "definitions.h"

SYSTEM_HANDLE_INFORMATION* hInfo;
HANDLE procHandle = NULL;
HANDLE hProcess = NULL;
HANDLE HijackedHandle = NULL;

OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security) {
    OBJECT_ATTRIBUTES object;
    object.Length = sizeof(OBJECT_ATTRIBUTES);
    object.ObjectName = name;
    object.Attributes = attributes;
    object.RootDirectory = hRoot;
    object.SecurityDescriptor = security;
    object.SecurityQualityOfService = NULL;
    return object;
}

DWORD GetPID(LPCSTR procName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap && hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnap, &procEntry)) {
            do {
                if (lstrcmpiA(procEntry.szExeFile, procName) == 0) {
                    DWORD pid = procEntry.th32ProcessID;
                    CloseHandle(hSnap);
                    return pid;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
        CloseHandle(hSnap);
    }
    return 0;
}

bool IsHandleValid(HANDLE handle) {
    return (handle && handle != INVALID_HANDLE_VALUE);
}

void CleanUpAndExit(LPCSTR ErrorMessage) {
    if (hInfo)
        delete[] hInfo;

    if (procHandle)
        CloseHandle(procHandle);

    std::cout << ErrorMessage << std::endl;
    std::cin.get();
}

HANDLE HijackExistingHandle(DWORD dwTargetProcessId) {
    HMODULE Ntdll = GetModuleHandleA("ntdll");

    _RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(Ntdll, "RtlAdjustPrivilege");
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(Ntdll, "NtQuerySystemInformation");
    _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(Ntdll, "NtDuplicateObject");
    _NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(Ntdll, "NtOpenProcess");
    BOOLEAN OldPriv;
    RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv);

    OBJECT_ATTRIBUTES Obj_Attribute = InitObjectAttributes(NULL, 0, NULL, NULL); // if u r wondering this inits structures
    CLIENT_ID clientID = { 0 };

    DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
    hInfo = (SYSTEM_HANDLE_INFORMATION*) new byte[size];
    ZeroMemory(hInfo, size);

    NTSTATUS NtRet = NULL;
    do {
        delete[] hInfo;
        size = (DWORD)(size * 1.5);

        try {
            hInfo = (PSYSTEM_HANDLE_INFORMATION) new byte[size];
        }
        catch (std::bad_alloc) {
            CleanUpAndExit("bad heap alloc");
            return NULL;
        }
        Sleep(1);
    } while ((NtRet = NtQuerySystemInformation(SystemHandleInformation, hInfo, size, NULL)) == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(NtRet)) {
        CleanUpAndExit("NtQuerySystemInformation 1");
        return NULL;
    }

    for (unsigned int i = 0; i < hInfo->HandleCount; ++i) {
        static DWORD NumOfOpenHandles;
        GetProcessHandleCount(GetCurrentProcess(), &NumOfOpenHandles);

        if (NumOfOpenHandles > 64) {
            CleanUpAndExit("handle leak");
            return NULL;
        }

        if (!IsHandleValid((HANDLE)hInfo->Handles[i].Handle))
            continue;

        if (hInfo->Handles[i].ObjectTypeNumber != ProcessHandleType)
            continue;

        clientID.UniqueProcess = (PVOID)(ULONG_PTR)hInfo->Handles[i].ProcessId;

        if (procHandle)
            CloseHandle(procHandle);

        NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE, &Obj_Attribute, &clientID);
        if (!IsHandleValid(procHandle) || !NT_SUCCESS(NtRet))
            continue;

        // dupe handle
        NtRet = NtDuplicateObject(procHandle, (HANDLE)hInfo->Handles[i].Handle, NtCurrentProcess, &HijackedHandle, PROCESS_ALL_ACCESS, 0, 0);
        if (!IsHandleValid(HijackedHandle) || !NT_SUCCESS(NtRet))
            continue;

        // verif handle points to what we want and u ofc will use it for roblox
        if (GetProcessId(HijackedHandle) != dwTargetProcessId) {
            CloseHandle(HijackedHandle);
            HijackedHandle = NULL;
            continue;
        }

        hProcess = HijackedHandle;
        break;
    }

    CleanUpAndExit("Success");
    return hProcess;
}