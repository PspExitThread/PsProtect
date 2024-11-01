#pragma once

#include <ntifs.h>
#include <minwindef.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <intrin.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <wdf.h>
#include <Ndis.h>

ULONG ProtectionOffset = 0x87a;
ULONG UniqueProcessIdOffset = 0x440;
ULONG ApcQueueableOffset = 0x074;
ULONG ActiveProcessLinksOffset = 0x448;

#define PPL_Antimalware 0x31

EXTERN_C_START
NTSTATUS ZwAdjustPrivilegesToken(IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES NewState OPTIONAL,
    IN ULONG BufferLength OPTIONAL,
    OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    OUT PULONG ReturnLength);
NTSTATUS
ZwSetInformationProcess(
    IN HANDLE                    ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID                     ProcessInformation,
    IN ULONG                     ProcessInformationLength);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN ULONG SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
EXTERN_C_END

#define X(name, value) \
    tkp.Privileges[0].Luid = RtlConvertLongToLuid(value); \
    status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG)); \
    if (!NT_SUCCESS(status)) \
    { \
        ZwClose(hToken); \
    } \

#define PRIVILEGE_MAPPING \
    X(SE_MACHINE_ACCOUNT_PRIVILEGE, 6L) \
    X(SE_TCB_PRIVILEGE, 7L) \
    X(SE_SECURITY_PRIVILEGE, 8L) \
    X(SE_TAKE_OWNERSHIP_PRIVILEGE, 9L) \
    X(SE_LOAD_DRIVER_PRIVILEGE, 10L) \
    X(SE_SYSTEM_PROFILE_PRIVILEGE, 11L) \
    X(SE_SYSTEMTIME_PRIVILEGE, 12L) \
    X(SE_PROF_SINGLE_PROCESS_PRIVILEGE, 13L) \
    X(SE_INC_BASE_PRIORITY_PRIVILEGE, 14L) \
    X(SE_CREATE_PAGEFILE_PRIVILEGE, 15L) \
    X(SE_CREATE_PERMANENT_PRIVILEGE, 16L) \
    X(SE_BACKUP_PRIVILEGE, 17L) \
    X(SE_RESTORE_PRIVILEGE, 18L) \
    X(SE_SHUTDOWN_PRIVILEGE, 19L) \
    X(SE_DEBUG_PRIVILEGE, 20L) \
    X(SE_AUDIT_PRIVILEGE, 21L) \
    X(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, 22L) \
    X(SE_CHANGE_NOTIFY_PRIVILEGE, 23L) \
    X(SE_REMOTE_SHUTDOWN_PRIVILEGE, 24L) \
    X(SE_UNDOCK_PRIVILEGE, 25L) \
    X(SE_SYNC_AGENT_PRIVILEGE, 26L) \
    X(SE_ENABLE_DELEGATION_PRIVILEGE, 27L) \
    X(SE_MANAGE_VOLUME_PRIVILEGE, 28L) \
    X(SE_IMPERSONATE_PRIVILEGE, 29L) \
    X(SE_CREATE_GLOBAL_PRIVILEGE, 30L) \
    X(SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE, 31L) \
    X(SE_RELABEL_PRIVILEGE, 32L) \
    X(SE_INC_WORKING_SET_PRIVILEGE, 33L) \
    X(SE_TIME_ZONE_PRIVILEGE, 34L) \
    X(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, 35L) \
    X(SE_MIN_WELL_KNOWN_PRIVILEGE, 2L) \
    X(SE_CREATE_TOKEN_PRIVILEGE, 2L) \
    X(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, 3L) \
    X(SE_LOCK_MEMORY_PRIVILEGE, 4L) \
    X(SE_INCREASE_QUOTA_PRIVILEGE, 5L)


NTSTATUS GetTokenOffset()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    CLIENT_ID   ClientId = { 0 };
    OBJECT_ATTRIBUTES ob;
    HANDLE  ProcessHandle;
    HANDLE TokenHandle = 0;
    ULONG64 TokenOffset = 0;

    ClientId.UniqueProcess = PsGetCurrentProcessId();
    InitializeObjectAttributes(&ob, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenProcess(&ProcessHandle, GENERIC_ALL, &ob, &ClientId);
    ASSERT(NT_SUCCESS(Status));

    Status = ZwOpenProcessTokenEx(ProcessHandle, TOKEN_ALL_ACCESS, OBJ_KERNEL_HANDLE, &TokenHandle);
    ASSERT(NT_SUCCESS(Status));

    PVOID ProcessObject = nullptr;
    Status = ObReferenceObjectByHandle(ProcessHandle, GENERIC_ALL, *PsProcessType, KernelMode, &ProcessObject, 0);
    ASSERT(NT_SUCCESS(Status));

    PVOID TokenObject = nullptr;
    Status = ObReferenceObjectByHandle(TokenHandle, TOKEN_ALL_ACCESS, *SeTokenObjectType, KernelMode, &TokenObject, 0);
    ASSERT(NT_SUCCESS(Status));

    size_t* ProcessObjectAddress = (size_t*)ProcessObject;
    size_t TokenObjectAddress = (size_t)TokenObject;

    for (int i = 0; i < 0xa00 / sizeof(size_t); i++) {
        size_t tmp = ProcessObjectAddress[i];
        tmp = tmp & ~0xf;
        if (tmp == TokenObjectAddress) {
            TokenOffset = i * sizeof(size_t);
            break;
        }
    }

    ObDereferenceObject(ProcessObject);
    ObDereferenceObject(TokenObject);
    Status = ZwClose(TokenHandle);
    Status = ZwClose(ProcessHandle);
    return TokenOffset;
}

