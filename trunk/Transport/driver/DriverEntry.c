#include "DriverEntry.h"
#include "communication.h"
#include "wfp.h"
#include "SystemThread.h"
#include "CommunicationPort.h"
#include "process.h"

//#include "trace.h"
//#include "DriverEntry.tmh"

UNICODE_STRING g_SymbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\Inject");
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Inject");

LONG gDriverUnloading = FALSE;//为TRUE时就不再接受各个消息了

PDEVICE_OBJECT g_deviceObject;

void * gThreadObj[MAXIMUM_WAIT_OBJECTS];

KWAIT_BLOCK g_WaitBlockArray[MAXIMUM_WAIT_OBJECTS];//The WaitBlockArray buffer must reside in nonpaged system memory. 


//////////////////////////////////////////////////////////////////////////////////////////////////


DRIVER_UNLOAD DriverUnload;
#pragma alloc_text(PAGE, DriverUnload)
//#pragma PAGEDCODE
//#pragma  code_seg("PAGE")
_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID DriverUnload(_In_ struct _DRIVER_OBJECT * DriverObject)
/*
会出现：显示卸载成功了，但是驱动模块还在内存中，所以再次启动会启动失败。
同时，这个文件在Windows 10上也删除不掉，但可以改名。
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    char ThreadNumbers = min(KeNumberProcessors, MAXIMUM_WAIT_OBJECTS);

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    InterlockedIncrement(&gDriverUnloading);
    KeSetEvent(&g_PacketEvent, IO_NO_INCREMENT, FALSE);//唤醒等待中的工作线程，使其退出。

    //先等工作线程退出，确保没有线程还在IsBlockPacker的FltSendMessage里使用g_Data.Filter，
    //之后再拆WFP和通信端，否则worker会使用已释放的filter，造成use-after-free。
    ThreadNumbers = 1;
    status = KeWaitForMultipleObjects(ThreadNumbers, gThreadObj, WaitAll, Executive, KernelMode, FALSE, NULL, &g_WaitBlockArray[0]);
    switch (status) {
    case STATUS_SUCCESS:
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "信息：KeWaitForMultipleObjects %s", "STATUS_SUCCESS");
        break;
    case STATUS_ALERTED:
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "警告：KeWaitForMultipleObjects  %s", "STATUS_ALERTED");
        break;
    case STATUS_USER_APC:
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "警告：KeWaitForMultipleObjects  %s", "STATUS_USER_APC");
        break;
    case STATUS_TIMEOUT:
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "警告：KeWaitForMultipleObjects  %s", "STATUS_TIMEOUT");
        break;
    default:
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "错误：status:%#x", status);
        break;
    }

    for (CCHAR i = 0; i < ThreadNumbers; i++) {
        if (NULL != gThreadObj[i]) {
            ObDereferenceObject(gThreadObj[i]);
        }
    }

    StopWFP();//注销callout、移除flow、销毁注入句柄。此时worker已退出，安全。
    Unload(0);//注销进程回调、关闭通信端、注销过滤器。此时worker不再使用filter，消除竞态。

    IoDeleteSymbolicLink(&g_SymbolicLinkName);
    IoDeleteDevice(g_deviceObject);
}


DRIVER_INITIALIZE DriverEntry;
//#pragma INITCODE
#pragma alloc_text(INIT, DriverEntry)
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE threadHandle = NULL;
    char ThreadNumbers = min(KeNumberProcessors, MAXIMUM_WAIT_OBJECTS);

    UNREFERENCED_PARAMETER(pRegistryPath);

    if (!KD_DEBUGGER_NOT_PRESENT) {
        KdBreakPoint();
    }

    PAGED_CODE();

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    InitializeListHead(&g_PacketList);
    KeInitializeSpinLock(&g_PacketListLock);
    KeInitializeEvent(&g_PacketEvent, SynchronizationEvent, FALSE);//工作线程的包到达信号，必须在注册回调前初始化。

    InitializeListHead(&g_flowContextList);
    KeInitializeSpinLock(&g_flowContextListLock);

    PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "信息：FUNCTION:%ls", _CRT_WIDE(__FUNCTION__));

    __try {
        status = IoCreateDevice(pDriverObject,
                                0,
                                &g_DeviceName,
                                FILE_DEVICE_UNKNOWN,
                                FILE_DEVICE_SECURE_OPEN,
                                TRUE,/*独占式设备,同一时刻只有一个句柄打开此设备*/
                                &g_deviceObject);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "错误：status:%#x", status);
            __leave;
        }

        status = IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "错误：status:%#x", status);
            __leave;
        }

        status = CreateCommunicationPort(pDriverObject);
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "status:%#x", status);
            __leave;
        }

        status = StartWFP();
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        ThreadNumbers = 1;
        for (CCHAR i = 0; i < ThreadNumbers; i++) {
            status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkThread, NULL);
            if (!NT_SUCCESS(status)) {
                PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "PsCreateSystemThread status:%#x", status);
                __leave;
            }
            status = ObReferenceObjectByHandle(threadHandle, 0, NULL, KernelMode, &gThreadObj[i], NULL);
            ZwClose(threadHandle);
            if (!NT_SUCCESS(status)) {
                PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "ObReferenceObjectByHandle status:%#x", status);
                gThreadObj[i] = NULL;
                __leave;
            }
        }
    } __finally {
        if (!NT_SUCCESS(status)) {
            //终止可能已创建的工作线程并等待其退出，防止驱动卸载后线程仍在运行。
            InterlockedIncrement(&gDriverUnloading);
            KeSetEvent(&g_PacketEvent, IO_NO_INCREMENT, FALSE);
            for (CCHAR i = 0; i < ThreadNumbers; i++) {
                if (NULL != gThreadObj[i]) {
                    KeWaitForSingleObject(gThreadObj[i], Executive, KernelMode, FALSE, NULL);
                    ObDereferenceObject(gThreadObj[i]);
                    gThreadObj[i] = NULL;
                }
            }

            StopWFP();//可调用（幂等）。若StartWFP已成功，会注销callout/解除BFE订阅。
            Unload(0);//注销进程回调、关闭通信端。

            if (g_SymbolicLinkName.Length) {
                IoDeleteSymbolicLink(&g_SymbolicLinkName);
            }

            if (g_deviceObject) {
                IoDeleteDevice(g_deviceObject);
            }
        }
    }

    PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "信息：status:%#x", status);

    pDriverObject->DriverUnload = DriverUnload;

    return status;
}
