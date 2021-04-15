#include "CommunicationPort.h"
#include "..\public\public.h"


DATA g_Data;//  Structure that contains all the global data structures used throughout the scanner.


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
/*
没有FltStartFiltering这个函数不会被调用。
*/
{
    //NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Flags);

    if (NULL != g_Data.ServerPort) {
        FltCloseCommunicationPort(g_Data.ServerPort);//  Close the server port.  
    }

    if (NULL != g_Data.Filter) {
        FltUnregisterFilter(g_Data.Filter);//  Unregister the filter
    }

    return STATUS_SUCCESS;
}


NTSTATUS InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                       _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                       _In_ DEVICE_TYPE VolumeDeviceType,
                       _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);
#pragma alloc_text(PAGE, InstanceSetup)
NTSTATUS InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                       _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                       _In_ DEVICE_TYPE VolumeDeviceType,
                       _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    return status;//status STATUS_SUCCESS
}


NTSTATUS QueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}


FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,                //  Context Registration.
    NULL,                          //  Operation callbacks
    Unload,                             //  FilterUnload
    InstanceSetup,                      //  InstanceSetup
    QueryTeardown,                      //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent
};


//////////////////////////////////////////////////////////////////////////////////////////////////


LONG ExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionPointer, _In_ BOOLEAN AccessingUserBuffer)
/*++
Routine Description:
Exception filter to catch errors touching user buffers.

Arguments:
ExceptionPointer - The exception record.
AccessingUserBuffer - If TRUE, overrides FsRtlIsNtStatusExpected to allow the caller to munge the error to a desired status.

Return Value:
EXCEPTION_EXECUTE_HANDLER - If the exception handler should be run.
EXCEPTION_CONTINUE_SEARCH - If a higher exception handler should take care of this exception.
--*/
{
    NTSTATUS Status;

    Status = ExceptionPointer->ExceptionRecord->ExceptionCode;

    //  Certain exceptions shouldn't be dismissed within the namechanger filter unless we're touching user memory.
    if (!FsRtlIsNtstatusExpected(Status) && !AccessingUserBuffer) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_EXECUTE_HANDLER;
}


NTSTATUS PortConnect(_In_ PFLT_PORT ClientPort,
                     _In_opt_ PVOID ServerPortCookie,
                     _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                     _In_ ULONG SizeOfContext,
                     _Outptr_result_maybenull_ PVOID * ConnectionCookie
);
#pragma alloc_text(PAGE, PortConnect)
NTSTATUS PortConnect(_In_ PFLT_PORT ClientPort,
                     _In_opt_ PVOID ServerPortCookie,
                     _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                     _In_ ULONG SizeOfContext,
                     _Outptr_result_maybenull_ PVOID * ConnectionCookie
)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

#if defined(_WIN64)
    if (IoIs32bitProcess(NULL)) {
        return STATUS_UNSUCCESSFUL;
    }
#endif

    FLT_ASSERT(g_Data.ClientPort == NULL);
    FLT_ASSERT(g_Data.UserProcess == NULL);

    g_Data.UserProcess = PsGetCurrentProcess();
    g_Data.ClientPort = ClientPort;

    return STATUS_SUCCESS;
}


VOID PortDisconnect(_In_opt_ PVOID ConnectionCookie);
#pragma alloc_text(PAGE, PortDisconnect)
VOID PortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    PAGED_CODE();

    FltCloseClientPort(g_Data.Filter, &g_Data.ClientPort);//这个函数会把第二个参数设置为0.

    //g_Data.UserProcess = NULL;//  Reset the user-process field.
    InterlockedExchangePointer(&g_Data.UserProcess, NULL);
}


NTSTATUS MessageNotifyCallback(
    IN PVOID PortCookie,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,//用户可以接受的数据的最大长度.
    OUT PULONG ReturnOutputBufferLength//用户实际接收的数据大小，和OutputBuffer应该一致。
);
#pragma alloc_text(PAGE, MessageNotifyCallback)
NTSTATUS MessageNotifyCallback(
    IN PVOID PortCookie,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,//用户可以接受的数据的最大长度.
    OUT PULONG ReturnOutputBufferLength//用户实际接收的数据大小，和OutputBuffer应该一致。
)
/*
Routine Description:
This is called whenever a user mode application wishes to communicate with this minifilter.

Arguments:
ConnectionCookie - unused
OperationCode - An identifier describing what type of message this is.  These codes are defined by the MiniFilter.
InputBuffer - A buffer containing input data, can be NULL if there is no input data.
InputBufferSize - The size in bytes of the InputBuffer.
OutputBuffer - A buffer provided by the application that originated the communication in which to store data to be returned to this application.
OutputBufferSize - The size in bytes of the OutputBuffer.
ReturnOutputBufferSize - The size in bytes of meaningful data returned in the OutputBuffer.

Return Value:
Returns the status of processing the message.

//                      **** PLEASE READ ****
//
//  The INPUT and OUTPUT buffers are raw user mode addresses.
//  The filter manager has already done a ProbedForRead (on InputBuffer) and
//  ProbedForWrite (on OutputBuffer) which guarentees they are valid addresses based on the access (user mode vs. kernel mode).
//  The minifilter does not need to do their own probe.
//
//  The filter manager is NOT doing any alignment checking on the pointers.
//  The minifilter must do this themselves if they care (see below).
//
//  The minifilter MUST continue to use a try/except around any access to these buffers.

这里要注意:1.数据地址的对齐.
2.文档建议使用:try/except处理.
3.如果是64位的驱动要考虑32位的EXE发来的请求（IoIs32bitProcess）.
这里规定：传递过来的是一个结构，结构的第一个成员是int，也就是自定义的消息的类别。
*/
{
    NTSTATUS status = STATUS_SUCCESS;
    int command;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);

#if defined(_WIN64)
    if (IoIs32bitProcess(NULL)) {
        return STATUS_INVALID_PARAMETER;

        ////  Validate alignment for the 32bit process on a 64bit system
        //if (!IS_ALIGNED(OutputBuffer, sizeof(ULONG))) {
        //    status = STATUS_DATATYPE_MISALIGNMENT;   
        //    return status;
        //}
    }
#endif

    __try {//  Probe and capture input message: the message is raw user mode buffer, so need to protect with exception handler
        command = ((PCOMMAND_MESSAGE)InputBuffer)->Command;
    } __except (ExceptionFilter(GetExceptionInformation(), TRUE)) {
        return GetExceptionCode();
    }

    switch (command) {
        //case PASS_PID://获取用户的传来的PID，应该放入一个链表里面。
        //    status = save_pid(InputBuffer);
        //    break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS CreateCommunicationPort(_In_ PDRIVER_OBJECT DriverObject)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING uniString;
    PSECURITY_DESCRIPTOR sd;
    NTSTATUS status;

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_Data.Filter);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "错误：status:%#x", status);
        return status;
    }

    RtlInitUnicodeString(&uniString, g_PortName);

    //  We secure the port so only ADMINs & SYSTEM can acecss it.
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "错误：status:%#x", status);
        FltUnregisterFilter(g_Data.Filter);
        return status;
    } 

    InitializeObjectAttributes(&oa, &uniString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);
    status = FltCreateCommunicationPort(g_Data.Filter,
                                        &g_Data.ServerPort,
                                        &oa,
                                        NULL,
                                        PortConnect,
                                        PortDisconnect,
                                        MessageNotifyCallback,
                                        1);
    //  Free the security descriptor in all cases.
    //  It is not needed once the call to FltCreateCommunicationPort() is made.    
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "错误：status:%#x", status);
        FltUnregisterFilter(g_Data.Filter);
    }

    FltFreeSecurityDescriptor(sd);

    return status;
}
