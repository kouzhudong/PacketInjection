#pragma once

#include "DriverEntry.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
关于UserProcess的一点说明：
防止进程被非法结束。从进程被非法结束到FltCloseClientPort，这期间访问这个值会出问题。
解决办法是：
1.进程回调监控这个进程的退出，且对这个值进行原子操作。
2.ExInitializeRundownProtection系列函数。没用过，好些也不能解决。因为进程的这个成员地址是未知的，因为进程对象未公开。
*/
typedef struct _DATA {
    PDRIVER_OBJECT DriverObject;//  The object that identifies this driver.
    PFLT_FILTER Filter;//  The filter handle that results from a call to FltRegisterFilter.
    PFLT_PORT ServerPort;//  Listens for incoming connections
    PEPROCESS UserProcess;//  User process that connected to the port 
    PFLT_PORT ClientPort;//  Client port for a connection to user-mode
} DATA, * PDATA;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern DATA g_Data;

NTSTATUS CreateCommunicationPort(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
