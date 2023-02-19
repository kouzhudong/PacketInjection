#include "CommunicationThread.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOLEAN IsKernelDebuggerEnabled()
/*
参考：\win2k\trunk\private\ntos\w32\ntcon\server\input.c的InputExceptionFilter函数。
*/
{
    NTSTATUS Status;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION KernelDebuggerInfo = {0};

    HMODULE hModule = GetModuleHandle(TEXT("ntdll.dll"));
    if (NULL == hModule) {
        return KernelDebuggerInfo.KernelDebuggerEnabled;
    }

    NtQuerySystemInformation_PFN NtQuerySystemInformation = (NtQuerySystemInformation_PFN)GetProcAddress(hModule, "NtQuerySystemInformation");
    if (NULL == NtQuerySystemInformation) {
        return KernelDebuggerInfo.KernelDebuggerEnabled;
    }

    Status = NtQuerySystemInformation(SystemKernelDebuggerInformation, &KernelDebuggerInfo, sizeof(KernelDebuggerInfo), NULL);
    if (!NT_SUCCESS(Status)) {
        return KernelDebuggerInfo.KernelDebuggerEnabled;
    }

    return KernelDebuggerInfo.KernelDebuggerEnabled;
}


VOID Usage(TCHAR* exe)
/*++
Routine Description
    Prints usage
--*/
{
    printf("本程序的用法如下：\r\n");
}


int _cdecl wmain(_In_ int argc, _In_reads_(argc) TCHAR * argv[])
{
    if (IsDebuggerPresent() || IsKernelDebuggerEnabled()) {
        __debugbreak();//DebugBreak();
    }

    setlocale(LC_CTYPE, ".936");//解决汉字显示的问题。

    switch (argc) {
    case 1:
        work();
        break;
    default:
        Usage(argv[0]);
        break;
    }
}
