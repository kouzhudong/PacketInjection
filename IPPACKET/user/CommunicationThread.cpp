#include "log.h"
#include "CommunicationThread.h"
#include "rule.h"

HANDLE g_hThread[MAXIMUM_WAIT_OBJECTS];
DWORD g_thread_count = 0;

HANDLE g_port;
HANDLE g_completion;

LONG g_SvcStop;//考虑用命名的事件对象，可跨进程操作。

PRtlIpv6AddressToString Ipv6AddressToStringW;


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD WINAPI CommunicationThread(_In_ PVOID Context)
/*
注意：
这里是典型的高并发低延迟的函数，具体体现是：
高并发：多线程，且有很多的消息发来，如：文件，进程，网络，注册表等，每秒成千上万个。
低延迟：驱动在等待，必须很快处理，否者别的进程和系统出现卡慢等现象。

所以：
这里的做法是：
大部分是纯内存操作。
尽量减少各种IO操作，如：文件，网络，注册表，进程和进入内核的函数。
尽量减少密集型的CPU操作，如：各种哈希值的计算。
各种锁要处理好，避免死锁。

基于以上的结论：
1.警告日志的上传要另开一个线程，因为这里有网络操作，特别是同步的。
2.减少日志的打印，包括debugview的。
3.不能等待别人，只有别人等待这里。
*/
{
    PMESSAGE message = NULL;
    HRESULT hr = S_OK;

    UNREFERENCED_PARAMETER(Context);

    LOGW(IMPORTANT_INFO_LEVEL, "FUNCTION:%ls, tid:%d", _CRT_WIDE(__FUNCTION__), GetCurrentThreadId());

    for (;;) {
        LPOVERLAPPED pOvlp;
        DWORD outSize;
        ULONG_PTR key;
        BOOL result = GetQueuedCompletionStatus(g_completion, &outSize, &key, &pOvlp, INFINITE);
        message = CONTAINING_RECORD(pOvlp, MESSAGE, Ovlp);
        if (!result) {
            hr = HRESULT_FROM_WIN32(GetLastError());
            LOGW(ERROR_LEVEL, "FUNCTION:%ls, tid:%d, LastError:%#x",
                 _CRT_WIDE(__FUNCTION__), GetCurrentThreadId(), hr);
            break;
        }

        /*
        对上报的信息进行处理，匹配规则，并返回结果。
        */
        REPLY_MESSAGE replyMessage = {0};
        replyMessage.ReplyHeader.Status = 0;
        replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
        replyMessage.Reply.IsBlock = DisposeMessage(&message->Notification);
        hr = FilterReplyMessage(g_port, (PFILTER_REPLY_HEADER)&replyMessage, sizeof(replyMessage));
        if (!SUCCEEDED(hr)) {//ERROR_FLT_NO_WAITER_FOR_REPLY 注意：调试状态下会超时。
            LOGW(ERROR_LEVEL, "FUNCTION:%ls, tid:%d, LastError:%#x, result:%#x",
                 _CRT_WIDE(__FUNCTION__), GetCurrentThreadId(), GetLastError(), hr);
            //break; //不break也不continue，仅仅打印一个信息，对性能和功能无影响。
        }

        /*
        退出的时机，必须在FilterGetMessage之前，这是新的开始，最好在FilterReplyMessage之后。
        否则在释放内存（message）时，发生：
        VERIFIER STOP 0000000000000802: pid 0xE44: Using a freed address in a pending I/O operation.
        这说明这个操作还没完成。
        */
        if (InterlockedCompareExchange(&g_SvcStop, 0, 0)) {
            LOGW(IMPORTANT_INFO_LEVEL, "FUNCTION:%ls, tid:%d", _CRT_WIDE(__FUNCTION__), GetCurrentThreadId());
            break;
        }

        memset(&message->Ovlp, 0, sizeof(OVERLAPPED));
        hr = FilterGetMessage(g_port, &message->MessageHeader, FIELD_OFFSET(MESSAGE, Ovlp), &message->Ovlp);
        if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            LOGW(ERROR_LEVEL, "FUNCTION:%ls, tid:%d, LastError:%#x",
                 _CRT_WIDE(__FUNCTION__), GetCurrentThreadId(), hr);
            break;
        }
    }

    if (!InterlockedCompareExchange(&g_SvcStop, 0, 0)) {
        InterlockedIncrement(&g_SvcStop);
    }

    if (!SUCCEEDED(hr)) {
        if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {//port disconncted.     
            LOGW(IMPORTANT_INFO_LEVEL, "FUNCTION:%ls, tid:%d, LastError:%#x, result:%#x",
                 _CRT_WIDE(__FUNCTION__), GetCurrentThreadId(), GetLastError(), hr);
            LOGW(IMPORTANT_INFO_LEVEL, "Port is disconnected, probably due to filter unloading.\n");
        } else {
            LOGW(ERROR_LEVEL, "FUNCTION:%ls, tid:%d, LastError:%#x, result:%#x",
                 _CRT_WIDE(__FUNCTION__), GetCurrentThreadId(), GetLastError(), hr);
        }
    }

    HeapFree(GetProcessHeap(), 0, message);

    LOGW(IMPORTANT_INFO_LEVEL, "FUNCTION:%ls, tid:%d", _CRT_WIDE(__FUNCTION__), GetCurrentThreadId());

    return hr;
}


void init()
{
    InitializeCriticalSection(&g_log_cs);
    g_log_level = DEFAULT_LOG_LEVEL | 1 << NORMAL_INFO_LEVEL | 1 << VERBOSE_INFO_LEVEL | 1 << TRACE_LEVEL;

    HMODULE hModule = GetModuleHandle(TEXT("Ntdll"));
    _ASSERTE(hModule);
    Ipv6AddressToStringW = (PRtlIpv6AddressToString)GetProcAddress(hModule, "RtlIpv6AddressToStringW");
    _ASSERTE(Ipv6AddressToStringW);
}


void work()
{
    SYSTEM_INFO systemInfo;
    DWORD dwThreadCount = 0;
    GetSystemInfo(&systemInfo);
    dwThreadCount = systemInfo.dwNumberOfProcessors;
    dwThreadCount = 1;

    init();

    HRESULT hr = FilterConnectCommunicationPort(g_PortName, 0, NULL, 0, NULL, &g_port);
    if (S_OK != hr || INVALID_HANDLE_VALUE == g_port) {
        LOGA(ERROR_LEVEL, "hr:%#x, LastError:%#x, port:%p", hr, GetLastError(), g_port);
        return;
    }

    g_completion = CreateIoCompletionPort(g_port, NULL, 0, dwThreadCount);
    _ASSERTE(g_completion != NULL);

    DWORD dwThreadId;
    for (; g_thread_count < dwThreadCount; g_thread_count++) {
        g_hThread[g_thread_count] = CreateThread(NULL, 0, CommunicationThread, NULL, 0, &dwThreadId);
        _ASSERTE(g_hThread[g_thread_count]);
    }

    /*
    这个循环也可以考虑放到上面的循环里做。
    */
    for (g_thread_count = 0; g_thread_count < dwThreadCount; g_thread_count++) {
        PMESSAGE msg = (PMESSAGE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MESSAGE));//这个内存在线程退出时释放。
        _ASSERTE(msg != NULL);

        memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));
        hr = FilterGetMessage(g_port,
                              &msg->MessageHeader,
                              FIELD_OFFSET(MESSAGE, Ovlp),
                              &msg->Ovlp);
        _ASSERTE(hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING));
    }

    DWORD ret = WaitForMultipleObjects(g_thread_count, g_hThread, TRUE, INFINITE);
    switch (ret) {
    case WAIT_OBJECT_0:
        LOGW(IMPORTANT_INFO_LEVEL, "");
        break;
    case WAIT_TIMEOUT:
        LOGW(ERROR_LEVEL, "");
        break;
    case WAIT_FAILED:
        LOGW(ERROR_LEVEL, "LastError:%#x", GetLastError());
        break;
    default:
        LOGW(ERROR_LEVEL, "ret:%d, LastError:%#x", ret, GetLastError());
        break;
    }
}
