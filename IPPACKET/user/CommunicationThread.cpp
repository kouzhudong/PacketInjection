#include "log.h"
#include "CommunicationThread.h"
#include "rule.h"

HANDLE g_hThread[MAXIMUM_WAIT_OBJECTS];
DWORD g_thread_count = 0;

HANDLE g_port;
HANDLE g_completion;

LONG g_SvcStop;//�������������¼����󣬿ɿ���̲�����

PRtlIpv6AddressToString Ipv6AddressToStringW;


//////////////////////////////////////////////////////////////////////////////////////////////////


DWORD WINAPI CommunicationThread(_In_ PVOID Context)
/*
ע�⣺
�����ǵ��͵ĸ߲������ӳٵĺ��������������ǣ�
�߲��������̣߳����кܶ����Ϣ�������磺�ļ������̣����磬ע���ȣ�ÿ���ǧ�������
���ӳ٣������ڵȴ�������ܿ촦�����߱�Ľ��̺�ϵͳ���ֿ���������

���ԣ�
����������ǣ�
�󲿷��Ǵ��ڴ������
�������ٸ���IO�������磺�ļ������磬ע������̺ͽ����ں˵ĺ�����
���������ܼ��͵�CPU�������磺���ֹ�ϣֵ�ļ��㡣
������Ҫ����ã�����������

�������ϵĽ��ۣ�
1.������־���ϴ�Ҫ��һ���̣߳���Ϊ����������������ر���ͬ���ġ�
2.������־�Ĵ�ӡ������debugview�ġ�
3.���ܵȴ����ˣ�ֻ�б��˵ȴ����
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
        ���ϱ�����Ϣ���д���ƥ����򣬲����ؽ����
        */
        REPLY_MESSAGE replyMessage = {0};
        replyMessage.ReplyHeader.Status = 0;
        replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
        replyMessage.Reply.IsBlock = DisposeMessage(&message->Notification);
        hr = FilterReplyMessage(g_port, (PFILTER_REPLY_HEADER)&replyMessage, sizeof(replyMessage));
        if (!SUCCEEDED(hr)) {//ERROR_FLT_NO_WAITER_FOR_REPLY ע�⣺����״̬�»ᳬʱ��
            LOGW(ERROR_LEVEL, "FUNCTION:%ls, tid:%d, LastError:%#x, result:%#x",
                 _CRT_WIDE(__FUNCTION__), GetCurrentThreadId(), GetLastError(), hr);
            //break; //��breakҲ��continue��������ӡһ����Ϣ�������ܺ͹�����Ӱ�졣
        }

        /*
        �˳���ʱ����������FilterGetMessage֮ǰ�������µĿ�ʼ�������FilterReplyMessage֮��
        �������ͷ��ڴ棨message��ʱ��������
        VERIFIER STOP 0000000000000802: pid 0xE44: Using a freed address in a pending I/O operation.
        ��˵�����������û��ɡ�
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
    ���ѭ��Ҳ���Կ��Ƿŵ������ѭ��������
    */
    for (g_thread_count = 0; g_thread_count < dwThreadCount; g_thread_count++) {
        PMESSAGE msg = (PMESSAGE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MESSAGE));//����ڴ����߳��˳�ʱ�ͷš�
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
