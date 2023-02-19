#include "log.h"

#pragma warning(disable:26812)


/*
��LOG_LEVEL��Ӧ�������١�
����δ�����Ƿ�ֹԽ�硣
*/
const wchar_t* g_log_level_w[MAX_LEVEL + 1] = {
    L"������Ϣ��",
    L"������Ϣ��",
    L"��Ҫ��Ϣ��",
    L"��ͨ��Ϣ��",
    L"�߳���Ϣ��",
    L"������Ϣ��",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺",
    L"δ���壺"
};


CRITICAL_SECTION g_log_cs;//ͬ����־�ļ��Ķ���


ULONG g_log_level = DEFAULT_LOG_LEVEL;//��־���أ��������ļ����ơ�


//////////////////////////////////////////////////////////////////////////////////////////////////


void LogA(IN LOG_LEVEL Level, IN char const * Format, ...)
{
    if (!BitTest((const LONG*)&g_log_level, Level)) {
        return;
    }

    if (Level >= MAX_LEVEL) {
        return;
    }

    setlocale(0, "chs");//֧��д���֡�

    EnterCriticalSection(&g_log_cs);

    va_list args;
    va_start(args, Format);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t time[MAX_PATH] = {0};//��ʽ��2016-07-11 17:35:54 
    int written = wsprintfW(time, L"%04d-%02d-%02d %02d:%02d:%02d:%03d\t",
                            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    written = printf("%ls", time);

    written = printf("%ls", g_log_level_w[Level]);

    written = vprintf(Format, args);

    va_end(args);

    LeaveCriticalSection(&g_log_cs);
}


void LogW(IN LOG_LEVEL Level, IN wchar_t const * Format, ...)
{


}
