#include "log.h"

#pragma warning(disable:26812)


/*
和LOG_LEVEL对应，不能少。
定义未定义是防止越界。
*/
const wchar_t* g_log_level_w[MAX_LEVEL + 1] = {
    L"错误信息：",
    L"警告信息：",
    L"重要信息：",
    L"普通信息：",
    L"冗长信息：",
    L"跟踪信息：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义：",
    L"未定义："
};


CRITICAL_SECTION g_log_cs;//同步日志文件的对象。


ULONG g_log_level = DEFAULT_LOG_LEVEL;//日志开关，由配置文件控制。


//////////////////////////////////////////////////////////////////////////////////////////////////


void LogA(IN LOG_LEVEL Level, IN char const * Format, ...)
{
    if (!BitTest((const LONG*)&g_log_level, Level)) {
        return;
    }

    if (Level >= MAX_LEVEL) {
        return;
    }

    setlocale(0, "chs");//支持写汉字。

    EnterCriticalSection(&g_log_cs);

    va_list args;
    va_start(args, Format);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t time[MAX_PATH] = {0};//格式：2016-07-11 17:35:54 
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
