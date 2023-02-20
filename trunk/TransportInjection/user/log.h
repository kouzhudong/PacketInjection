#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
日志的级别。
按位定义，最大有效数是ULONG的位数。
注意：位数是从零开始的，检查位的函数也是这样的。
*/
typedef enum _LOG_LEVEL {
    ERROR_LEVEL = 0,
    WARNING_LEVEL = 1,
    IMPORTANT_INFO_LEVEL,
    NORMAL_INFO_LEVEL,
    VERBOSE_INFO_LEVEL,
    TRACE_LEVEL,

    MAX_LEVEL = 31
} LOG_LEVEL;


#define DEFAULT_LOG_LEVEL (1 << ERROR_LEVEL | 1 << WARNING_LEVEL | 1 << IMPORTANT_INFO_LEVEL)


//////////////////////////////////////////////////////////////////////////////////////////////////


extern CRITICAL_SECTION g_log_cs;
extern ULONG g_log_level;


void LogA(IN LOG_LEVEL Level, IN char const * Format, ...);
void LogW(IN LOG_LEVEL Level, IN wchar_t const * Format, ...);


#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define __FILENAMEW__ (wcsrchr(_CRT_WIDE(__FILE__), L'\\') ? wcsrchr(_CRT_WIDE(__FILE__), L'\\') + 1 : _CRT_WIDE(__FILE__))


/*
仅仅支持宽字符，不支持单字符参数。
注意：第二个参数是单字符，可以为空，但不要为NULL，更不能省略。
*/
#define LOGW(Level, Format, ...) \
{LogW(Level, L"FILE:%ls, LINE:%d, "##Format, __FILENAMEW__, __LINE__, __VA_ARGS__);} //\r\n

/*
既支持单字符也支持宽字符。
注意：第二个参数是单字符，可以为空，但不要为NULL，更不能省略。

用%ls打印宽字符，遇到特殊字符会截断。
*/
#define LOGA(Level, Format, ...) \
{LogA(Level, "FILE:%s, LINE:%d, "##Format, __FILENAME__, __LINE__, __VA_ARGS__);} //\r\n


//////////////////////////////////////////////////////////////////////////////////////////////////


void DebugPrintA(const char * format, ...);
void DebugPrintW(const wchar_t * format, ...);
