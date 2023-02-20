#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
��־�ļ���
��λ���壬�����Ч����ULONG��λ����
ע�⣺λ���Ǵ��㿪ʼ�ģ����λ�ĺ���Ҳ�������ġ�
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
����֧�ֿ��ַ�����֧�ֵ��ַ�������
ע�⣺�ڶ��������ǵ��ַ�������Ϊ�գ�����ҪΪNULL��������ʡ�ԡ�
*/
#define LOGW(Level, Format, ...) \
{LogW(Level, L"FILE:%ls, LINE:%d, "##Format, __FILENAMEW__, __LINE__, __VA_ARGS__);} //\r\n

/*
��֧�ֵ��ַ�Ҳ֧�ֿ��ַ���
ע�⣺�ڶ��������ǵ��ַ�������Ϊ�գ�����ҪΪNULL��������ʡ�ԡ�

��%ls��ӡ���ַ������������ַ���ضϡ�
*/
#define LOGA(Level, Format, ...) \
{LogA(Level, "FILE:%s, LINE:%d, "##Format, __FILENAME__, __LINE__, __VA_ARGS__);} //\r\n


//////////////////////////////////////////////////////////////////////////////////////////////////


void DebugPrintA(const char * format, ...);
void DebugPrintW(const wchar_t * format, ...);
