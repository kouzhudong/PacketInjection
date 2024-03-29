#pragma once 

#include <ntifs.h>
#include <ntddk.h>
//#include <wdf.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#include <fwpsk.h>
#pragma warning(pop)

#include <fwpmk.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#define INITGUID
#include <guiddef.h>

#define NDIS_SUPPORT_NDIS6      1 //ntddndis.h 和ndis.h有时把这个设置为0.

#include <ndis.h>
#include <windef.h>
#include <initguid.h> //静态定义UUID用的，否则：error LNK2001。
#include <Fwpmk.h>
#include <Ntstrsafe.h>
#include <Wsk.h>
#include <ipmib.h>
#include <netpnp.h>
#include <ntintsafe.h>
#include <fwpvi.h>
#include <fltkernel.h>

#define TAG 'tset' //test


//////////////////////////////////////////////////////////////////////////////////////////////////


#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define __FILENAMEW__ (wcsrchr(_CRT_WIDE(__FILE__), L'\\') ? wcsrchr(_CRT_WIDE(__FILE__), L'\\') + 1 : _CRT_WIDE(__FILE__))

/*
既支持单字符也支持宽字符。
注意：
1.第三个参数是单字符，可以为空，但不要为NULL，更不能省略。
2.驱动在DPC上不要打印宽字符。
3.
*/

//这个支持3三个参数。
#define Print(ComponentId, Level, Format, ...) \
{DbgPrintEx(ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__);}

//这个最少4个参数。
#define PrintEx(ComponentId, Level, Format, ...) \
{KdPrintEx((ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__));}


//////////////////////////////////////////////////////////////////////////////////////////////////


extern LONG gDriverUnloading;
extern PDEVICE_OBJECT g_deviceObject;
