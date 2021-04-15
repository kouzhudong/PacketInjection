#pragma once

#include "DriverEntry.h"

#define IOCTL_PASS_EVENT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_INFO      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_YES_NO        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_IP        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_IP        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DEL_IP        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*
Maximum URL length is 2,083 characters in Internet Explorer
https://support.microsoft.com/en-us/help/208427/maximum-url-length-is-2-083-characters-in-internet-explorer

UrlHash/UrlIsA/UrlGetLocationA/UrlUnescapeW/_tagCOMPONENT等函数和结构都使用了INTERNET_MAX_URL_LENGTH.

URL Length Limits
https://blogs.msdn.microsoft.com/ieinternals/2014/08/13/url-length-limits/
里说:WinINET.h defines INTERNET_MAX_URL_LENGTH as 2083 characters.

文件和注册表的极限是1024.
进程和路径的极限是32767.

所以还采用这个数值.
*/
#define MAX_URL_LEN (32 * 1024)


typedef enum _NETWORK_TYPE{
    UNUSE,
    URL,
    DNS
}NETWORK_TYPE;


typedef struct _PACKET_INFO {
    PVOID pending_packer;//仅供内核使用,是PPENDED_PACKET,用于验证.

    NETWORK_TYPE type;

    BOOL IsBlock;

    char data[MAX_URL_LEN];
} PACKET_INFO, *PPACKET_INFO;


//////////////////////////////////////////////////////////////////////////////////////////////////


_Dispatch_type_(IRP_MJ_CREATE) 
_Dispatch_type_(IRP_MJ_CLOSE) 
DRIVER_DISPATCH CreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) 
DRIVER_DISPATCH DeviceControl;
