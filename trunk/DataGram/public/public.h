#pragma once 

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#define g_PortName L"\\CommunicationPort"


#define IPV4_ADDRESS_LENGTH  4
#define IPV6_ADDRESS_LENGTH 16

static_assert(sizeof(IN6_ADDR) == IPV6_ADDRESS_LENGTH, "XXX");


//////////////////////////////////////////////////////////////////////////////////////////////////


//这个定义与SOCKADDR_INET何曾的相似啊！
typedef struct _IP_ADDR {
    ADDRESS_FAMILY addressFamily;
    IN_ADDR ipv4;
    IN6_ADDR ipv6;
} IP_ADDR, * PIP_ADDR;


/*
注意：使用此结构的函数，要求此结构的某些成员必须某个尺寸的内存对齐。

此结构的定义，可参考：PENDED_PACKET以及FLOW_DATA，可包含这两个结构的大部分成员，还可添加额外的成员。
*/
#pragma pack( push )
#pragma pack(16)
typedef struct _NOTIFICATION {
    ULONGLONG IsBlock; //应用层专用的。之所以用ULONGLONG是因为内存对齐。

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //网络信息
    
    FWP_DIRECTION Direction;
    IPPROTO Protocol;//UINT8

    IP_ADDR SourceIp;
    UINT16 SourcePort;
    IP_ADDR DestinationIp;
    UINT16 DestinationPort;

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //进程信息

    WCHAR  processPath[MAX_PATH + 1] OPTIONAL;
    UINT32 size OPTIONAL;//字节大小，非字符个数。

    UINT64 processId OPTIONAL;

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //用户信息。

    SID* sid OPTIONAL;
    ULONG sidLen OPTIONAL;

    //////////////////////////////////////////////////////////////////////////////////////////////////

    PBYTE UserBuffer OPTIONAL;
    SIZE_T UserBufferLength OPTIONAL;//PAGE_SIZE对齐。始终大于等于DataLength。
    SIZE_T DataLength OPTIONAL;//实际的网络数据。

    //////////////////////////////////////////////////////////////////////////////////////////////////

    //可继续添加。
} NOTIFICATION, * PNOTIFICATION;
#pragma pack( pop )


/*
应用层返回给驱动信息。
*/
typedef struct _REPLY {
    BOOL IsBlock;
} REPLY, * PREPLY;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef enum _CMD {


}CMD;


#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.
typedef struct _COMMAND_MESSAGE { //应用层和驱动公用的结构。
    CMD Command;//这个成员的位置保持不变。

    //下面可继续添加。

} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;
#pragma warning(pop)


//////////////////////////////////////////////////////////////////////////////////////////////////
