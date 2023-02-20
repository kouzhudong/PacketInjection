#pragma once 

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#define g_PortName L"\\CommunicationPort"


#define IPV4_ADDRESS_LENGTH  4
#define IPV6_ADDRESS_LENGTH 16

static_assert(sizeof(IN6_ADDR) == IPV6_ADDRESS_LENGTH, "XXX");


//////////////////////////////////////////////////////////////////////////////////////////////////


//���������SOCKADDR_INET���������ư���
typedef struct _IP_ADDR {
    ADDRESS_FAMILY addressFamily;
    IN_ADDR ipv4;
    IN6_ADDR ipv6;
} IP_ADDR, * PIP_ADDR;


/*
ע�⣺ʹ�ô˽ṹ�ĺ�����Ҫ��˽ṹ��ĳЩ��Ա����ĳ���ߴ���ڴ���롣

�˽ṹ�Ķ��壬�ɲο���PENDED_PACKET�Լ�FLOW_DATA���ɰ����������ṹ�Ĵ󲿷ֳ�Ա��������Ӷ���ĳ�Ա��
*/
#pragma pack( push )
#pragma pack(16)
typedef struct _NOTIFICATION {
    ULONGLONG IsBlock; //Ӧ�ò�ר�õġ�֮������ULONGLONG����Ϊ�ڴ���롣

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //������Ϣ
    
    FWP_DIRECTION Direction;
    IPPROTO Protocol;//UINT8

    IP_ADDR SourceIp;
    UINT16 SourcePort;
    IP_ADDR DestinationIp;
    UINT16 DestinationPort;

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //������Ϣ

    WCHAR  processPath[MAX_PATH + 1] OPTIONAL;
    UINT32 size OPTIONAL;//�ֽڴ�С�����ַ�������

    UINT64 processId OPTIONAL;

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //�û���Ϣ��

    SID* sid OPTIONAL;
    ULONG sidLen OPTIONAL;

    //////////////////////////////////////////////////////////////////////////////////////////////////

    PBYTE UserBuffer OPTIONAL;
    SIZE_T UserBufferLength OPTIONAL;//PAGE_SIZE���롣ʼ�մ��ڵ���DataLength��
    SIZE_T DataLength OPTIONAL;//ʵ�ʵ��������ݡ�

    //////////////////////////////////////////////////////////////////////////////////////////////////

    //�ɼ�����ӡ�
} NOTIFICATION, * PNOTIFICATION;
#pragma pack( pop )


/*
Ӧ�ò㷵�ظ�������Ϣ��
*/
typedef struct _REPLY {
    BOOL IsBlock;
} REPLY, * PREPLY;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef enum _CMD {


}CMD;


#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.
typedef struct _COMMAND_MESSAGE { //Ӧ�ò���������õĽṹ��
    CMD Command;//�����Ա��λ�ñ��ֲ��䡣

    //����ɼ�����ӡ�

} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;
#pragma warning(pop)


//////////////////////////////////////////////////////////////////////////////////////////////////
