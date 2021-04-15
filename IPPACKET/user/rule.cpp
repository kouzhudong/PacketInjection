#include "rule.h"
#include "CommunicationThread.h"
#include "log.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


const wchar_t* get_protocol_name(IPPROTO protocol)
{
    const wchar_t* protocol_name = 0;

    switch (protocol) {
    case IPPROTO_TCP:
        protocol_name = L"TCP";
        break;
    case IPPROTO_UDP:
        protocol_name = L"UDP";
        break;
    case IPPROTO_IPV4:
        protocol_name = L"IPV4";
        break;
    case IPPROTO_IPV6:
        protocol_name = L"IPV6";
        break;
    case IPPROTO_ICMP:
        protocol_name = L"ICMP";
        break;
    case IPPROTO_IGMP:
        protocol_name = L"IGMP";
        break;
    case IPPROTO_ICMPV6:
        protocol_name = L"ICMPV6";
        break;
    default:
        protocol_name = L"δ֪";//Ҳ�ɴ�ӡһ����ֵ��
        break;
    }

    return protocol_name;
}


BOOL ApplyRule(PNOTIFICATION notification)
/*
��Ĵ��붼�����

�⣬�ɣ���һ���ķ�װ����װ���࣬�����ص�������

����ֻ�ɽ�������ͷ�����ϣ��������޸����硣

������ܶ��п���ȥ���ɣ�
*/
{
    BOOL IsBlock = FALSE;





    return IsBlock;
}


void ResolutionProtocol(PNOTIFICATION notification)
/*
���ܣ�����PNOTIFICATION�ṩ����Ϣ������UserBuffer�������Э�����ݣ�����ΪUserBufferLength��

ע�⣺�ڴ�����Ϊ������д�Ͳ���ִ�С�

������ܶ��п���ȥ���ɣ�

���ﲻ�����޸��ڴ棬��ʹ�ڴ��д��д��Ҳ��Ч����Ϊ������֧�֣�û���޸ġ�
*/
{
    if (NULL == notification) {
        return;
    }

    if (NULL == notification->UserBuffer) {
        return;
    }

    if (0 == notification->UserBufferLength) {
        return;
    }

    if (0 == notification->DataLength) {
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////

    BYTE test = *(PBYTE)notification->UserBuffer;

    LOGA(VERBOSE_INFO_LEVEL,
         "\r��һ���ֽ��ǣ�%#x, ���ݳ��ȣ�%d�����ó��ȣ�%d�����೤�ȣ�%d��\n\n",
         test,
         notification->DataLength,
         notification->UserBufferLength,
         notification->UserBufferLength - notification->DataLength
         );






}


VOID ShowMessage(PNOTIFICATION notification)
/*
���ܣ���ӡ�����ϱ����¼���

���ã�����⼸���߳��Ƿ���������

ע�⣺
1.��������ⲻ�˷���Դ��������Ӱ���ٶȡ�
2.�����Ϣ�Ǻ�Ƶ���ġ�
3.�����Ϣ�ľ��������Ҳ�Ǻܶ�ġ�
*/
{
    WCHAR SourceIp[MAX_ADDRESS_STRING_LENGTH + 1] = {0};

    switch (notification->SourceIp.addressFamily)
    {
    case AF_INET:
        notification->SourceIp.ipv4.S_un.S_addr = ntohl(notification->SourceIp.ipv4.S_un.S_addr);
        InetNtop(AF_INET, &notification->SourceIp.ipv4, SourceIp, _countof(SourceIp));
        break;
    case AF_INET6://ע���ֽ���RtlUlongByteSwap
        InetNtop(AF_INET6, &notification->SourceIp.ipv6, SourceIp, _countof(SourceIp));
        //Ipv6AddressToStringW(&notification->SourceIp.ipv6, SourceIp);
        break;
    default:
        _ASSERTE(FALSE);
        break;
    }
    
    WCHAR DestinationIp[MAX_ADDRESS_STRING_LENGTH + 1] = {0};

    switch (notification->DestinationIp.addressFamily)
    {
    case AF_INET:
        notification->DestinationIp.ipv4.S_un.S_addr = ntohl(notification->DestinationIp.ipv4.S_un.S_addr);
        InetNtop(AF_INET, &notification->DestinationIp.ipv4, DestinationIp, _countof(DestinationIp));
        break;
    case AF_INET6://ע���ֽ���RtlUlongByteSwap
        InetNtop(AF_INET6, &notification->DestinationIp.ipv6, DestinationIp, _countof(DestinationIp));
        //Ipv6AddressToStringW(&notification->DestinationIp.ipv6, DestinationIp);
        break;
    default:
        _ASSERTE(FALSE);
        break;
    }

    LOGA(VERBOSE_INFO_LEVEL, 
         "\nSourceIp:%ls, SourcePort:%d, DestinationIp:%ls, DestinationPort:%d��\n"
         "Direction:%ls, Protocol:%ls��\n"
         "pid:%d, processPath:%ls��\n\n",
         SourceIp, notification->SourcePort, DestinationIp, notification->DestinationPort,
         notification->Direction ? L"INBOUND" : L"OUTBOUND",
         get_protocol_name(notification->Protocol),
         notification->processId, notification->processPath
         );

    __try {
        BOOL ret = IsBadReadPtr(&notification->UserBuffer, notification->UserBufferLength);//ProbeForRead 
        if (ret) {
            LOGA(VERBOSE_INFO_LEVEL, "XXXXX");
        }

        ResolutionProtocol(notification);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOGA(VERBOSE_INFO_LEVEL, "XXXXX");
    }
}


BOOL DisposeMessage(PNOTIFICATION notification)
{
    BOOL IsBlock = FALSE;

    ShowMessage(notification);

    IsBlock = ApplyRule(notification);

    return IsBlock;
}
