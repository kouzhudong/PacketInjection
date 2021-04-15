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
        protocol_name = L"未知";//也可打印一个数值。
        break;
    }

    return protocol_name;
}


BOOL ApplyRule(PNOTIFICATION notification)
/*
你的代码都在这里。

这，可，进一步的封装，封装成类，给个回调函数。

这里只可解析网络和返回阻断，但不能修改网络。

这个功能都有看官去做吧！
*/
{
    BOOL IsBlock = FALSE;





    return IsBlock;
}


void ResolutionProtocol(PNOTIFICATION notification)
/*
功能：根据PNOTIFICATION提供的信息，解析UserBuffer里的网络协议数据，长度为UserBufferLength。

注意：内存属性为：不可写和不可执行。

这个功能都有看官去做吧！

这里不建议修改内存，即使内存可写，写了也无效，因为驱动不支持，没做修改。
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
         "\r第一个字节是：%#x, 数据长度：%d，可用长度：%d，多余长度：%d。\n\n",
         test,
         notification->DataLength,
         notification->UserBufferLength,
         notification->UserBufferLength - notification->DataLength
         );






}


VOID ShowMessage(PNOTIFICATION notification)
/*
功能：打印驱动上报的事件。

作用：检测这几个线程是否工作正常。

注意：
1.不开启检测不浪费资源，开启了影响速度。
2.这个消息是很频繁的。
3.这个消息的具体的内容也是很多的。
*/
{
    WCHAR SourceIp[MAX_ADDRESS_STRING_LENGTH + 1] = {0};

    switch (notification->SourceIp.addressFamily)
    {
    case AF_INET:
        notification->SourceIp.ipv4.S_un.S_addr = ntohl(notification->SourceIp.ipv4.S_un.S_addr);
        InetNtop(AF_INET, &notification->SourceIp.ipv4, SourceIp, _countof(SourceIp));
        break;
    case AF_INET6://注意字节序：RtlUlongByteSwap
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
    case AF_INET6://注意字节序：RtlUlongByteSwap
        InetNtop(AF_INET6, &notification->DestinationIp.ipv6, DestinationIp, _countof(DestinationIp));
        //Ipv6AddressToStringW(&notification->DestinationIp.ipv6, DestinationIp);
        break;
    default:
        _ASSERTE(FALSE);
        break;
    }

    LOGA(VERBOSE_INFO_LEVEL, 
         "\nSourceIp:%ls, SourcePort:%d, DestinationIp:%ls, DestinationPort:%d。\n"
         "Direction:%ls, Protocol:%ls。\n"
         "pid:%d, processPath:%ls。\n\n",
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
