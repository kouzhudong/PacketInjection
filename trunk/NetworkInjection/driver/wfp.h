#pragma once

#include "DriverEntry.h"
#include "..\public\public.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


DEFINE_GUID(NULL_GUID, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);


/*
网络操作的上下文。
*/
typedef struct _FLOW_DATA {
    LIST_ENTRY  listEntry;

    //这三个必不可少。
    UINT64      flowHandle; CRITICAL
    UINT16      layerId; CRITICAL
    UINT32      calloutId; CRITICAL

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //网络信息

    FWP_DIRECTION Direction;
    IPPROTO Protocol;//UINT8
    ADDRESS_FAMILY addressFamily;

    IP_ADDR SourceIp;
    UINT16 SourcePort;
    IP_ADDR DestinationIp;
    UINT16 DestinationPort;

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //进程信息

    WCHAR*      processPath;
    UINT32      size;

    UINT64      processId;

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //用户信息。

    SID *sid;
    ULONG sidLen;

    //////////////////////////////////////////////////////////////////////////////////////////////////

    BOOLEAN deleting;//驱动卸载时设置此标志.最好有，否者，卸载的时候死锁等问题。
    LONG    refCount;//引用计数,防止本结构的内存被释放.特别注意：所有释放本结构的地方都用检查这个值。
} FLOW_DATA, *PFLOW_DATA;


typedef struct _PENDED_PACKET {
    LIST_ENTRY listEntry;

    PFLOW_DATA Context OPTIONAL;//上下文，保护进程信息。
    FLOW_DATA belongingFlow;//这里不是上下文，而是自己获取的类似上下文的信息，不保护进程信息。

    //////////////////////////////////////////////////////////////////////////////////////////////////

    FWP_DIRECTION Direction;
    IPPROTO Protocol;//UINT8
    ADDRESS_FAMILY addressFamily;
    BOOLEAN isIPv6;

    //////////////////////////////////////////////////////////////////////////////////////////////////

    NET_BUFFER_LIST * NetBufferList;// NetBufferList Chain to be processed    
    size_t DataLength;              // Length of NBL Chain   

    PBYTE KernelBuffer;
    SIZE_T KernelBufferLength;    

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //Inject成员数据。

    //FwpsInjectNetworkSendAsync和FwpsInjectNetworkReceiveAsync公用。
    HANDLE injectionContext;
    COMPARTMENT_ID compartmentId;

    //FwpsInjectNetworkReceiveAsync特有。
    IF_INDEX interfaceIndex;
    IF_INDEX subInterfaceIndex;

    //////////////////////////////////////////////////////////////////////////////////////////////////



} PENDED_PACKET, * PPENDED_PACKET;


/*
专门收集CALLOUTID的全局变量数据，避免在VS的显示中显示过多的全局变量。

另一个思路是：弄个全局数组，没有成员名，数组的大小是FWPS_BUILTIN_LAYER_MAX。
数组的成员顺序和FWPS_BUILTIN_LAYER_MAX的一样。
注意:不同的编译版本的FWPS_BUILTIN_LAYER_MAX的值是不一样的。
*/
typedef struct _CALLOUTID {
    //////////////////////////////////////////////////////////////////////////////////////////////

    UINT32 EstablishedId4;
    UINT32 EstablishedId6;

    UINT32 EstablishedId4_DISCARD;
    UINT32 EstablishedId6_DISCARD;

    //////////////////////////////////////////////////////////////////////////////////////////////

    UINT32 OUTBOUND_TRANSPORT_V4;
    UINT32 OUTBOUND_TRANSPORT_V6;

    UINT32 INBOUND_TRANSPORT_V4;
    UINT32 INBOUND_TRANSPORT_V6;

    UINT32 OUTBOUND_TRANSPORT_DISCARD_V4;
    UINT32 OUTBOUND_TRANSPORT_DISCARD_V6;

    UINT32 INBOUND_TRANSPORT_DISCARD_V4;
    UINT32 INBOUND_TRANSPORT_DISCARD_V6;

    //////////////////////////////////////////////////////////////////////////////////////////////

    UINT32 OUTBOUND_IPPACKET_V4;
    UINT32 OUTBOUND_IPPACKET_V6;

    UINT32 INBOUND_IPPACKET_V4;
    UINT32 INBOUND_IPPACKET_V6;

    UINT32 OUTBOUND_IPPACKET_DISCARD_V4;
    UINT32 OUTBOUND_IPPACKET_DISCARD_V6;

    UINT32 INBOUND_IPPACKET_DISCARD_V4;
    UINT32 INBOUND_IPPACKET_DISCARD_V6;

    //////////////////////////////////////////////////////////////////////////////////////////////

    //UINT32 STREAM_V4;
    //UINT32 STREAM_V4_DISCARD;

    //UINT32 STREAM_V6;
    //UINT32 STREAM_V6_DISCARD;

    //UINT32 STREAM_PACKET_V4;
    //UINT32 STREAM_PACKET_V6;

    //////////////////////////////////////////////////////////////////////////////////////////////

    //UINT32 DATAGRAM_DATA_V4;
    //UINT32 DATAGRAM_DATA_V4_DISCARD;

    //UINT32 DATAGRAM_DATA_V6;
    //UINT32 DATAGRAM_DATA_V6_DISCARD;

    //////////////////////////////////////////////////////////////////////////////////////////////

    //可继续添加.
    //...

}CALLOUTID, *PCALLOUTID;


/*
用于注册用的数组。
如果不满足需求，可以再添加成员，如一些数据结构（FWPS_CALLOUT， FWPM_CALLOUT， FWPM_FILTER）中的flags成员。
甚至是数组中的数组，如CALLOUT_FILTER中再添加FWPM_FILTER_CONDITION0。
*/
typedef struct _CALLOUT_FILTER {
    __in     const GUID * SystemlayerKey;
    __out    PUINT32 MyCalloutId;//PUINT32
    __in     FWPS_CALLOUT_CLASSIFY_FN1 ClassifyFn;
    __in     FWPS_CALLOUT_NOTIFY_FN1 NotifyFn;
    __in_opt FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 FlowDeleteFn;
} CALLOUT_FILTER, * PCALLOUT_FILTER;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern HANDLE g_IpPacket4_InjectionHandle_in;
extern HANDLE g_IpPacket4_InjectionHandle_out;
extern HANDLE g_IpPacket6_InjectionHandle_in;
extern HANDLE g_IpPacket6_InjectionHandle_out;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern LIST_ENTRY g_flowContextList;
extern KSPIN_LOCK g_flowContextListLock;
extern CALLOUTID g_CallOutId;

NTSTATUS StartWFP();
void StopWFP();
