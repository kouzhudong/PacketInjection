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
    UINT64      flowHandle;
    UINT16      layerId;
    UINT32      calloutId;

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

    PFLOW_DATA belongingFlow;
    FWP_DIRECTION  direction;

    NET_BUFFER_LIST * NetBufferList;// NetBufferList Chain to be processed    
    size_t DataLength;              // Length of NBL Chain   

    PBYTE KernelBuffer;
    SIZE_T KernelBufferLength;    

#pragma warning(push)
#pragma warning(disable: 4201) //NAMELESS_STRUCT_UNION
    union
    {
        FWP_BYTE_ARRAY16 remoteAddr;
        UINT32 ipv4RemoteAddr;
    };
#pragma warning(pop)

    SCOPE_ID remoteScopeId;
    WSACMSGHDR * controlData;
    ULONG controlDataLength;

    // Data fields for inbound packet re-injection.
    ULONG nblOffset;
    UINT32 ipHeaderSize;
    UINT32 transportHeaderSize;
    IF_INDEX interfaceIndex;
    IF_INDEX subInterfaceIndex;

    COMPARTMENT_ID compartmentId;
    UINT64 endpointHandle;// Data fields for outbound packet re-injection.

} PENDED_PACKET, * PPENDED_PACKET;


/*
用于注册用的数组。
如果不满足需求，可以再添加成员，如一些数据结构（FWPS_CALLOUT， FWPM_CALLOUT， FWPM_FILTER）中的flags成员。
甚至是数组中的数组，如CALLOUT_FILTER中再添加FWPM_FILTER_CONDITION0。
*/
typedef struct _CALLOUT_FILTER {
    __in     const GUID * SystemlayerKey;
    __in     FWPS_CALLOUT_CLASSIFY_FN1 ClassifyFn;
    __in     FWPS_CALLOUT_NOTIFY_FN1 NotifyFn;
    __in_opt FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 FlowDeleteFn;
} CALLOUT_FILTER, * PCALLOUT_FILTER;


//////////////////////////////////////////////////////////////////////////////////////////////////


extern HANDLE g_Forward_InjectionHandle;
extern HANDLE g_Network_InjectionHandle;
extern HANDLE g_Transport_InjectionHandle;
extern HANDLE g_Stream_InjectionHandle;

extern LIST_ENTRY g_PacketList;
extern KSPIN_LOCK g_PacketListLock;

_IRQL_requires_max_(DISPATCH_LEVEL)
void DereferenceFlowContext(_Inout_ PFLOW_DATA flowContext);

void ReferenceFlowContext(_Inout_ PFLOW_DATA flowContext);
void GetFlagsIndexesForLayer(_In_ UINT16 layerId, _Out_ UINT * flagsIndex);
void GetNetWorkInfo(const FWPS_INCOMING_VALUES * pClassifyValues, OUT PPENDED_PACKET packet);


//////////////////////////////////////////////////////////////////////////////////////////////////


extern LIST_ENTRY g_flowContextList;
extern KSPIN_LOCK g_flowContextListLock;
extern UINT32 g_CallOutId[FWPS_BUILTIN_LAYER_MAX];

NTSTATUS StartWFP();
void StopWFP();
