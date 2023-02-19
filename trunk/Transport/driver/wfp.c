#include "wfp.h"
#include "communication.h"
#include "DriverEntry.h"
#include "Auxiliary.h"
#include "SystemThread.h"
#include "..\public\public.h"

//#include "trace.h"
//#include "wfp.tmh"

HANDLE g_EngineHandle;
HANDLE g_ChangeHandle;

//HANDLE g_Transport_InjectionHandle;
HANDLE g_Transport4_InjectionHandle;
HANDLE g_Transport6_InjectionHandle;

CALLOUTID g_CallOutId;

LIST_ENTRY g_flowContextList;//�����ռ��ʹ���(TCP��UDP��)��Ϣ��FLOW_DATA����.
KSPIN_LOCK g_flowContextListLock;


//////////////////////////////////////////////////////////////////////////////////////////////////


void GetNetWorkInfo(const FWPS_INCOMING_VALUES * pClassifyValues, OUT PPENDED_PACKET packet)
/*
���ܣ���ȡһЩ������Ϣ���Ա㷵�ظ�Ӧ�ò㡣

���Ǹ�ֵ��Ӧ�ö���һ����
*/
{
    switch (pClassifyValues->layerId) {
    case FWPS_LAYER_STREAM_V4:
    {
        packet->belongingFlow.SourceIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS].value.uint32;

        packet->belongingFlow.SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value.uint16;

        packet->belongingFlow.DestinationIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value.uint32;

        packet->belongingFlow.DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value.uint16;

        packet->belongingFlow.Direction = pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_DIRECTION].value.uint16;

        break;
    }
    case FWPS_LAYER_STREAM_V6:
    {
        PIN6_ADDR ipv6;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&packet->belongingFlow.SourceIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        packet->belongingFlow.SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value.uint16;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&packet->belongingFlow.DestinationIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        packet->belongingFlow.DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_REMOTE_PORT].value.uint16;

        packet->belongingFlow.Direction = pClassifyValues->incomingValue[FWPS_FIELD_STREAM_V6_DIRECTION].value.uint16;

        break;
    }
    case FWPS_LAYER_DATAGRAM_DATA_V4:
    {
        packet->belongingFlow.Protocol = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8;

        packet->belongingFlow.SourceIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32;

        packet->belongingFlow.SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;

        packet->belongingFlow.DestinationIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;

        packet->belongingFlow.DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;

        packet->belongingFlow.Direction = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint16;

        break;
    }
    case FWPS_LAYER_DATAGRAM_DATA_V6:
    {
        PIN6_ADDR ipv6;

        packet->belongingFlow.Protocol = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL].value.uint8;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&packet->belongingFlow.SourceIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        packet->belongingFlow.SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT].value.uint16;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&packet->belongingFlow.DestinationIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        packet->belongingFlow.DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT].value.uint16;

        packet->belongingFlow.Direction = pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].value.uint16;

        break;
    }
    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
    {
        packet->belongingFlow.Direction = FWP_DIRECTION_INBOUND;

        packet->belongingFlow.Protocol = pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;

        packet->belongingFlow.addressFamily = AF_INET;

        packet->belongingFlow.SourceIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;

        packet->belongingFlow.SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;

        packet->belongingFlow.DestinationIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;

        packet->belongingFlow.DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

        break;
    }
    case FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD:
    {
        NOTHING;
        break;
    }
    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
    {
        PIN6_ADDR ipv6;

        packet->belongingFlow.Direction = FWP_DIRECTION_INBOUND;

        packet->belongingFlow.Protocol = pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;

        packet->belongingFlow.addressFamily = AF_INET6;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&packet->belongingFlow.SourceIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        packet->belongingFlow.SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&packet->belongingFlow.DestinationIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        packet->belongingFlow.DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;

        break;
    }
    case FWPS_LAYER_INBOUND_TRANSPORT_V6_DISCARD:
    {
        NOTHING;
        break;
    }
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
    {
        packet->belongingFlow.Direction = FWP_DIRECTION_OUTBOUND;

        packet->belongingFlow.Protocol = pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;

        packet->belongingFlow.addressFamily = AF_INET;

        packet->belongingFlow.SourceIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;

        packet->belongingFlow.SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;

        packet->belongingFlow.DestinationIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;

        packet->belongingFlow.DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

        break;
    }
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD:
    {
        NOTHING;
        break;
    }
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
    {
        PIN6_ADDR ipv6;

        packet->belongingFlow.Direction = FWP_DIRECTION_OUTBOUND;

        packet->belongingFlow.Protocol = pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;

        packet->belongingFlow.addressFamily = AF_INET6;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&packet->belongingFlow.SourceIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        packet->belongingFlow.SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&packet->belongingFlow.DestinationIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        packet->belongingFlow.DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;

        break;
    }
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD:
    {
        NOTHING;
        break;
    }
    default:
        ASSERT(FALSE);
        break;
    }
}


PPENDED_PACKET BuildTransportPendPacket(_In_ const FWPS_INCOMING_VALUES * inFixedValues,
                                        _In_ const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
                                        _Inout_opt_ void * layerData
)
/*
ע�⣺���ݲ�ͬ��ע�ỷ������ָLAYER���������ȡ��ֵҪ�в�ͬ�ı仯��
*/
{
    PPENDED_PACKET packet = NULL;

    ASSERT(layerData);

    packet = ExAllocatePoolWithTag(NonPagedPool, sizeof(PENDED_PACKET), TAG);
    if (NULL == packet) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "��Ϣ��%s", "�����ڴ�ʧ��");
        return packet;
    }
    RtlZeroMemory(packet, sizeof(PENDED_PACKET));

    //PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "��Ϣ������ DataGram packet:%p", packet);

    GetNetWorkInfo(inFixedValues, packet);

    if (layerData != NULL) {
        packet->NetBufferList = layerData;
        FwpsReferenceNetBufferList(packet->NetBufferList, TRUE);// Reference the net buffer list to make it accessible outside of classifyFn.
    }

    packet->belongingFlow.addressFamily = GetAddressFamilyForLayer(inFixedValues->layerId);
    packet->belongingFlow.Direction = GetPacketDirectionForLayer(inFixedValues->layerId);

    packet->direction = packet->belongingFlow.Direction;
    packet->addressFamily = packet->belongingFlow.addressFamily;
    FillNetwork5Tuple(inFixedValues, packet->addressFamily, packet);

    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID));
    packet->compartmentId = inMetaValues->compartmentId;

    if (packet->belongingFlow.Direction == FWP_DIRECTION_OUTBOUND) {
        ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE));
        packet->endpointHandle = inMetaValues->transportEndpointHandle;
        packet->remoteScopeId = inMetaValues->remoteScopeId;

        if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA)) {
            ASSERT(inMetaValues->controlDataLength > 0);

            packet->controlData = ExAllocatePoolWithTag(NonPagedPool, inMetaValues->controlDataLength, TAG);
            ASSERT(packet->controlData);
            RtlCopyMemory(packet->controlData, inMetaValues->controlData, inMetaValues->controlDataLength);

            packet->controlDataLength = inMetaValues->controlDataLength;
        }
    } else {
        UINT interfaceIndexIndex = 0;
        UINT subInterfaceIndexIndex = 0;

        ASSERT(packet->belongingFlow.Direction == FWP_DIRECTION_INBOUND);

        GetDeliveryInterfaceIndexesForLayer(inFixedValues->layerId, &interfaceIndexIndex, &subInterfaceIndexIndex);
        packet->interfaceIndex = inFixedValues->incomingValue[interfaceIndexIndex].value.uint32;
        packet->subInterfaceIndex = inFixedValues->incomingValue[subInterfaceIndexIndex].value.uint32;

        ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_IP_HEADER_SIZE));
        ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE));

        packet->ipHeaderSize = inMetaValues->ipHeaderSize;
        packet->transportHeaderSize = inMetaValues->transportHeaderSize;

        if (packet->NetBufferList != NULL) {
            FWPS_PACKET_LIST_INFORMATION packetInfo = {0};
            FwpsGetPacketListSecurityInformation(packet->NetBufferList,
                                                 FWPS_PACKET_LIST_INFORMATION_QUERY_IPSEC | FWPS_PACKET_LIST_INFORMATION_QUERY_INBOUND,
                                                 &packetInfo);

            packet->ipSecProtected = (BOOLEAN)packetInfo.ipsecInformation.inbound.isSecure;
            packet->nblOffset = NET_BUFFER_DATA_OFFSET(NET_BUFFER_LIST_FIRST_NB(packet->NetBufferList));
        }
    }

    for (NET_BUFFER * pNB = NET_BUFFER_LIST_FIRST_NB(packet->NetBufferList); pNB; pNB = NET_BUFFER_NEXT_NB(pNB)) {
        packet->DataLength += NET_BUFFER_DATA_LENGTH(pNB);
    }

    return packet;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOLEAN IsAleClassifyRequired(_In_ const FWPS_INCOMING_METADATA_VALUES * inMetaValues)
{
    // Note that use of FWP_CONDITION_FLAG_REQUIRES_ALE_CLASSIFY has been deprecated in Vista SP1 and Windows Server 2008.
    return FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_ALE_CLASSIFY_REQUIRED);
}


void NTAPI TransportClassifyFn(_In_ const FWPS_INCOMING_VALUES0 * pClassifyValues,
                               _In_ const FWPS_INCOMING_METADATA_VALUES0 * pMetadata,
                               _Inout_opt_ void * layerData,
                               _In_opt_ const void * classifyContext,
                               _In_ const FWPS_FILTER1 * filter,
                               _In_ UINT64 flowContext,
                               _Inout_ FWPS_CLASSIFY_OUT0 * pClassifyOut
)
{
    //PFLOW_DATA flowData = *(PFLOW_DATA *)(UINT64 *)&flowContext;
    KLOCK_QUEUE_HANDLE lockHandle;
    FWPS_PACKET_INJECTION_STATE packetState;
    PPENDED_PACKET packet = NULL;
    UINT flagsIndex = 0;
    UINT32 flags = 0;
    BOOLEAN isIPv6 = !LayerIsIPv4(pClassifyValues->layerId);
    HANDLE g_Transport_InjectionHandle = isIPv6 ? g_Transport6_InjectionHandle : g_Transport4_InjectionHandle;
    FWP_DIRECTION packetDirection;

    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);

    //////////////////////////////////////////////////////////////////////////////////////////////
    //�Ź�һЩ����

    _Analysis_assume_(layerData != NULL);
    ASSERT(layerData != NULL);

    GetFlagsIndexesForLayer(pClassifyValues->layerId, &flagsIndex);
    flags = pClassifyValues->incomingValue[flagsIndex].value.uint32;

    //if (FlagOn(flags, FWP_CONDITION_FLAG_IS_FRAGMENT)) {
    //    return;
    //}

    //if (FlagOn(flags, FWP_CONDITION_FLAG_IS_LOOPBACK)) {
    //    return;
    //}

    if ((pClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;// We don't have the necessary right to alter the packet.
    }

    packetState = FwpsQueryPacketInjectionState(g_Transport_InjectionHandle, layerData, NULL);
    if ((packetState == FWPS_PACKET_INJECTED_BY_SELF) ||
        (packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) ||
        gDriverUnloading) {
        pClassifyOut->actionType = FWP_ACTION_PERMIT;
        if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
            pClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }

        return;// We don't re-inspect packets that we've inspected earlier.
    }

    packetDirection = GetPacketDirectionForLayer(pClassifyValues->layerId);

    if (packetDirection == FWP_DIRECTION_INBOUND) {
        if (IsAleClassifyRequired(pMetadata)) {
            // Inbound transport packets that are destined to ALE Recv-Accept layers, 
            // for initial authorization or reauth, should be inspected at the ALE layer.
            // We permit it from Tranport here.
            pClassifyOut->actionType = FWP_ACTION_PERMIT;
            if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
                pClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            }

            return;
        } else {
            // To be compatible with Vista's IpSec implementation, we must not intercept not-yet-detunneled IpSec traffic.
            FWPS_PACKET_LIST_INFORMATION packetInfo = {0};
            FwpsGetPacketListSecurityInformation(layerData,
                                                 FWPS_PACKET_LIST_INFORMATION_QUERY_IPSEC | FWPS_PACKET_LIST_INFORMATION_QUERY_INBOUND,
                                                 &packetInfo);
            if (packetInfo.ipsecInformation.inbound.isTunnelMode && !packetInfo.ipsecInformation.inbound.isDeTunneled) {
                pClassifyOut->actionType = FWP_ACTION_PERMIT;
                if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
                    pClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
                }

                return;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////

     /*
     ��ȡ/����һ���ڵ���Ϣ.
     */
    packet = BuildTransportPendPacket(pClassifyValues, pMetadata, layerData);
    if (packet == NULL) {
        pClassifyOut->actionType = FWP_ACTION_PERMIT;
        if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
            pClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
        return;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////

    /*
    ����һ���ڵ�.
    */
    KeAcquireInStackQueuedSpinLock(&g_PacketListLock, &lockHandle);
    InsertTailList(&g_PacketList, &packet->listEntry);
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    //////////////////////////////////////////////////////////////////////////////////////////////

    pClassifyOut->actionType = FWP_ACTION_BLOCK;
    pClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    pClassifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}


VOID NTAPI FlowDeleteFn(IN UINT16 layerId, IN UINT32 calloutId, IN UINT64 flowContext)
{
    PFLOW_DATA flowData = *(PFLOW_DATA *)(UINT64 *)&flowContext;
    KLOCK_QUEUE_HANDLE lockHandle;

    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    KeAcquireInStackQueuedSpinLock(&g_flowContextListLock, &lockHandle);
    if (!flowData->deleting) {
        RemoveEntryList(&flowData->listEntry);//�������Ȼ�����⡣�鿴deleting��Ա��ֵ��    
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    ASSERT(flowData->refCount > 0);
    InterlockedDecrement(&flowData->refCount);

    if (flowData->refCount == 0) {

        ExFreePoolWithTag(flowData->sid, TAG);
        ExFreePoolWithTag(flowData->processPath, TAG);

        ExFreePoolWithTag(flowData, TAG);

        //PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "������Ϣ���ͷ�������:%p", flowData);
    }
}


NTSTATUS NotifyFn(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                  _In_ const GUID * filterKey,
                  _Inout_ FWPS_FILTER1 * filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}


VOID AssociateOneContext(_In_ const FWPS_INCOMING_VALUES0 * pClassifyValues,
                         _In_ const FWPS_INCOMING_METADATA_VALUES0 * pMetadata,
                         UINT16 layerId,
                         UINT32 calloutId)
{
    PFLOW_DATA fc = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE lockHandle;
    PISID sid = NULL;

    if (0 != gDriverUnloading) {
        return;
    }

    fc = (PFLOW_DATA)ExAllocatePoolWithTag(NonPagedPool, sizeof(FLOW_DATA), TAG);//FwpsFlowAssociateContext���óɹ��˲��ͷš�
    ASSERT(fc);
    RtlZeroMemory(fc, sizeof(FLOW_DATA));

    //PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, "������Ϣ������������:%p", fc);

    //////////////////////////////////////////////////////////////////////////////////////////////

    /*
    �������������ã�������ж�ص�ʱ�򣬵���RemoveFlows��������Ҫ������������
    ���ߣ���ʹ����ж�سɹ��������ٴμ��ػ�ʧ�ܡ�
    ��Ҳ��FwpsCalloutUnregisterById����STATUS_DEVICE_BUSY��ԭ��
    */
    fc->flowHandle = pMetadata->flowHandle;
    fc->calloutId = calloutId;
    fc->layerId = layerId;

    //////////////////////////////////////////////////////////////////////////////////////////////

    switch (pClassifyValues->layerId) {
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
    {
        fc->addressFamily = AF_INET;

        fc->Protocol = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint16;

        fc->SourceIp.addressFamily = AF_INET;
        //fc->SourceIp.addressFamily = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS_TYPE].value;//����ֵ��������NL_ADDRESS_TYPE

        fc->SourceIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;

        fc->SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;

        fc->DestinationIp.addressFamily = AF_INET;

        fc->SourceIp.ipv4.S_un.S_addr = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;

        fc->DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;

        fc->Direction = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.uint16;

        sid = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_USER_ID].value.sid;

        break;
    }
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD:
    {

        break;
    }
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
    {
        PIN6_ADDR ipv6;

        fc->addressFamily = AF_INET6;

        fc->Protocol = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint16;

        fc->SourceIp.addressFamily = AF_INET6;
        //fc->SourceIp.addressFamily = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS_TYPE].value;//����ֵ��������NL_ADDRESS_TYPE

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&fc->SourceIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        fc->SourcePort = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16;

        fc->DestinationIp.addressFamily = AF_INET6;

        ipv6 = (PIN6_ADDR)pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;
        RtlCopyMemory(&fc->DestinationIp.ipv6, ipv6, IPV6_ADDRESS_LENGTH);

        fc->DestinationPort = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16;

        fc->Direction = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION].value.uint16;

        sid = pClassifyValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_USER_ID].value.sid;

        break;
    }
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD:
    {

        break;
    }
    default:
        break;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //����/������Ϣ��д��

    fc->processPath = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, pMetadata->processPath->size, TAG);
    ASSERT(fc->processPath);
    memcpy(fc->processPath, pMetadata->processPath->data, pMetadata->processPath->size);
    fc->size = pMetadata->processPath->size;

    fc->processId = pMetadata->processId;

    if (NULL != sid) {
        fc->sidLen = RtlLengthSid(sid);
        fc->sid = (SID *)ExAllocatePoolWithTag(NonPagedPool, fc->sidLen, TAG);
        ASSERT(fc->sid);
        memcpy(fc->sid, sid, fc->sidLen);
    }

    fc->refCount = 1;

    //////////////////////////////////////////////////////////////////////////////////////////////    

    status = FwpsFlowAssociateContext(pMetadata->flowHandle, layerId, calloutId, (UINT64)fc);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL,
                "����status:%#x, CalloutId:%x", status, calloutId);
        ExFreePoolWithTag(fc, TAG);
        return;
    }

    KeAcquireInStackQueuedSpinLock(&g_flowContextListLock, &lockHandle);
    InsertTailList(&g_flowContextList, &fc->listEntry);
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}


void NTAPI EstablishedClassifyFn(_In_ const FWPS_INCOMING_VALUES0 * pClassifyValues,
                                 _In_ const FWPS_INCOMING_METADATA_VALUES0 * pMetadata,
                                 _Inout_opt_ void * layerData,
                                 _In_opt_ const void * classifyContext,
                                 _In_ const FWPS_FILTER1 * pFilter,
                                 _In_ UINT64 flowContext,
                                 _Inout_ FWPS_CLASSIFY_OUT0 * pClassifyOut
)
{
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(pFilter);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(layerData);

    ASSERT(pMetadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID);
    ASSERT(pMetadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH);
    ASSERT(pMetadata->processPath->size);

    /*
    ���Կ��Ƕ�һ��������б���������������ģ������ֿ�дһ�������������ּ��ˡ�
    ���ǣ��������ܻ��ж���ĺ����õ������ġ�
    */
    switch (pClassifyValues->layerId) {
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
        //AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_DATAGRAM_DATA_V4, g_CallOutId.DATAGRAM_DATA_V4);
        AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_INBOUND_TRANSPORT_V4, g_CallOutId.INBOUND_TRANSPORT_V4);
        AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_OUTBOUND_TRANSPORT_V4, g_CallOutId.OUTBOUND_TRANSPORT_V4);

        //�ɼ������.

        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD://�����ߵ������û��
        //AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_DATAGRAM_DATA_V4_DISCARD, g_CallOutId.DATAGRAM_DATA_V4_DISCARD);
        //AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_STREAM_V4_DISCARD, g_CallOutId.STREAM_V4_DISCARD);
        AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD, g_CallOutId.INBOUND_TRANSPORT_DISCARD_V4);
        AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD, g_CallOutId.OUTBOUND_TRANSPORT_DISCARD_V4);

        //�ɼ������.

        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
        //AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_DATAGRAM_DATA_V6, g_CallOutId.DATAGRAM_DATA_V6);
        AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_INBOUND_TRANSPORT_V6, g_CallOutId.INBOUND_TRANSPORT_V6);
        AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_OUTBOUND_TRANSPORT_V6, g_CallOutId.OUTBOUND_TRANSPORT_V6);

        //�ɼ������.

        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD://�����ߵ������û��
        //AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_DATAGRAM_DATA_V6_DISCARD, g_CallOutId.DATAGRAM_DATA_V6_DISCARD);
        //AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_STREAM_V6_DISCARD, g_CallOutId.STREAM_V6_DISCARD);
        AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_INBOUND_TRANSPORT_V6_DISCARD, g_CallOutId.INBOUND_TRANSPORT_DISCARD_V6);
        AssociateOneContext(pClassifyValues, pMetadata, FWPS_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD, g_CallOutId.OUTBOUND_TRANSPORT_DISCARD_V6);

        //�ɼ������.

        break;
    default:
        KdBreakPoint();
        break;
    }

    pClassifyOut->actionType = FWP_ACTION_PERMIT;
    if (pFilter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
        pClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }

    //if (pClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
    //    pClassifyOut->actionType = FWP_ACTION_CONTINUE;
    //}
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID RemoveFlows()
{
    KLOCK_QUEUE_HANDLE lockHandle;

    KeAcquireInStackQueuedSpinLock(&g_flowContextListLock, &lockHandle);
    while (!IsListEmpty(&g_flowContextList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_flowContextList);
        PFLOW_DATA flowContext = CONTAINING_RECORD(entry, FLOW_DATA, listEntry);
        NTSTATUS status;

        flowContext->deleting = TRUE; // We don't want our flow deletion function to try to remove this from the list.        
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        status = FwpsFlowRemoveContext(flowContext->flowHandle, flowContext->layerId, flowContext->calloutId);//���ӵ���FlowDeleteFn��
        KeAcquireInStackQueuedSpinLock(&g_flowContextListLock, &lockHandle);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL,
                    "����status:%#x, flowHandle:%I64d, layerId:%#x, calloutId:%#x",
                    status, flowContext->flowHandle,
                    flowContext->layerId,
                    flowContext->calloutId);
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}


void UnregisterAllCalloutId()
/*
������һ��forѭ��ʵ��.
*/
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    UINT32 counter = sizeof(CALLOUTID) / sizeof(UINT32);//_ARRAYSIZE(g_CallOutId);
    UINT32 i = 0;
    PUINT32 temp = (PUINT32)&g_CallOutId;

    for (; i < counter; i++) {
        if (temp[i]) {
            NtStatus = FwpsCalloutUnregisterById(temp[i]);
            if (!NT_SUCCESS(NtStatus)) {
                PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL,
                        "����i:%d, id:%#x, NtStatus:%#x", i, temp[i], NtStatus);
            }

            /*
            ��Ҫ����,��,��:FreePendedPacket���п����������.����д�����.
            */
            //temp[i] = 0;
        }
    }
}


void ShowCalloutId()
{
    UINT32 counter = sizeof(CALLOUTID) / sizeof(UINT32);
    UINT32 i = 0;
    PUINT32 temp = (PUINT32)&g_CallOutId;

    for (; i < counter; i++) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "��Ϣ��i:%d, id:%#x", i, temp[i]);
    }
}


void DestroyInjectionHandle()
{
    NTSTATUS status = STATUS_SUCCESS;

    if (g_Transport4_InjectionHandle != NULL) {
        status = FwpsInjectionHandleDestroy(g_Transport4_InjectionHandle);
        ASSERT(NT_SUCCESS(status));
        g_Transport4_InjectionHandle = 0;
    }

    if (g_Transport6_InjectionHandle != NULL) {
        status = FwpsInjectionHandleDestroy(g_Transport6_InjectionHandle);
        ASSERT(NT_SUCCESS(status));
        g_Transport6_InjectionHandle = 0;
    }
}


void StopWFP()
{
    NTSTATUS status = STATUS_SUCCESS;
    KLOCK_QUEUE_HANDLE flowListLockHandle;

    KeAcquireInStackQueuedSpinLock(&g_flowContextListLock, &flowListLockHandle);
    InterlockedIncrement(&gDriverUnloading);
    KeReleaseInStackQueuedSpinLock(&flowListLockHandle);

    status = FwpmBfeStateUnsubscribeChanges(g_ChangeHandle);
    ASSERT(NT_SUCCESS(status));
    status = FwpmEngineClose(g_EngineHandle);
    ASSERT(NT_SUCCESS(status));

    RemoveFlows();

    UnregisterAllCalloutId();

    DestroyInjectionHandle();
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS RegisterCallout(__in GUID SystemlayerKey,
                         __out PUINT32 MyCalloutId,
                         __in FWPS_CALLOUT_CLASSIFY_FN1 ClassifyFn,
                         __in FWPS_CALLOUT_NOTIFY_FN1 NotifyFn,
                         __in_opt FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 FlowDeleteFn
)
/*
ע�����紦��

������������
1.���˵�������
2.���˵ķֲ�ΪFWPM_SUBLAYER_UNIVERSAL��
3.Callout��displayData�����ֺ�������
4.Filter��displayData�����ֺ�������
5.FWPS_CALLOUT��flags�����á�
6.FWPM_CALLOUT��flags�����á�
7.FWPM_FILTER��ĸ��ָ�����ϸ�;�ȷ�����á�
����Ҫ������Ҫ��ѡ���Ƿ�ʹ�����������
�����������Ҳ��һ����ͨ���ԣ���ע����ɹ�����������̫�࣬��Ҫ�ڴ������й��ˡ�

������
FlowDeleteFn ��û����Ҫ�����ģ�����������ע��ʧ�ܵ�����£����Բ�Ҫ�����ר�Ź��������ĵĲ���û���������Ϊ������û�������ġ�
*/
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    FWPS_CALLOUT sCallout = {0};
    FWPM_CALLOUT mCallout = {0};
    FWPM_DISPLAY_DATA displayData = {0};
    FWPM_FILTER filter = {0};
    GUID MyCalloutKey;

    NtStatus = ExUuidCreate(&MyCalloutKey);
    if (!NT_SUCCESS(NtStatus)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
        return NtStatus;
    }

    /*
    ���Կ�����RtlStringFromGUID��GUIDת��Ϊ�ַ�����Ȼ���Ƹ���Ӧ�ĳ�Ա�����滻test�ַ�����
    ���߰�SystemlayerKeyҲת��Ϊ�ַ�����Ȼ���������ַ���ƴ�ӣ�Ȼ��ֵ�����滻test�ַ�����
    */

    sCallout.calloutKey = MyCalloutKey;
    sCallout.classifyFn = ClassifyFn;
    sCallout.notifyFn = NotifyFn;
    sCallout.flowDeleteFn = FlowDeleteFn;
    NtStatus = FwpsCalloutRegister(g_deviceObject, &sCallout, MyCalloutId);
    if (!NT_SUCCESS(NtStatus)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
        return NtStatus;
    }

    __try {
        displayData.name = L"test";
        displayData.description = L"test";
        mCallout.calloutKey = sCallout.calloutKey;
        mCallout.displayData = displayData;
        mCallout.applicableLayer = SystemlayerKey;
        NtStatus = FwpmCalloutAdd(g_EngineHandle, &mCallout, NULL, NULL);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
            __leave;
        }

        filter.layerKey = SystemlayerKey;
        filter.action.calloutKey = sCallout.calloutKey;
        filter.displayData.name = L"test";
        filter.displayData.description = L"test";
        filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
        filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
        NtStatus = FwpmFilterAdd(g_EngineHandle, &filter, NULL, NULL);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
            __leave;
        }
    } __finally {
        if (!NT_SUCCESS(NtStatus)) {
            FwpsCalloutUnregisterById(*MyCalloutId);
            *MyCalloutId = 0;
        }
    }

    return NtStatus;
}


NTSTATUS FwpsCalloutRegisterFilter(_In_ CONST PCALLOUT_FILTER Registration)
/*
���Կ�����minifilter������ע������ݽṹ��������ע�ᡣ
�������������FltRegisterFilter�Ĺ��ܣ����ֶ���FwpsCalloutRegisterFilter����FwpmCalloutRegisterFilter.
*/
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    int i = 0;

    for (i = 0; ; i++) {
        if (IsEqualGUID(&NULL_GUID, Registration[i].SystemlayerKey)) {
            break;
        }

        NtStatus = RegisterCallout(*Registration[i].SystemlayerKey,
                                   Registration[i].MyCalloutId,
                                   Registration[i].ClassifyFn,
                                   Registration[i].NotifyFn,
                                   Registration[i].FlowDeleteFn);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����i:%d, status:%#x", i, NtStatus);
            break;
        }
    }

    return NtStatus;
}


/*
GUID���붨��Ϊָ�룬���ߣ����ָ������⡣
*/
CALLOUT_FILTER g_CalloutFilter[] =
{
    //������ע�����ĸ�����������Ҳ������ϣ���������һ����NULL��
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,           &g_CallOutId.EstablishedId4,                EstablishedClassifyFn,  NotifyFn,   0},
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,           &g_CallOutId.EstablishedId6,                EstablishedClassifyFn,  NotifyFn,   0},
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD,   &g_CallOutId.EstablishedId4_DISCARD,        EstablishedClassifyFn,  NotifyFn,   0},
    {&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD,   &g_CallOutId.EstablishedId6_DISCARD,        EstablishedClassifyFn,  NotifyFn,   0},

    //ע��TRANSPORT��صĴ���
    {&FWPM_LAYER_INBOUND_TRANSPORT_V4,              &g_CallOutId.INBOUND_TRANSPORT_V4,          TransportClassifyFn,  NotifyFn,   FlowDeleteFn},
    {&FWPM_LAYER_INBOUND_TRANSPORT_V6,              &g_CallOutId.INBOUND_TRANSPORT_V6,          TransportClassifyFn,  NotifyFn,   FlowDeleteFn},
    {&FWPM_LAYER_OUTBOUND_TRANSPORT_V4,             &g_CallOutId.OUTBOUND_TRANSPORT_V4,         TransportClassifyFn,  NotifyFn,   FlowDeleteFn},
    {&FWPM_LAYER_OUTBOUND_TRANSPORT_V6,             &g_CallOutId.OUTBOUND_TRANSPORT_V6,         TransportClassifyFn,  NotifyFn,   FlowDeleteFn},
    //{&FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD,      &g_CallOutId.INBOUND_TRANSPORT_DISCARD_V4,  TransportClassifyFn,  NotifyFn,   FlowDeleteFn},
    //{&FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD,      &g_CallOutId.INBOUND_TRANSPORT_DISCARD_V6,  TransportClassifyFn,  NotifyFn,   FlowDeleteFn},
    //{&FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD,     &g_CallOutId.OUTBOUND_TRANSPORT_DISCARD_V4, TransportClassifyFn,  NotifyFn,   FlowDeleteFn},
    //{&FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD,     &g_CallOutId.OUTBOUND_TRANSPORT_DISCARD_V6, TransportClassifyFn,  NotifyFn,   FlowDeleteFn},

    //ע��DATAGRAM_DATA��صĴ���
    //{&FWPM_LAYER_DATAGRAM_DATA_V4,             &g_CallOutId.DATAGRAM_DATA_V4,         DataGramClassifyFn,  NotifyFn,   FlowDeleteFn},
    //{&FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD,     &g_CallOutId.DATAGRAM_DATA_V4_DISCARD, DataGramClassifyFn,  NotifyFn,   FlowDeleteFn},
    //{&FWPM_LAYER_DATAGRAM_DATA_V6,             &g_CallOutId.DATAGRAM_DATA_V6,         DataGramClassifyFn,  NotifyFn,   FlowDeleteFn},
    //{&FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD,     &g_CallOutId.DATAGRAM_DATA_V6_DISCARD, DataGramClassifyFn,  NotifyFn,   FlowDeleteFn},

    //�����Լ�����ӡ�
    //...

    //�����������β��
    {&NULL_GUID, 0, NULL, NULL, NULL}
};


NTSTATUS CreateInjectionHandle()
{
    NTSTATUS NtStatus = STATUS_SUCCESS;

    NtStatus = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &g_Transport4_InjectionHandle);
    if (!NT_SUCCESS(NtStatus)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
        return NtStatus;
    }

    NtStatus = FwpsInjectionHandleCreate(AF_INET6, FWPS_INJECTION_TYPE_TRANSPORT, &g_Transport6_InjectionHandle);
    if (!NT_SUCCESS(NtStatus)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
        return NtStatus;
    }

    return NtStatus;
}


NTSTATUS RegisterCallouts()
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    FWPM_SESSION session = {0};

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    NtStatus = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(NtStatus)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
        return NtStatus;
    }

    NtStatus = FwpmTransactionBegin(g_EngineHandle, 0);
    if (!NT_SUCCESS(NtStatus)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
        FwpmEngineClose(g_EngineHandle);
        return NtStatus;
    }

    __try {
        NtStatus = CreateInjectionHandle();
        if (!NT_SUCCESS(NtStatus)) {
            __leave;
        }

        NtStatus = FwpsCalloutRegisterFilter(g_CalloutFilter);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
            __leave;
        }

        NtStatus = FwpmTransactionCommit(g_EngineHandle);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
            __leave;
        }
    } __finally {
        if (!NT_SUCCESS(NtStatus)) {
            FwpmTransactionAbort(g_EngineHandle);

            StopWFP();
        } else {
            ShowCalloutId();
        }
    }

    return NtStatus;
}


VOID NTAPI SubscriptionBFEStateChangeCallback(IN OUT void * context, IN FWPM_SERVICE_STATE newState)
//VOID SubscriptionBFEStateChangeCallback(_Inout_ VOID* pContext, _In_ FWPM_SERVICE_STATE bfeState)
/*
Purpose:  Callback, invoked on BFE service state change, which will get or release a handle to the engine.
MSDN_Ref: HTTP://MSDN.Microsoft.com/En-US/Library/Windows/Hardware/FF550062.aspx
�����ĵã�
1.����ϵͳ������ʱ������ FWPM_SERVICE_START_PENDING ������ FWPM_SERVICE_RUNNING ��
2.�����������ǲ���������ġ�
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(context);

    switch (newState) {
    case FWPM_SERVICE_RUNNING:
        //����FwpmEngineOpen��ȡEngineHandle��
        status = RegisterCallouts();
        break;
    case FWPM_SERVICE_STOP_PENDING:
        //Ҫ�����������һЩС������
        //����FwpmEngineClose�ͷ�EngineHandle��
        break;
    case FWPM_SERVICE_STOPPED://ϵͳ������ʱ����������
        break;
    case FWPM_SERVICE_START_PENDING://����ϵͳ������ʱ���������� 
        break;
    default:
        break;
    }
}


NTSTATUS StartWFP()
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    FWPM_SERVICE_STATE BfeState = FwpmBfeStateGet();//������ж������Ƿ���ϵͳ������״̬��

    if (FWPM_SERVICE_RUNNING == BfeState) {//FWPM_SERVICE_STOP_PENDING
        NtStatus = RegisterCallouts();
    } else {
        NtStatus = FwpmBfeStateSubscribeChanges(g_deviceObject,
                                                SubscriptionBFEStateChangeCallback,
                                                NULL,
                                                &g_ChangeHandle);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", NtStatus);
            return NtStatus;
        }
    }

    return NtStatus;
}
