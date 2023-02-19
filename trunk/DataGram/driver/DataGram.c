#include "DataGram.h"
#include "Register.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


PPENDED_PACKET BuildDataGramPendPacket(_In_ const FWPS_INCOMING_VALUES * inFixedValues,
                                       _In_ const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
                                       _Inout_opt_ void * layerData,
                                       PFLOW_DATA flowContextLocal)
{
    PPENDED_PACKET packet = NULL;

    if (NULL == flowContextLocal) {
        return packet;
    }

    packet = ExAllocatePoolWithTag(NonPagedPool, sizeof(PENDED_PACKET), TAG);
    if (NULL == packet) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "信息：%s", "申请内存失败");
        return packet;
    }
    RtlZeroMemory(packet, sizeof(PENDED_PACKET));

    PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "信息：创建 DataGram packet:%p", packet);

    packet->belongingFlow = flowContextLocal;

    ReferenceFlowContext(flowContextLocal);/*防止内存被释放*/

    if (flowContextLocal->addressFamily == AF_INET) {
        packet->direction = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_DIRECTION].value.uint32;
    } else {
        packet->direction = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_DIRECTION].value.uint32;
    }

    packet->NetBufferList = layerData;
    FwpsReferenceNetBufferList(packet->NetBufferList, TRUE);// Reference the net buffer list to make it accessible outside of classifyFn.

    ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_COMPARTMENT_ID));
    packet->compartmentId = inMetaValues->compartmentId;

    if (packet->direction == FWP_DIRECTION_OUTBOUND) {
        ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE));
        packet->endpointHandle = inMetaValues->transportEndpointHandle;

        if (flowContextLocal->addressFamily == AF_INET) {// See PREfast comments above.  Opaque pointer tricks PREfast.            
            UINT32 uint32 = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
            packet->ipv4RemoteAddr = RtlUlongByteSwap(uint32);/* host-order -> network-order conversion */
        } else {
            FWP_BYTE_ARRAY16 * byteArray16 = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS].value.byteArray16;
            RtlCopyMemory((UINT8 *)&packet->remoteAddr, byteArray16, sizeof(FWP_BYTE_ARRAY16));
        }

        packet->remoteScopeId = inMetaValues->remoteScopeId;

        if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA)) {
            ASSERT(inMetaValues->controlDataLength > 0);

            packet->controlData = ExAllocatePoolWithTag(NonPagedPool, inMetaValues->controlDataLength, TAG);
            ASSERT(packet->controlData);
            RtlCopyMemory(packet->controlData, inMetaValues->controlData, inMetaValues->controlDataLength);

            packet->controlDataLength = inMetaValues->controlDataLength;
        }
    } else {
        //ASSERT(packet->direction == FWP_DIRECTION_INBOUND);

        if (flowContextLocal->addressFamily == AF_INET) {
            packet->interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_INTERFACE_INDEX].value.uint32;
            packet->subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_SUB_INTERFACE_INDEX].value.uint32;
        } else {
            packet->interfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_INTERFACE_INDEX].value.uint32;
            packet->subInterfaceIndex = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_SUB_INTERFACE_INDEX].value.uint32;
        }

        //ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_IP_HEADER_SIZE));
        //ASSERT(FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE));

        packet->ipHeaderSize = inMetaValues->ipHeaderSize;
        packet->transportHeaderSize = inMetaValues->transportHeaderSize;
        packet->nblOffset = NET_BUFFER_DATA_OFFSET(NET_BUFFER_LIST_FIRST_NB(packet->NetBufferList));
    }

    for (NET_BUFFER * pNB = NET_BUFFER_LIST_FIRST_NB(packet->NetBufferList); pNB; pNB = NET_BUFFER_NEXT_NB(pNB)) {
        packet->DataLength += NET_BUFFER_DATA_LENGTH(pNB);
    }

    return packet;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void NTAPI DataGramClassifyFn(_In_ const FWPS_INCOMING_VALUES0 * pClassifyValues,
                              _In_ const FWPS_INCOMING_METADATA_VALUES0 * pMetadata,
                              _Inout_opt_ void * layerData,
                              _In_opt_ const void * classifyContext,
                              _In_ const FWPS_FILTER1 * filter,
                              _In_ UINT64 flowContext,
                              _Inout_ FWPS_CLASSIFY_OUT0 * pClassifyOut
)
{
    PFLOW_DATA flowData = *(PFLOW_DATA *)(UINT64 *)&flowContext;
    KLOCK_QUEUE_HANDLE lockHandle;
    //NET_BUFFER_LIST * IoPacket = (NET_BUFFER_LIST *)layerData;
    FWPS_PACKET_INJECTION_STATE packetState;
    PPENDED_PACKET packet = NULL;
    UINT flagsIndex = 0;
    UINT32 flags = 0;

    UNREFERENCED_PARAMETER(classifyContext);

    //////////////////////////////////////////////////////////////////////////////////////////////
    //放过一些处理。

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

    //////////////////////////////////////////////////////////////////////////////////////////////

     /*
     获取/制作一个节点信息.
     */
    packet = BuildDataGramPendPacket(pClassifyValues, pMetadata, layerData, flowData);
    if (packet == NULL) {
        pClassifyOut->actionType = FWP_ACTION_PERMIT;
        if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
            pClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
        return;
    }

    GetNetWorkInfo(pClassifyValues, packet);

    //////////////////////////////////////////////////////////////////////////////////////////////

    /*
    插入一个节点.
    */
    KeAcquireInStackQueuedSpinLock(&g_PacketListLock, &lockHandle);
    InsertTailList(&g_PacketList, &packet->listEntry);
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    //////////////////////////////////////////////////////////////////////////////////////////////

    pClassifyOut->actionType = FWP_ACTION_BLOCK;
    pClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    pClassifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
