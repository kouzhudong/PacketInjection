#include "Auxiliary.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOLEAN LayerIsIPv4(_In_ UINT32 layerID)
/**
Purpose: Determine if the layer is an IPv4 layer.

说明：
1.摘自Windows Filtering Platform Sample工程的KrnlHlprFwpmLayerIsIPv4函数。
2.inspect工程有个GetAddressFamilyForLayer函数，功能类似，但是简单。
3.DDProxy工程是直接和FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4比较的，这个最简单。
*/
{
    BOOLEAN isIPv4 = FALSE;

    if (layerID == FWPS_LAYER_INBOUND_IPPACKET_V4 ||
        layerID == FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD ||
        layerID == FWPS_LAYER_OUTBOUND_IPPACKET_V4 ||
        layerID == FWPS_LAYER_OUTBOUND_IPPACKET_V4_DISCARD ||
        layerID == FWPS_LAYER_IPFORWARD_V4 ||
        layerID == FWPS_LAYER_IPFORWARD_V4_DISCARD ||
        layerID == FWPS_LAYER_INBOUND_TRANSPORT_V4 ||
        layerID == FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD ||
        layerID == FWPS_LAYER_OUTBOUND_TRANSPORT_V4 ||
        layerID == FWPS_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD ||
        layerID == FWPS_LAYER_STREAM_V4 ||
        layerID == FWPS_LAYER_STREAM_V4_DISCARD ||
        layerID == FWPS_LAYER_DATAGRAM_DATA_V4 ||
        layerID == FWPS_LAYER_DATAGRAM_DATA_V4_DISCARD ||
        layerID == FWPS_LAYER_INBOUND_ICMP_ERROR_V4 ||
        layerID == FWPS_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD ||
        layerID == FWPS_LAYER_OUTBOUND_ICMP_ERROR_V4 ||
        layerID == FWPS_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4 ||
        layerID == FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_AUTH_LISTEN_V4 ||
        layerID == FWPS_LAYER_ALE_AUTH_LISTEN_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_AUTH_CONNECT_V4 ||
        layerID == FWPS_LAYER_ALE_AUTH_CONNECT_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ||
        layerID == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 ||
        layerID == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD ||
#if(NTDDI_VERSION >= NTDDI_WIN7)
        layerID == FWPS_LAYER_NAME_RESOLUTION_CACHE_V4 ||
        layerID == FWPS_LAYER_ALE_RESOURCE_RELEASE_V4 ||
        layerID == FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 ||
        layerID == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 ||
        layerID == FWPS_LAYER_ALE_BIND_REDIRECT_V4 ||
        layerID == FWPS_LAYER_STREAM_PACKET_V4 ||
#if(NTDDI_VERSION >= NTDDI_WIN8)
        layerID == FWPS_LAYER_INGRESS_VSWITCH_TRANSPORT_V4 ||
        layerID == FWPS_LAYER_EGRESS_VSWITCH_TRANSPORT_V4 ||
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
        layerID == FWPS_LAYER_IPSEC_KM_DEMUX_V4 ||
        layerID == FWPS_LAYER_IPSEC_V4 ||
        layerID == FWPS_LAYER_IKEEXT_V4) {
        isIPv4 = TRUE;
    }

    return isIPv4;
}


void GetFlagsIndexesForLayer(_In_ UINT16 layerId, _Out_ UINT * flagsIndex)
/*
摘自：\Windows-driver-samples\network\trans\inspect\sys\utils.h

正确按照FWPS_BUILTIN_LAYERS_的顺序补充完毕。
*/
{
    switch (layerId) {
    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
        *flagsIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_FLAGS;
        break;
    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
        *flagsIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_FLAGS;
        break;

    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
        *flagsIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_FLAGS;
        break;
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
        *flagsIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_FLAGS;
        break;

    case FWPS_LAYER_STREAM_V4:
        *flagsIndex = FWPS_FIELD_STREAM_V4_FLAGS;
        break;
    case FWPS_LAYER_STREAM_V6:
        *flagsIndex = FWPS_FIELD_STREAM_V6_FLAGS;
        break;

    case FWPS_LAYER_DATAGRAM_DATA_V4:
        *flagsIndex = FWPS_FIELD_DATAGRAM_DATA_V4_FLAGS;
        break;
    case FWPS_LAYER_DATAGRAM_DATA_V6:
        *flagsIndex = FWPS_FIELD_DATAGRAM_DATA_V6_FLAGS;
        break;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        *flagsIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        *flagsIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS;
        break;

    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        *flagsIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        *flagsIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS;
        break;

    default:
        *flagsIndex = UINT_MAX;
        NT_ASSERT(0);
        break;
    }
}


ADDRESS_FAMILY GetAddressFamilyForLayer(_In_ UINT16 layerId)
{
    ADDRESS_FAMILY addressFamily;

    switch (layerId) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
        addressFamily = AF_INET;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
        addressFamily = AF_INET6;
        break;
    default:
        addressFamily = AF_UNSPEC;
        NT_ASSERT(0);
    }

    return addressFamily;
}


FWP_DIRECTION GetPacketDirectionForLayer(_In_ UINT16 layerId)
{
    FWP_DIRECTION direction;

    switch (layerId) {
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
        direction = FWP_DIRECTION_OUTBOUND;
        break;
    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
        direction = FWP_DIRECTION_INBOUND;
        break;
    default:
        direction = FWP_DIRECTION_MAX;
        NT_ASSERT(0);
    }

    return direction;
}


void GetDeliveryInterfaceIndexesForLayer(_In_ UINT16 layerId,
                                         _Out_ UINT * interfaceIndexIndex,
                                         _Out_ UINT * subInterfaceIndexIndex)
{
    *interfaceIndexIndex = 0;
    *subInterfaceIndexIndex = 0;

    switch (layerId) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        *interfaceIndexIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX;
        *subInterfaceIndexIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_SUB_INTERFACE_INDEX;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        *interfaceIndexIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_INDEX;
        *subInterfaceIndexIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_SUB_INTERFACE_INDEX;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        *interfaceIndexIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_INDEX;
        *subInterfaceIndexIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SUB_INTERFACE_INDEX;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        *interfaceIndexIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_INDEX;
        *subInterfaceIndexIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SUB_INTERFACE_INDEX;
        break;
    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
        *interfaceIndexIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_INTERFACE_INDEX;
        *subInterfaceIndexIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX;
        break;
    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
        *interfaceIndexIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_INTERFACE_INDEX;
        *subInterfaceIndexIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_SUB_INTERFACE_INDEX;
        break;
    default:
        NT_ASSERT(0);
        break;
    }
}


void GetNetwork5TupleIndexesForLayer(_In_ UINT16 layerId,
                                     _Out_ UINT * localAddressIndex,
                                     _Out_ UINT * remoteAddressIndex,
                                     _Out_ UINT * localPortIndex,
                                     _Out_ UINT * remotePortIndex,
                                     _Out_ UINT * protocolIndex)
{
    switch (layerId) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        *localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        *localAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        *localAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        *localAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
        break;
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
        *localAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL;
        break;
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
        *localAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL;
        break;
    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
        *localAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL;
        break;
    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
        *localAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS;
        *remoteAddressIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS;
        *localPortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT;
        *remotePortIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT;
        *protocolIndex = FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL;
        break;
    default:
        *localAddressIndex = UINT_MAX;
        *remoteAddressIndex = UINT_MAX;
        *localPortIndex = UINT_MAX;
        *remotePortIndex = UINT_MAX;
        *protocolIndex = UINT_MAX;
        NT_ASSERT(0);
    }
}


void FillNetwork5Tuple(_In_ const FWPS_INCOMING_VALUES * inFixedValues,
                       _In_ ADDRESS_FAMILY addressFamily,
                       _Inout_ PPENDED_PACKET packet)
{
    UINT localAddrIndex;
    UINT remoteAddrIndex;
    UINT localPortIndex;
    UINT remotePortIndex;
    UINT protocolIndex;

    GetNetwork5TupleIndexesForLayer(inFixedValues->layerId,
                                    &localAddrIndex,
                                    &remoteAddrIndex,
                                    &localPortIndex,
                                    &remotePortIndex,
                                    &protocolIndex);

    if (addressFamily == AF_INET) {
        packet->ipv4LocalAddr = RtlUlongByteSwap( /* host-order -> network-order conversion */
                                                 inFixedValues->incomingValue[localAddrIndex].value.uint32);
        packet->ipv4RemoteAddr = RtlUlongByteSwap( /* host-order -> network-order conversion */
                                                  inFixedValues->incomingValue[remoteAddrIndex].value.uint32);
    } else {
        ASSERT(addressFamily == AF_INET6);
        RtlCopyMemory((UINT8 *)&packet->localAddr,
                      inFixedValues->incomingValue[localAddrIndex].value.byteArray16,
                      sizeof(FWP_BYTE_ARRAY16));
        RtlCopyMemory((UINT8 *)&packet->remoteAddr,
                      inFixedValues->incomingValue[remoteAddrIndex].value.byteArray16,
                      sizeof(FWP_BYTE_ARRAY16));
    }

    packet->localPort = RtlUshortByteSwap(inFixedValues->incomingValue[localPortIndex].value.uint16);
    packet->remotePort = RtlUshortByteSwap(inFixedValues->incomingValue[remotePortIndex].value.uint16);
    packet->protocol = inFixedValues->incomingValue[protocolIndex].value.uint8;
}
