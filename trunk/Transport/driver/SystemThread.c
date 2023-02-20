#include "SystemThread.h"
#include "wfp.h"
#include "CommunicationPort.h"
#include "..\public\public.h"


LIST_ENTRY g_PacketList;/*PENDED_PACKET���͵�����,���ڱ���TCP��UDP�Ĳ���.*/
KSPIN_LOCK g_PacketListLock;


//////////////////////////////////////////////////////////////////////////////////////////////////


_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
_Success_(return != 0)
BYTE * NBLCopyToBuffer(_In_opt_ NET_BUFFER_LIST * pTemplateNBL, _Out_ SIZE_T * pSize)
/**
Purpose:  Copies the NBL to a buffer.
*/
{
    BYTE * pBuffer = 0;
    UINT32   numBytes = 0;

    *pSize = 0;

    if (pTemplateNBL) {
        for (NET_BUFFER * pNB = NET_BUFFER_LIST_FIRST_NB(pTemplateNBL); pNB; pNB = NET_BUFFER_NEXT_NB(pNB)) {
            numBytes += NET_BUFFER_DATA_LENGTH(pNB);
        }
    }

    if (numBytes) {
        pBuffer = (BYTE *)ExAllocatePoolWithTag(NonPagedPool, numBytes, TAG);
        ASSERT(pBuffer);
        RtlZeroMemory(pBuffer, numBytes);

        if (pTemplateNBL) {
            NET_BUFFER * pNB = NET_BUFFER_LIST_FIRST_NB(pTemplateNBL);

            for (UINT32 bytesCopied = 0; bytesCopied < numBytes && pNB; pNB = NET_BUFFER_NEXT_NB(pNB)) {
                BYTE * pContiguousBuffer = 0;
                UINT32 bytesNeeded = NET_BUFFER_DATA_LENGTH(pNB);

                if (bytesNeeded) {
                    BYTE * pAllocatedBuffer = (BYTE *)ExAllocatePoolWithTag(NonPagedPool, bytesNeeded, TAG);
                    ASSERT(pAllocatedBuffer);
                    RtlZeroMemory(pAllocatedBuffer, bytesNeeded);

                    pContiguousBuffer = (BYTE *)NdisGetDataBuffer(pNB, bytesNeeded, pAllocatedBuffer, 1, 0);

                    RtlCopyMemory(&(pBuffer[bytesCopied]),
                                  pContiguousBuffer ? pContiguousBuffer : pAllocatedBuffer,
                                  bytesNeeded);

                    bytesCopied += bytesNeeded;

                    ExFreePoolWithTag(pAllocatedBuffer, TAG);
                }
            }
        }

        *pSize = numBytes;
    }

    return pBuffer;
}


void FreePendedPacket(_Inout_ __drv_freesMem(Mem) PPENDED_PACKET packet)
{
    if (packet->NetBufferList != NULL) {
        FwpsDereferenceNetBufferList(packet->NetBufferList, FALSE);
    }

    if (packet->controlData != NULL) {
        ExFreePoolWithTag(packet->controlData, TAG);
    }

    ExFreePoolWithTag(packet, TAG);

    //PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL, "��Ϣ���ͷ� DataGram packet:%p", packet);
}


VOID NTAPI InjectComplete(_In_ VOID * Context,
                          _Inout_ NET_BUFFER_LIST * NetBufferList,
                          _In_ BOOLEAN DispatchLevel)
{
    PPENDED_PACKET packet = Context;

    UNREFERENCED_PARAMETER(DispatchLevel);

    FwpsFreeCloneNetBufferList(NetBufferList, 0);

    FreePendedPacket(packet);
}


NTSTATUS InboundInject(_In_ PPENDED_PACKET packet)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST * clonedNetBufferList = NULL;
    NET_BUFFER * netBuffer;
    ULONG nblOffset;
    NDIS_STATUS ndisStatus;
    //BOOLEAN isIPv6 = !LayerIsIPv4(packet->belongingFlow.layerId);
    HANDLE Transport_InjectionHandle = NULL;

    netBuffer = NET_BUFFER_LIST_FIRST_NB(packet->NetBufferList);// For inbound net buffer list, we can assume it contains only one net buffer.   
    nblOffset = NET_BUFFER_DATA_OFFSET(netBuffer);

    // The TCP/IP stack could have retreated the net buffer list by the transportHeaderSize amount; 
    // detect the condition here to avoid retreating twice.
    if (nblOffset != packet->nblOffset) {
        ASSERT(packet->nblOffset - nblOffset == packet->transportHeaderSize);
        packet->transportHeaderSize = 0;
    }

    // Adjust the net buffer list offset to the start of the IP header.
    ndisStatus = NdisRetreatNetBufferDataStart(netBuffer,
                                               packet->ipHeaderSize + packet->transportHeaderSize,
                                               0,
                                               NULL);
    _Analysis_assume_(ndisStatus == NDIS_STATUS_SUCCESS);

    // Note that the clone will inherit the original net buffer list's offset.
    status = FwpsAllocateCloneNetBufferList(packet->NetBufferList, NULL, NULL, 0, &clonedNetBufferList);

    // Undo the adjustment on the original net buffer list.
    NdisAdvanceNetBufferDataStart(netBuffer, packet->ipHeaderSize + packet->transportHeaderSize, FALSE, NULL);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
        return status;
    }

    if (packet->ipSecProtected) {
        UINT8 * remoteAddr = NULL;
        UINT8 * localAddr = NULL;

        switch (packet->belongingFlow.addressFamily) {
        case AF_INET:
        {
            ULONG ra = RtlUlongByteSwap(packet->belongingFlow.DestinationIp.ipv4.S_un.S_addr);
            ULONG la = RtlUlongByteSwap(packet->belongingFlow.SourceIp.ipv4.S_un.S_addr);

            remoteAddr = (UINT8 *)&ra;
            localAddr = (UINT8 *)&la;

            Transport_InjectionHandle = g_Transport4_InjectionHandle;

            break;
        }
        case AF_INET6:
            remoteAddr = (UINT8 *)&packet->belongingFlow.DestinationIp.ipv6;
            localAddr = (UINT8 *)&packet->belongingFlow.DestinationIp.ipv6;

            Transport_InjectionHandle = g_Transport6_InjectionHandle;

            break;
        default:
            ASSERT(FALSE);
            break;
        }

        // When an IpSec protected packet is indicated to AUTH_RECV_ACCEPT or INBOUND_TRANSPORT layers,
        // for performance reasons the tcpip stack does not remove the AH/ESP header from the packet.
        // And such packets cannot be recv-injected back to the stack w/o removing the AH/ESP header.
        // Therefore before re-injection we need to "re-build" the cloned packet.
        //status = FwpsConstructIpHeaderForTransportPacket(clonedNetBufferList,
        //                                                 packet->ipHeaderSize,
        //                                                 packet->belongingFlow.addressFamily,
        //                                                 remoteAddr,
        //                                                 localAddr,
        //                                                 packet->belongingFlow.Protocol,
        //                                                 0,
        //                                                 NULL,
        //                                                 0,
        //                                                 0,
        //                                                 NULL,
        //                                                 0,
        //                                                 0);
        status = FwpsConstructIpHeaderForTransportPacket(clonedNetBufferList,
                                                         packet->ipHeaderSize,
                                                         packet->addressFamily,
                                                         (UINT8 *)&packet->remoteAddr,
                                                         (UINT8 *)&packet->localAddr,
                                                         packet->protocol,
                                                         0,
                                                         NULL,
                                                         0,
                                                         0,
                                                         NULL,
                                                         0,
                                                         0);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
            FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
            return status;
        }
    }

    switch (packet->belongingFlow.addressFamily) {
    case AF_INET:
    {
        Transport_InjectionHandle = g_Transport4_InjectionHandle;
        break;
    }
    case AF_INET6:
        Transport_InjectionHandle = g_Transport6_InjectionHandle;
        break;
    default:
        ASSERT(FALSE);
        break;
    }

    //status = FwpsInjectTransportReceiveAsync(Transport_InjectionHandle,
    //                                         NULL,
    //                                         NULL,
    //                                         0,
    //                                         packet->belongingFlow.addressFamily,
    //                                         packet->compartmentId,
    //                                         packet->interfaceIndex,
    //                                         packet->subInterfaceIndex,
    //                                         clonedNetBufferList,
    //                                         InjectComplete,
    //                                         packet);
    status = FwpsInjectTransportReceiveAsync(Transport_InjectionHandle,
                                             NULL,
                                             NULL,
                                             0,
                                             packet->addressFamily,
                                             packet->compartmentId,
                                             packet->interfaceIndex,
                                             packet->subInterfaceIndex,
                                             clonedNetBufferList,
                                             InjectComplete,
                                             packet);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
    }

    return status;
}


NTSTATUS OutboundInject(_In_ PPENDED_PACKET packet)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST * clonedNetBufferList = NULL;
    FWPS_TRANSPORT_SEND_PARAMS sendArgs = {0};
    //BOOLEAN isIPv6 = !LayerIsIPv4(packet->belongingFlow.layerId);
    HANDLE Transport_InjectionHandle = NULL;
    UINT8 * remoteAddr = NULL;

    status = FwpsAllocateCloneNetBufferList(packet->NetBufferList, NULL, NULL, 0, &clonedNetBufferList);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
        return status;
    }

    switch (packet->belongingFlow.addressFamily) {
    case AF_INET:
    {
        ULONG ra = RtlUlongByteSwap(packet->belongingFlow.DestinationIp.ipv4.S_un.S_addr);

        remoteAddr = (UINT8 *)&ra;

        Transport_InjectionHandle = g_Transport4_InjectionHandle;

        break;
    }
    case AF_INET6:
        remoteAddr = (UINT8 *)&packet->belongingFlow.DestinationIp.ipv6;

        Transport_InjectionHandle = g_Transport6_InjectionHandle;

        break;
    default:
        ASSERT(FALSE);
        break;
    }

    //// Determine whehter we need to proxy the destination address. 
    //// If not, we set the remoteAddress to the same address that was initially classified.
    //sendArgs.remoteAddress = remoteAddr;
    //sendArgs.remoteScopeId = packet->remoteScopeId;
    //sendArgs.controlData = packet->controlData;
    //sendArgs.controlDataLength = packet->controlDataLength;

    //// Send-inject the modified net buffer list to the new destination address.
    //status = FwpsInjectTransportSendAsync(Transport_InjectionHandle,
    //                                      NULL,
    //                                      packet->endpointHandle,
    //                                      0,
    //                                      &sendArgs,
    //                                      packet->belongingFlow.addressFamily,
    //                                      packet->compartmentId,
    //                                      clonedNetBufferList,
    //                                      InjectComplete,
    //                                      packet);

    sendArgs.remoteAddress = (UINT8 *)(&packet->remoteAddr);
    sendArgs.remoteScopeId = packet->remoteScopeId;
    sendArgs.controlData = packet->controlData;
    sendArgs.controlDataLength = packet->controlDataLength;

    // Send-inject the cloned net buffer list.
    status = FwpsInjectTransportSendAsync(Transport_InjectionHandle,
                                          NULL,
                                          packet->endpointHandle,
                                          0,
                                          &sendArgs,
                                          packet->addressFamily,
                                          packet->compartmentId,
                                          clonedNetBufferList,
                                          InjectComplete,
                                          packet);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
        FwpsFreeCloneNetBufferList(clonedNetBufferList, 0);
    }

    return status;
}


NTSTATUS inject(PPENDED_PACKET packet)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (packet->belongingFlow.Direction == FWP_DIRECTION_OUTBOUND) {
        status = OutboundInject(packet);
    } else {
        status = InboundInject(packet);
    }

    return status;
}


void CopyPackInfo2User(IN PPENDED_PACKET packet, OUT PNOTIFICATION SentToUser)
/*
���ܣ�����PPENDED_PACKET����Ϣ������PFLOW_DATA����Ϣ����PNOTIFICATION��
*/
{
    SentToUser->Direction = packet->belongingFlow.Direction;

    SentToUser->Protocol = packet->belongingFlow.Protocol;

    SentToUser->SourceIp.addressFamily = packet->belongingFlow.addressFamily;

    switch (packet->belongingFlow.addressFamily) {
    case AF_INET:
        SentToUser->SourceIp.ipv4.S_un.S_addr = packet->belongingFlow.SourceIp.ipv4.S_un.S_addr;
        break;
    case AF_INET6:
        RtlCopyMemory(&SentToUser->SourceIp.ipv6, &packet->belongingFlow.SourceIp.ipv6, IPV6_ADDRESS_LENGTH);
        break;
    default:
        ASSERT(FALSE);
        break;
    }

    SentToUser->SourcePort = packet->belongingFlow.SourcePort;

    SentToUser->DestinationIp.addressFamily = packet->belongingFlow.addressFamily;

    switch (packet->belongingFlow.addressFamily) {
    case AF_INET:
        SentToUser->DestinationIp.ipv4.S_un.S_addr = packet->belongingFlow.DestinationIp.ipv4.S_un.S_addr;
        break;
    case AF_INET6:
        RtlCopyMemory(&SentToUser->DestinationIp.ipv6, &packet->belongingFlow.DestinationIp.ipv6, IPV6_ADDRESS_LENGTH);
        break;
    default:
        ASSERT(FALSE);
        break;
    }

    SentToUser->DestinationPort = packet->belongingFlow.DestinationPort;

    if (packet->belongingFlow.size >= MAX_PATH * sizeof(WCHAR)) {
        UNICODE_STRING temp = {0};

        temp.Buffer = packet->belongingFlow.processPath;
        temp.Length = (USHORT)packet->belongingFlow.size;
        temp.MaximumLength = temp.Length;

        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "���棺processPath:%wZ", temp);
    }

    SentToUser->size = min(MAX_PATH * sizeof(WCHAR), packet->belongingFlow.size);
    RtlCopyMemory(&SentToUser->processPath, packet->belongingFlow.processPath, SentToUser->size);

    SentToUser->processId = packet->belongingFlow.processId;
}


void CopyToUserMemory(IN PPENDED_PACKET packet, OUT PNOTIFICATION SentToUser)
/*
��Ϊ����û��ӳ���ȥ���������︴�ƹ�ȥ��

��;������ӳ���Ӧ�ò��ڴ档
*/
{
    KAPC_STATE   ApcState;

    if (NULL == g_Data.UserProcess) {
        return;
    }

    KeStackAttachProcess(g_Data.UserProcess, &ApcState);

    __try {
        ProbeForRead(SentToUser->UserBuffer, SentToUser->UserBufferLength, 1);
        ProbeForWrite(SentToUser->UserBuffer, SentToUser->UserBufferLength, 1);

        RtlCopyMemory(SentToUser->UserBuffer, packet->KernelBuffer, packet->KernelBufferLength);

        SentToUser->DataLength = packet->KernelBufferLength;//����ɹ��ˣ���Ū�����
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "ExceptionCode:%#x", GetExceptionCode());
    }

    KeUnstackDetachProcess(&ApcState);
}


void MapPackInfo2User(IN PPENDED_PACKET packet, OUT PNOTIFICATION SentToUser)
/*
���ܣ���������Ϣӳ�䵽������ͨѶ�Ľ��̡�
      ȥ����д�����ԣ���Ϊ��ʱ��֧���޸ĵĲ�����

ʵ�ְ취��
1.MmMapLockedPagesSpecifyCache + KeStackAttachProcess��
2.ZwMapViewOfSection
3.MmmapViewOfSection
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE  Handle = 0;
    OBJECT_ATTRIBUTES ObjectAttributes = {0};
    HANDLE Section = NULL;
    LARGE_INTEGER MaximumSize = {0};//ZwCreateSection rounds this value up to the nearest multiple of PAGE_SIZE.

    if (0 == packet->DataLength || NULL == g_Data.UserProcess) {
        return;
    }

    packet->KernelBuffer = NBLCopyToBuffer(packet->NetBufferList, &packet->KernelBufferLength);
    if (NULL == packet->KernelBuffer) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "ע�⣺������������ʧ�ܣ����ȣ�%d", (int)packet->DataLength);
        return;
    }

    if (packet->DataLength != packet->KernelBufferLength) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL,
                "���棺�������ݿ��ܶ�ʧ��DataLength��%d��KernelBufferLength��%d",
                (int)packet->DataLength,
                (int)packet->KernelBufferLength);//��ʱ��Ӧ�����Ϊ׼��
    }

    MaximumSize.QuadPart = packet->KernelBufferLength;
    InitializeObjectAttributes(&ObjectAttributes, NULL, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
    status = ZwCreateSection(&Section,
                             SECTION_MAP_READ | SECTION_MAP_WRITE,// | SECTION_MAP_EXECUTE
                             &ObjectAttributes,
                             &MaximumSize,
                             PAGE_READWRITE,//PAGE_READONLY PAGE_EXECUTE_READWRITE
                             SEC_COMMIT,
                             NULL);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
        return;
    }

    status = ObOpenObjectByPointer(g_Data.UserProcess,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_ALL | PROCESS_VM_OPEARATION | 0xfff,
                                   *PsProcessType,
                                   UserMode,
                                   &Handle);//ע��Ҫ�رվ����  
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
        ZwClose(Section);
        return;
    }

    status = ZwMapViewOfSection(Section,
                                Handle,
                                (PVOID *)&SentToUser->UserBuffer,
                                0L,
                                packet->KernelBufferLength,
                                NULL,
                                &SentToUser->UserBufferLength,
                                ViewShare,
                                0L,
                                PAGE_READWRITE); //PAGE_READONLY PAGE_EXECUTE_READWRITE
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
    } else {
        CopyToUserMemory(packet, SentToUser);//����ûӳ�䣬ֻ�����ÿ�д���ԣ�Ȼ���ơ�
        //�����֧���޸��������ݣ��������ڴ�Ϊֻ�����ԡ�
    }

    //ZwUnmapViewOfSection(Handle, ViewBase);//�����ֹ�˲�����
    ZwClose(Section);
    ZwClose(Handle);
}


void UnMapPackInfo2User(IN PPENDED_PACKET packet, OUT PNOTIFICATION SentToUser)
/*
���ܣ���������Ϣӳ�䵽������ͨѶ�Ľ��̡�
      ȥ����д�����ԣ���Ϊ��ʱ��֧���޸ĵĲ�����

ʵ�ְ취��
1.MmMapLockedPagesSpecifyCache + KeStackAttachProcess��
2.ZwMapViewOfSection
3.MmmapViewOfSection
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE  KernelHandle = 0;

    if (SentToUser->UserBuffer && NULL != g_Data.UserProcess) {
        status = ObOpenObjectByPointer(g_Data.UserProcess,
                                       OBJ_KERNEL_HANDLE,
                                       NULL,
                                       GENERIC_ALL | PROCESS_VM_OPEARATION | 0xfff,
                                       *PsProcessType,
                                       UserMode,
                                       &KernelHandle);//ע��Ҫ�رվ����  
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
        } else {
            __try {
                /*
                ����������ں˾����
                �����ҪUNMAPȨ�ޡ�
                */
                status = ZwUnmapViewOfSection(KernelHandle, SentToUser->UserBuffer);
                if (!NT_SUCCESS(status)) {
                    PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "����status:%#x", status);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Print(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "ExceptionCode:%#x", GetExceptionCode());
            }

            ZwClose(KernelHandle);
        }
    }

    if (packet->KernelBuffer) {
        ExFreePoolWithTag(packet->KernelBuffer, TAG);
    }
}


BOOL IsBlockPacker(PPENDED_PACKET packet)
/*
����FltSendMessageʵ�֡�

������һЩ׼�����磺ӳ������ڴ浽Ӧ�ò㣬��ʱ�����ڴ�Ϊֻ���������޸ġ�
*/
{
    BOOL IsBlock = FALSE;
    PNOTIFICATION SentToUser = NULL;
    ULONG replyLength;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    LARGE_INTEGER timeout = {0};

    PAGED_CODE();

    //Ӧ�ò�û���������Ӳ����롣
    if (NULL == g_Data.ClientPort || NULL == g_Data.UserProcess) {
        return IsBlock;
    }

    //�Ź�������ͨѶ�Ľ��̡�
    if (g_Data.UserProcess == PsGetCurrentProcess()) {
        return IsBlock;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //��д���ظ�Ӧ�ò����Ϣ��

    SentToUser = ExAllocatePoolWithTag(PagedPool, sizeof(NOTIFICATION), TAG);
    ASSERT(SentToUser);
    RtlZeroMemory(SentToUser, sizeof(NOTIFICATION));

    CopyPackInfo2User(packet, SentToUser);
    MapPackInfo2User(packet, SentToUser);

    //////////////////////////////////////////////////////////////////////////////////////////////

    /*
    ������������ļ�����ȴ������ӣ�һ�㲻�Ῠ�ģ�����������������ͬ���ҵ��̵߳ı�����
    ����̨�Ĵ�ӡ�ַ�Ҳͦռ��ʱ���CPU�ġ�
    */
    replyLength = sizeof(REPLY);
    timeout.QuadPart = -((LONGLONG)10) * (LONGLONG)1000 * (LONGLONG)1000 * 1; // 1s
    status = FltSendMessage(g_Data.Filter,
                            &g_Data.ClientPort,
                            SentToUser,
                            sizeof(NOTIFICATION),
                            SentToUser,
                            &replyLength,
                            &timeout);
    switch (status) {
    case STATUS_SUCCESS:
        IsBlock = ((PREPLY)SentToUser)->IsBlock;
        break;
    case STATUS_TIMEOUT:
        Print(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "TIMEOUT");
        break;
    case STATUS_PORT_DISCONNECTED:
        Print(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "PORT DISCONNECTED");
        break;
    case STATUS_THREAD_IS_TERMINATING:
        Print(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "THREAD IS TERMINATING");
        break;
    default:
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "status:%#x", status);
        break;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    //������ɨβ������

    UnMapPackInfo2User(packet, SentToUser);
    ExFreePoolWithTag(SentToUser, TAG);
    return IsBlock;
}


_IRQL_requires_(PASSIVE_LEVEL)
VOID ProcessPacket(PPENDED_PACKET packet)
{
    BOOL IsBlock = IsBlockPacker(packet);

    if (IsBlock) {
        /*
        ������ע�����.
        */
        PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, "ע�⣺packet:0x%p", packet);
    } else {
        if (!packet->belongingFlow.deleting) {
            NTSTATUS status = inject(packet);
            if (NT_SUCCESS(status)) {
                packet = NULL;
            }
        }
    }

    if (packet != NULL) {
        FreePendedPacket(packet);
    }
}


VOID WorkThread(_In_ PVOID StartContext)
{
    PPENDED_PACKET packet;
    PLIST_ENTRY listEntry;
    KLOCK_QUEUE_HANDLE packetQueueLockHandle;

    UNREFERENCED_PARAMETER(StartContext);

    for (;;) {
        if (gDriverUnloading) {
            break;
        }

        listEntry = NULL;

        KeAcquireInStackQueuedSpinLock(&g_PacketListLock, &packetQueueLockHandle);
        if (!IsListEmpty(&g_PacketList)) {
            listEntry = RemoveHeadList(&g_PacketList);
        }
        KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);

        if (NULL != listEntry) {
            packet = CONTAINING_RECORD(listEntry, PENDED_PACKET, listEntry);
            ProcessPacket(packet);
        } else {
            LARGE_INTEGER   li;

            li.QuadPart = (1 * (((-10) * 1000) * 1000)); //��������ͣ1���ӡ�
            KeDelayExecutionThread(KernelMode, FALSE, &li);
        }
    }

    ASSERT(gDriverUnloading);

    KeAcquireInStackQueuedSpinLock(&g_PacketListLock, &packetQueueLockHandle);
    while (!IsListEmpty(&g_PacketList)) {
        listEntry = RemoveHeadList(&g_PacketList);
        packet = CONTAINING_RECORD(listEntry, PENDED_PACKET, listEntry);
        FreePendedPacket(packet);
    }
    KeReleaseInStackQueuedSpinLock(&packetQueueLockHandle);

    PsTerminateSystemThread(STATUS_SUCCESS);
}
