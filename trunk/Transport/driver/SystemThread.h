#pragma once

#include "DriverEntry.h"


#define PROCESS_VM_OPEARATION 8


//////////////////////////////////////////////////////////////////////////////////////////////////


extern LIST_ENTRY g_PacketList;
extern KSPIN_LOCK g_PacketListLock;
extern KEVENT g_PacketEvent;//数据包入队时被置位，唤醒工作线程，取代轮询。


KSTART_ROUTINE WorkThread;
