#pragma once

#include "DriverEntry.h"


#define PROCESS_VM_OPEARATION 8


//////////////////////////////////////////////////////////////////////////////////////////////////


extern LIST_ENTRY g_PacketList;
extern KSPIN_LOCK g_PacketListLock;


KSTART_ROUTINE WorkThread;
