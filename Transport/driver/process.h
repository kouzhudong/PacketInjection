#pragma once


#include "DriverEntry.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID CreateProcessNotifyEx(__inout PEPROCESS Process,
                           __in HANDLE ProcessId,
                           __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo
);

