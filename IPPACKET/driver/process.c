#include "process.h"
#include "CommunicationPort.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#pragma alloc_text(PAGE, CreateProcessNotifyEx)
VOID CreateProcessNotifyEx(__inout PEPROCESS Process,
                           __in HANDLE ProcessId,
                           __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo
)
/*

*/
{
    UNREFERENCED_PARAMETER(ProcessId);

    PAGED_CODE();

    if (CreateInfo) {
        NOTHING;
    } else {
        if (Process == g_Data.UserProcess) {
            InterlockedExchangePointer(&g_Data.UserProcess, NULL);
        }
    }
}
