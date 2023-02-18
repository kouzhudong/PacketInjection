#pragma once

#include <winsock2.h>//Do not include winsock.h and ws2def.h in the same module. Instead include only winsock2.h.
#include <windows.h>
#include <strsafe.h>
#include <assert.h>
#include <crtdbg.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <locale.h>
#include <Lmserver.h>
#include <stdarg.h>
#include <wincrypt.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <aclapi.h>
#include <VersionHelpers.h>
#include <ShlDisp.h>
#include <Shlobj.h>
#include <Softpub.h>
#include <mscat.h>
//#include <SubAuth.h>
//#include <LsaLookup.h>
#include <WinUser.h>
#include <direct.h>
#include <sddl.h>
#include <fwptypes.h>
#include <ws2tcpip.h>

//#include <winternl.h>
#include <SubAuth.h>
//#include <NTSecAPI.h>
//#include <ntdef.h>
//#include <netioapi.h>

#include <string>
#include <list>

#include <atlconv.h>

#include <bcrypt.h>
#pragma comment (lib, "Bcrypt.lib")

#include <ncrypt.h>
#pragma comment (lib, "Ncrypt.lib")

#include <wintrust.h>
#pragma comment (lib, "wintrust.lib")

#include <Setupapi.h>
#pragma comment (lib,"Setupapi.lib")

#include <Shlwapi.h>
#pragma comment (lib,"Shlwapi.lib")

#include <DbgHelp.h>
#pragma comment (lib,"DbgHelp.lib")

#pragma comment(lib, "crypt32.lib")

#include <psapi.h>
#pragma comment(lib, "Psapi.lib")

#include <Sfc.h>
#pragma comment(lib, "Sfc.lib")

#include <winsock.h>
#pragma comment(lib, "Ws2_32.lib")

#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")

#pragma comment(lib, "Version.lib") 

#include <Wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

#include <Userenv.h>
#pragma comment(lib, "Userenv.lib")

#include <fltuser.h>
#pragma comment (lib, "fltLib.lib")

#include <fwpmu.h>
#pragma comment (lib, "Fwpuclnt.lib")

using namespace std;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef enum _SYSTEM_INFORMATION_CLASS {// System Information Classes.
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;


typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);


typedef NTSTATUS(WINAPI* NtQuerySystemInformation_PFN)(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                                       __out_bcount_opt(SystemInformationLength) PVOID SystemInformation,
                                                       __in ULONG SystemInformationLength,
                                                       __out_opt PULONG ReturnLength
                                                       );


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef
LPTSTR(NTAPI* PRtlIpv6AddressToString)(
    __in          const IN6_ADDR* Addr,
    __out         LPTSTR S
    );


extern PRtlIpv6AddressToString Ipv6AddressToStringW;


//https://msdn.microsoft.com/en-us/library/windows/desktop/ms738518%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
//其实：IPV4的只需This buffer should be large enough to hold at least 16 characters.
#define MAX_ADDRESS_STRING_LENGTH   64


//十进制的端口字符串的长度。其实最大长度是5，可以设置为8。
#define MAX_PORT_STRING_LENGTH  5  //65535==FFFF 
