#pragma once

#include <evntrace.h>

#define EVENT_TRACING 

#if !defined(EVENT_TRACING)

#define TRACEBITONE 1

VOID
TraceEvents(
    __in ULONG DebugPrintLevel,
    __in ULONG DebugPrintFlag,
    __drv_formatString(printf) __in PCSTR DebugMessage,
    ...
);

#define WPP_INIT_TRACING(DriverObject, RegistryPath)
#define WPP_CLEANUP(DriverObject)

#else

#define WPP_CHECK_FOR_NULL_STRING  // to prevent exceptions due to NULL strings.

#define WPP_CONTROL_GUIDS                                              \
    WPP_DEFINE_CONTROL_GUID(                                           \
        TESTWPPGuid, \
        (99999999,9999,9999,9999,999999999999), \
        WPP_DEFINE_BIT(TRACEBITONE)         \
        ) 

// For DoTraceLevelMessage
#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) (WPP_FLAG_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)
#define WPP_LEVEL_FLAGS_LOGGER(lvl, flags) WPP_LEVEL_LOGGER(flags)


//
// This comment block is scanned by the trace preprocessor to define our Trace function.
//
// begin_wpp config
// FUNC Trace{FLAGS=MYDRIVER_ALL_INFO}(LEVEL, MSG, ...);
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);
// FUNC TraceMessage(LEVEL,FLAGS, MSG,...);
// FUNC DbgPrintEx(LEVEL,FLAGS, MSG,...);
// FUNC TraceFatal{LEVEL=TRACE_LEVEL_FATAL,FLAGS=FlagDriverWideLog}(MSG,...);
// FUNC TraceError{LEVEL=TRACE_LEVEL_ERROR,FLAGS=FlagDriverWideLog}(MSG,...);
// FUNC TraceWarning{LEVEL=TRACE_LEVEL_WARNING,FLAGS=FlagDriverWideLog}(MSG,...);
// FUNC TraceInformation{LEVEL=TRACE_LEVEL_INFORMATION,FLAGS=FlagDriverWideLog}(MSG,...);
// FUNC TraceVerbose{LEVEL=TRACE_LEVEL_VERBOSE,FLAGS=FlagDriverWideLog}(MSG,...);
// end_wpp
//

#endif
