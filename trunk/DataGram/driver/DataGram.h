#pragma once

#include "DriverEntry.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void NTAPI DataGramClassifyFn(_In_ const FWPS_INCOMING_VALUES0 * pClassifyValues,
                              _In_ const FWPS_INCOMING_METADATA_VALUES0 * pMetadata,
                              _Inout_opt_ void * layerData,
                              _In_opt_ const void * classifyContext,
                              _In_ const FWPS_FILTER1 * filter,
                              _In_ UINT64 flowContext,
                              _Inout_ FWPS_CLASSIFY_OUT0 * pClassifyOut
);


//////////////////////////////////////////////////////////////////////////////////////////////////
