#pragma once


#include "DriverEntry.h"
#include "pch.h"
#include "wfp.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOLEAN LayerIsIPv4(_In_ UINT32 layerID);
void GetFlagsIndexesForLayer(_In_ UINT16 layerId, _Out_ UINT * flagsIndex);
ADDRESS_FAMILY GetAddressFamilyForLayer(_In_ UINT16 layerId);
FWP_DIRECTION GetPacketDirectionForLayer(_In_ UINT16 layerId);
void GetDeliveryInterfaceIndexesForLayer(_In_ UINT16 layerId,
                                         _Out_ UINT * interfaceIndexIndex,
                                         _Out_ UINT * subInterfaceIndexIndex);
