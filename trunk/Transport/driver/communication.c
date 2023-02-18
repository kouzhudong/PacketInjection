#include "communication.h"
#include "..\public\public.h"

//#include "trace.h"
//#include "communication.tmh"

#ifdef ALLOC_PRAGMA
//pragma alloc_text()
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


//#pragma PAGEDCODE
//#pragma  code_seg("PAGE")
#pragma alloc_text(PAGE, CreateClose)
_Function_class_(DRIVER_DISPATCH)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS CreateClose(_In_ struct _DEVICE_OBJECT * DeviceObject, _Inout_ struct _IRP * Irp)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    switch (irpStack->MajorFunction) {
    case IRP_MJ_CREATE:
#if defined(_WIN64)
        if (IoIs32bitProcess(Irp)) {
            Status = STATUS_UNSUCCESSFUL;//不支持WOW64.
        }
#endif
        if (STATUS_SUCCESS == Status) {
            //gLogProcess = PsGetCurrentProcessId();
        }
        break;
    case IRP_MJ_CLOSE:/*关闭句柄和进程退出会走这里*/

        break;
    default:
        break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}


//#pragma PAGEDCODE
//#pragma  code_seg("PAGE")
#pragma alloc_text(PAGE, DeviceControl)
_Function_class_(DRIVER_DISPATCH)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
NTSTATUS DeviceControl(_In_ struct _DEVICE_OBJECT * DeviceObject, _Inout_ struct _IRP * Irp)
{
    NTSTATUS            status = STATUS_SUCCESS;
    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG               ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    //ULONG               inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    //ULONG               outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    //PUCHAR              InputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    //PUCHAR              OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    switch (ioControlCode) {
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
