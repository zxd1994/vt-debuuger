#pragma warning( disable : 4201)
//#include <ntddk.h>
#include "Ioctl.h"
#include "Hider.h"
#include "Utils.h"
#include "KuserSharedData.h"
#include "GlobalData.h"
#include "Peb.h"
#include "HypervisorGateway.h"
#include "Log.h"

extern HYPER_HIDE_GLOBAL_DATA g_HyperHide;

#include "CKernelDbg.h"
#define CTL_LOAD_DRIVER        0x800
#define CTL_UNLOAD_DRIVER      0x801
CKernelDbg CreateDebugger;
NTSTATUS DrvIOCTLDispatcher(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;

	switch (Stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case CTL_CODE(FILE_DEVICE_UNKNOWN, CTL_LOAD_DRIVER, METHOD_BUFFERED, FILE_ANY_ACCESS):
	{
		//初始化数据
		extern SYMBOLS_DATA g_SymbolsData;
		__try
		{
			memmove(&g_SymbolsData, Irp->AssociatedIrp.SystemBuffer, sizeof(SYMBOLS_DATA));
			LogInfo("CTL_LOAD_DRIVER:load symbols ok!");

		}_except(1)
		{
			LogInfo("CTL_LOAD_DRIVER:load symbols eeor!");
			break;
		}
		//初始化Hook
		if (!CreateDebugger.StartKernelDbg())
		{
			LogInfo("CTL_LOAD_DRIVER:StartKernelDbg eeror!");
		}
		else
		{
			LogInfo("CTL_LOAD_DRIVER:KernelDebugger Succsess!");
		}

		break;
	}

	case IOCTL_ADD_HIDER_ENTRY:
	{
		ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
		if (Hider::CreateEntry(IoGetCurrentProcess(), PidToProcess(*Pid)) == FALSE)
			Status = STATUS_UNSUCCESSFUL;
		else
			g_HyperHide.NumberOfActiveDebuggers++;
		break;
	}

	case IOCTL_REMOVE_HIDER_ENTRY:
	{
		ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
		if (Hider::RemoveEntry(PidToProcess(*Pid)) == FALSE)
			Status = STATUS_UNSUCCESSFUL;
		else
			g_HyperHide.NumberOfActiveDebuggers--;
		break;
	}

	case IOCTL_HIDE_FROM_SYSCALL:
	{
		PHIDE_INFO HideInfo = (PHIDE_INFO)Irp->AssociatedIrp.SystemBuffer;

		if (Hider::Hide(HideInfo) == FALSE)
			Status = STATUS_UNSUCCESSFUL;
		break;
	}

	case IOCTL_PROCESS_RESUMED:
	{
		ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
		UpdateDelta(PidToProcess(*Pid));
		if (Hider::ResumeCounterForProcess(PidToProcess(*Pid)) == FALSE)
			Status = STATUS_UNSUCCESSFUL;
		break;
	}

	case IOCTL_PROCESS_STOPPED:
	{
		ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
		GetBegin(PidToProcess(*Pid));

		if (Hider::StopCounterForProcess(PidToProcess(*Pid)) == FALSE)
			Status = STATUS_UNSUCCESSFUL;
		break;
	}

	case IOCTL_CLEAR_PEB_DEBUGGER_FLAG:
	{
		ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

		if (SetPebDeuggerFlag(PidToProcess(*Pid), FALSE) == FALSE)
			Status = STATUS_UNSUCCESSFUL;
		break;
	}

	case IOCTL_SET_PEB_DEBUGGER_FLAG:
	{
		ULONG* Pid = (ULONG*)Irp->AssociatedIrp.SystemBuffer;

		if (SetPebDeuggerFlag(PidToProcess(*Pid), TRUE) == FALSE)
			Status = STATUS_UNSUCCESSFUL;
		break;
	}

	case IOCTL_SET_HYPERVISOR_VISIBILITY:
	{
		BOOLEAN Value = *(BOOLEAN*)Irp->AssociatedIrp.SystemBuffer;
		hv::hypervisor_visible(Value);
		break;
	}

	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}