#pragma warning( disable : 4201 4805)
#include <ntddk.h>
#include <intrin.h>
#include "log.h"
#include "ntapi.h"
#include "hypervisor_routines.h"
#include "hypervisor_gateway.h"
#include "vmm.h"

#define IOCTL_POOL_MANAGER_ALLOCATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

__vmm_context* g_vmm_context = 0;

 VOID driver_unload(PDRIVER_OBJECT driver_object)
 {
	 UNICODE_STRING dos_device_name;
	 if(g_vmm_context != NULL)
	 {
		 if (g_vmm_context->vcpu_table[0]->vcpu_status.vmm_launched == true)
		 {
			 hvgt::ept_unhook();
			 hvgt::vmoff();
		 }
	 }

	 hv::disable_vmx_operation();
	 free_vmm_context();

	 RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhv");
	 IoDeleteSymbolicLink(&dos_device_name);
	 IoDeleteDevice(driver_object->DeviceObject);
 }

 NTSTATUS driver_create_close(_In_ PDEVICE_OBJECT device_object, _In_ PIRP irp)
 {
	 UNREFERENCED_PARAMETER(device_object);

	 irp->IoStatus.Status = STATUS_SUCCESS;
	 irp->IoStatus.Information = 0;

	 IoCompleteRequest(irp, IO_NO_INCREMENT);

	 return STATUS_SUCCESS;
 }

 NTSTATUS driver_ioctl_dispatcher(_In_ PDEVICE_OBJECT device_object, _In_ PIRP irp)
 {
	 UNREFERENCED_PARAMETER(device_object);
	 unsigned __int32 bytes_io = 0;
	 PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	 NTSTATUS status = STATUS_SUCCESS;

	 switch (stack->Parameters.DeviceIoControl.IoControlCode)
	 {
		 //
		 // Used by hypervisor control driver to perform allocations
		 //
		 case IOCTL_POOL_MANAGER_ALLOCATE:
		 {
			 status = pool_manager::perform_allocation();
			 break;
		 }
	 }

	 irp->IoStatus.Status = status;
	 irp->IoStatus.Information = bytes_io;

	 IoCompleteRequest(irp, IO_NO_INCREMENT);
	 return status;
 }

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PCUNICODE_STRING reg) 
{
	UNREFERENCED_PARAMETER(reg);

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT device_object = NULL;
	UNICODE_STRING driver_name, dos_device_name;

	RtlInitUnicodeString(&driver_name, L"\\Device\\airhv");
	RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhv");

	status = IoCreateDevice(driver_object, 0, &driver_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

	if (status == STATUS_SUCCESS)
	{
		driver_object->MajorFunction[IRP_MJ_CLOSE] = driver_create_close;
		driver_object->MajorFunction[IRP_MJ_CREATE] = driver_create_close;
		driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver_ioctl_dispatcher;

		driver_object->DriverUnload = driver_unload;
		driver_object->Flags |= DO_BUFFERED_IO;
		IoCreateSymbolicLink(&dos_device_name, &driver_name);
	}

	//
	// Check if our cpu support virtualization
	//
	if (!hv::virtualization_support()) {
		LogError("VMX operation is not supported on this processor.\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	//
	// Initialize and start virtual machine
	// If it fails turn off vmx and deallocate all structures
	//
	if(vmm_init() == false)
	{
		hv::disable_vmx_operation();
		free_vmm_context();
		LogError("Vmm initialization failed");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	return status;
}