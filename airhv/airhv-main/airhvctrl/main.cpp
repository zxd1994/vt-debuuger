#include <ntddk.h>
#include "hypervisor_gateway.h"
#include "utils.h"

extern void* kernel_code_caves[200];

void* nt_create_file_address;

NTSTATUS(*original_nt_create_file)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength
	);


NTSTATUS NTAPI hooked_nt_create_file(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
)
{
	__try
	{
		ProbeForRead(FileHandle, sizeof(HANDLE), 1);
		ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
		ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
		ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"test.txt") != NULL)
		{
			return STATUS_INVALID_BUFFER_SIZE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return original_nt_create_file(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

VOID driver_unload(PDRIVER_OBJECT driver_object)
{
	UNICODE_STRING dos_device_name;

	hvgt::unhook_function(nt_create_file_address);

	RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhvctrl");
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

	NTSTATUS status = STATUS_SUCCESS;

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
	PDEVICE_OBJECT device_oject = 0;
	UNICODE_STRING driver_name, dos_device_name;

	RtlInitUnicodeString(&driver_name, L"\\Device\\airhvctrl");
	RtlInitUnicodeString(&dos_device_name, L"\\DosDevices\\airhvctrl");

	status = IoCreateDevice(driver_object, 0, &driver_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_oject);

	if (status == STATUS_SUCCESS)
	{
		driver_object->MajorFunction[IRP_MJ_CLOSE] = driver_create_close;
		driver_object->MajorFunction[IRP_MJ_CREATE] = driver_create_close;
		driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver_ioctl_dispatcher;

		driver_object->DriverUnload = driver_unload;
		driver_object->Flags |= DO_BUFFERED_IO;
		IoCreateSymbolicLink(&dos_device_name, &driver_name);
	}

	UNICODE_STRING routine_name;
	RtlInitUnicodeString(&routine_name,L"NtCreateFile");

	// Find code caves in ntoskrnl.exe
	find_code_caves();

	// Get address of NtCreateFile syscall
	nt_create_file_address = MmGetSystemRoutineAddress(&routine_name);

	// 14 bytes hook using absolute jmp
	//hvgt::hook_function(nt_create_file_address, hooked_nt_create_file, (void**)&original_nt_create_file);

	// 5 bytes hook using relative jmp and code cave
	hvgt::hook_function(nt_create_file_address, hooked_nt_create_file, kernel_code_caves[0], (void**)&original_nt_create_file);

	// Send information to hypervisor to allocate new pools
	hvgt::send_irp_perform_allocation();

	return status;
}