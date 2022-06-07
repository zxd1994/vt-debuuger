#include <ntifs.h>
#include <stdint.h>
#include <intrin.h>

uint64_t OldAttach;

uint64_t GetDirectoryTableBase(PEPROCESS Process)
{
	return *(uint64_t*)(uint64_t(Process) + 0x28);
}

void AttachProcess(PEPROCESS Process, PETHREAD Thread)
{
	uint64_t DirectoryTableBase;
	uint64_t result;
	uint64_t Value;

	//Attach to Process
	OldAttach = *(uint64_t*)(uint64_t(Thread) + 0xB8);
	*(uint64_t*)(uint64_t(Thread) + 0xB8) = uint64_t(Process);

	// KernelApcPending
	*(uint64_t*)(uint64_t(Thread) + 0x98 + 0x29) = 0;

	//Get DirectoryTableBase;
	DirectoryTableBase = GetDirectoryTableBase(Process);
	if ((DirectoryTableBase & 2) != 0)
		DirectoryTableBase = DirectoryTableBase | 0x8000000000000000u;

	// Write offset to DirectoryTableBase
	__writegsqword(0x9000u, DirectoryTableBase);
	__writecr3(DirectoryTableBase);

	// Temp Control Register
	Value = __readcr4();
	if ((Value & 0x20080) != 0)
	{
		result = Value ^ 0x80;
		__writecr4(Value ^ 0x80);
		__writecr4(Value);
	}
	else
	{
		result = __readcr3();
		__writecr3(result);
	}
}

#include <ndis.h>
void DetachProcess(PEPROCESS Process, PETHREAD Thread)
{
	// KernelApcPending
	*(uint64_t*)(uint64_t(Thread) + 0x98 + 0x29) = 1;

	// restore to the old
	*(uint64_t*)(uint64_t(Thread) + 0xB8) = OldAttach;

	// Due to DCP the communication with usermode will crash, so we put a Sleep() 1 Millisecond for me it should be enough, so you need to test 
	//NdisMSleep(1);
}

NTSTATUS ReadVirtualMemory(
	PEPROCESS Process,
	PVOID Destination,
	PVOID Source,
	SIZE_T Size)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	KAPC_STATE ApcState;
	PHYSICAL_ADDRESS SourcePhysicalAddress;
	PVOID MappedIoSpace;
	PVOID MappedKva;
	PMDL Mdl;
	BOOLEAN ShouldUseSourceAsUserVa;

	if (NT_SUCCESS(ntStatus) && Process)
	{
		ShouldUseSourceAsUserVa = Source <= MmHighestUserAddress ? TRUE : FALSE;

		// 2. Get the physical address corresponding to the user virtual memory
		SourcePhysicalAddress = MmGetPhysicalAddress(
			ShouldUseSourceAsUserVa == TRUE ? Source : Destination);

		if (!SourcePhysicalAddress.QuadPart)
		{
			return STATUS_INVALID_ADDRESS;
		}

		// 4. Map an IO space for MDL
		MappedIoSpace = MmMapIoSpace(SourcePhysicalAddress, Size, MmNonCached);
		if (!MappedIoSpace)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// 5. Allocate MDL
		Mdl = IoAllocateMdl(MappedIoSpace, (ULONG)Size, FALSE, FALSE, NULL);
		if (!Mdl)
		{
			MmUnmapIoSpace(MappedIoSpace, Size);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// 6. Build MDL for non-paged pool
		MmBuildMdlForNonPagedPool(Mdl);

		// 7. Map to the KVA
		MappedKva = MmMapLockedPagesSpecifyCache(
			Mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority);

		if (!MappedKva)
		{
			MmUnmapIoSpace(MappedIoSpace, Size);
			IoFreeMdl(Mdl);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// 8. copy memory
		memcpy(
			ShouldUseSourceAsUserVa == TRUE ? Destination : MappedKva,
			ShouldUseSourceAsUserVa == TRUE ? MappedKva : Destination,
			Size);

		MmUnmapIoSpace(MappedIoSpace, Size);
		MmUnmapLockedPages(MappedKva, Mdl);
		IoFreeMdl(Mdl);
	}

	return ntStatus;
}

NTSTATUS ReadProcessMemory(HANDLE ProcessPid, PVOID Address, PVOID Buffer, SIZE_T Size)
{
	PEPROCESS Process = { 0 };
	auto ntStatus = PsLookupProcessByProcessId(ProcessPid, &Process);
	if (NT_SUCCESS(ntStatus) && Process)
	{
		auto CurrentThread = KeGetCurrentThread();

		AttachProcess(Process, CurrentThread);
		ntStatus = ReadVirtualMemory(Process, Buffer, Address, Size);
		DetachProcess(Process, CurrentThread);
	}

	ObDereferenceObject(Process);
	return ntStatus;
}
