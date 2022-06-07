#include "Memroy.h"

BOOLEAN WriteKernelMemory
(
	PVOID pDestination,
	PVOID pSourceAddress,
	SIZE_T SizeOfCopy)
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	pMdl = IoAllocateMdl(pDestination, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);
	if (!pMdl) return FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	pSafeAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (!pSafeAddress) return FALSE;
	RtlCopyMemory(pSafeAddress, pSourceAddress, SizeOfCopy);
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}


BOOLEAN ReadKernelMemory
(
	PVOID pDestination,
	PVOID pSourceAddress,
	SIZE_T SizeOfCopy)
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	pMdl = IoAllocateMdl(pSourceAddress, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);
	if (!pMdl) return FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	pSafeAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (!pSafeAddress) return FALSE;
	RtlCopyMemory(pDestination, pSafeAddress, SizeOfCopy);
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}


KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}



PVOID FindMemory
(
	PVOID   SearAddress,
	ULONG   SearLenth,
	TzmMode Mode,
    TZM    Tzm[5])
{
	//int Tzm[5][5]= { {0, 0}, { 0,0 }, { 0,0 }, { 0,0 }, { 0,0 } };
	
	if (!MmIsAddressValid(SearAddress))
	{
		return 0;
	}
	PUCHAR EndAddress = (PUCHAR)SearAddress + SearLenth;
	PUCHAR StartAddress = (PUCHAR)SearAddress;
	__try
	{
		for (; StartAddress < EndAddress; StartAddress++)
		{
			if (*(StartAddress + Tzm[0].Offset) == Tzm[0].Tzm &&
				*(StartAddress + Tzm[1].Offset) == Tzm[1].Tzm &&
				*(StartAddress + Tzm[2].Offset) == Tzm[2].Tzm &&
				*(StartAddress + Tzm[3].Offset) == Tzm[3].Tzm &&
				*(StartAddress + Tzm[4].Offset) == Tzm[4].Tzm)
			{

				switch (Mode)
				{
				case Normal:
					return StartAddress;
				case Call:
					return *(INT*)(StartAddress + 1) + StartAddress + 5;
				case Mov:
					return *(INT*)(StartAddress + 2) + StartAddress + 6;	
				case Lea:
					return *(INT*)(StartAddress + 3) + StartAddress + 7;

				default:
					break;
				}



			}
		}
	}
	_except(1)
	{
		
	}
	return 0;
}
PVOID FindMemoryFromReadAndWriteSection(PVOID ModuleBass, TzmMode Mode, TZM Tzm[5])
{
	if (!MmIsAddressValid(ModuleBass))
	{
		return 0;
	}
	PIMAGE_NT_HEADERS NtHeader=RtlImageNtHeader(ModuleBass);
	if (!NtHeader)
	{
		return 0;
	}

	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	PUCHAR StartAddr;

	for (USHORT i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
	{
		if (SectionHeader->Characteristics&(IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ))//可读可执行的区段
		{
			StartAddr =(PUCHAR) ((ULONG_PTR)ModuleBass+(ULONG_PTR) SectionHeader->VirtualAddress);
			
			
			PVOID RetAddr= FindMemory(StartAddr, SectionHeader->Misc.VirtualSize, Mode, Tzm);
			if (RetAddr)
			{
				return RetAddr;
			}
			else
			{
				continue;
			}
		}
	}
	return 0;
}


