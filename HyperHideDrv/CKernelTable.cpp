#include "CKernelTable.h"
#include "CPeModule.h"
#include "GlobalData.h"

PServiceDescriptorTableEntry_t g_KeServiceDescriptorTable=0;
PServiceDescriptorTableEntry_t g_KeServiceDescriptorTableShadow = 0;

CKernelTable::CKernelTable()
{

	if (!g_KeServiceDescriptorTable)
	{
		g_KeServiceDescriptorTable = GetKeServiceDescriptorTable();
	}
	if (!g_KeServiceDescriptorTableShadow)
	{
		g_KeServiceDescriptorTableShadow = GetKeServiceDescriptorTableShadow();

	}
	//KdPrint(("KeServiceDescriptorTable:%p\n KeServiceDescriptorTableShadow:%p\n", g_KeServiceDescriptorTable, g_KeServiceDescriptorTableShadow));
}
CKernelTable::~CKernelTable()
{

}





PVOID CKernelTable::GetAddressFromIndex(
	ULONG Index)
{

	PServiceDescriptorTableEntry_t KeServiceDescriptorTable = g_KeServiceDescriptorTable;

	if (!MmIsAddressValid(KeServiceDescriptorTable))
	{
		return 0;
	}
	if (Index > KeServiceDescriptorTable->NumberOfServices)
	{
		return 0;
	}

#ifdef _WIN64

	//(PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
	ULONG Offset = KeServiceDescriptorTable->ServiceTableBase[Index] >> 4;
	ULONG64 paddr = (ULONG64)(KeServiceDescriptorTable->ServiceTableBase) + Offset;
	DbgPrint("ServiceTableBase + Offset:%x", (ULONG64)(KeServiceDescriptorTable->ServiceTableBase) + Offset);
	return (PVOID)paddr;//为什么要&0xFFFFFFFF0FFFFFFF

	
#else
	return (PVOID)KeServiceDescriptorTable->ServiceTableBase[Index];
#endif // _WIN64

}

BOOLEAN CKernelTable::GetIndexFromName(
	IN CHAR* FunctionName,
	OUT PUINT32 Index)
{
#ifdef _WIN64

	/* Win7 64bit
	004> u zwopenprocess
	ntdll!ZwOpenProcess:
	00000000`774c1570 4c8bd1          mov     r10,rcx
	00000000`774c1573 b823000000      mov     eax,23h
	00000000`774c1578 0f05            syscall
	00000000`774c157a c3              ret
	00000000`774c157b 0f1f440000      nop     dword ptr [rax+rax]
	*/

	UINT32    Offset_SSDTFunctionIndexInNtdllExportFunctionAddress = 4;

#else

	/* 	Win7 32bit
	kd> u zwopenProcess
	nt!ZwOpenProcess:
	83e9162c b8be000000      mov     eax,0BEh
	83e91631 8d542404        lea     edx,[esp+4]
	83e91635 9c              pushfd
	83e91636 6a08            push    8
	83e91638 e8b1190000      call    nt!KiSystemService (83e92fee)
	83e9163d c21000          ret     10h
	*/

	/* WinXp 32bit
	kd> u zwopenprocess
	nt!ZwOpenProcess:
	804ff720 b87a000000      mov     eax,7Ah
	804ff725 8d542404        lea     edx,[esp+4]
	804ff729 9c              pushfd
	804ff72a 6a08            push    8
	804ff72c e850ed0300      call    nt!KiSystemService (8053e481)
	804ff731 c21000          ret     10h

	*/
	UINT32    Offset_SSDTFunctionIndexInNtdllExportFunctionAddress = 1;

#endif

	// 使用内存映射将Ntdll模块映射到System进程的内存空间进行查找(Ntdll.dll模块的导出表中进行搜索)

	WCHAR					wzFileFullPath[] = L"\\SystemRoot\\System32\\ntdll.dll";
	PVOID					MappingBaseAddress = NULL;
	SIZE_T					MappingViewSize = 0;
	PIMAGE_NT_HEADERS		NtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PUINT32					AddressOfFunctions = NULL;			// offset
	PUINT32					AddressOfNames = NULL;				// offset
	PUINT16					AddressOfNameOrdinals = NULL;		// Ordinal
	CHAR* szFunctionName = NULL;
	UINT32					FunctionOrdinal = 0;
	UINT_PTR				FunctionAddress = 0;
	BOOLEAN					bOk = FALSE;
	UINT32					i = 0;

	*Index = -1;

	//将Ntdll.dll 当前的空间中

	bOk = CPeModule::MappingFileToKernel(wzFileFullPath, &MappingBaseAddress, &MappingViewSize);
	if (bOk == FALSE)
	{
		return FALSE;
	}

	__try
	{
		NtHeader = RtlImageNtHeader(MappingBaseAddress);		// 转换成ntheader
		if (NtHeader && NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)MappingBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);		// 导出表地址

			AddressOfFunctions = (PUINT32)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfFunctions);
			AddressOfNames = (PUINT32)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfNames);
			AddressOfNameOrdinals = (PUINT16)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfNameOrdinals);

			// 这里不处理转发，ntdll应该不存在转发
			for (i = 0; i < ExportDirectory->NumberOfNames; i++)
			{
				szFunctionName = (CHAR*)((PUINT8)MappingBaseAddress + AddressOfNames[i]);   // 获得函数名称
				if (_stricmp(szFunctionName, FunctionName) == 0)						  // hit !
				{
					FunctionOrdinal = AddressOfNameOrdinals[i];
					FunctionAddress = (UINT_PTR)((PUINT8)MappingBaseAddress + AddressOfFunctions[FunctionOrdinal]);			// (WinXp 32bit 804ff720 ZwOpenProcess)		(Win7 32bit 83e9162c ZwOpenProcess)	(Win7 64bit 00000000`774c1570 ZwOpenProcess)

					// SSDT中函数索引
					*Index = *(PUINT32)(FunctionAddress + Offset_SSDTFunctionIndexInNtdllExportFunctionAddress);	// (WinXp 32bit 804ff721 7Ah)	(Win7 32bit 804ff721 0BEh)		(Win7 64bit 00000000`774c1574 23h)
					break;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	ZwUnmapViewOfSection(NtCurrentProcess(), MappingBaseAddress);


	if (*Index == -1)
	{
		return FALSE;
	}

	return TRUE;
}







PVOID CKernelTable::FindKeServiceDescriptorTable64
(
	PUCHAR StartSearchAddress,
	PUCHAR EndSearchAddress)
{
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONG_PTR KeServiceDescriptorTable = 0;

	//地址效验
	if (MmIsAddressValid((PVOID)StartSearchAddress) == FALSE)return NULL;
	if (MmIsAddressValid((PVOID)EndSearchAddress) == FALSE)return NULL;

	for (PUCHAR i = (PUCHAR)StartSearchAddress; i < (PUCHAR)EndSearchAddress; i++)
	{
		if (MmIsAddressValid((PVOID)i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)  //4c8d15
			{
				memcpy(&templong, i + 3, 4);
				KeServiceDescriptorTable = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return (PVOID)KeServiceDescriptorTable;
				//当前地址 + 长度 + 数值
				//fffff800`03c8c772+7 + 002320c7 = FFFFF80003EBE840
				/*
				fffff800`03c8c772 4c8d15c7202300  lea     r10,[nt!KeServiceDescriptorTable (fffff800`03ebe840)]
				fffff800`03c8c779 4c8d1d00212300  lea     r11,[nt!KeServiceDescriptorTableShadow (fffff800`03ebe880)]
				*/
			}
		}
	}
	return NULL;
}
PServiceDescriptorTableEntry_t CKernelTable::GetKeServiceDescriptorTable()
{
#ifdef _WIN64
	PUCHAR pKiSystemCall64 = (PUCHAR)__readmsr(0xc0000082);  //rdmsr c0000082   //定位KiSystemCall64
	PUCHAR EndSearchAddress = pKiSystemCall64 + 0x500;
	PVOID KeServiceDescriptorTable = 0;


	KeServiceDescriptorTable = FindKeServiceDescriptorTable64(pKiSystemCall64, EndSearchAddress);
	if (KeServiceDescriptorTable)
	{
		return  (PServiceDescriptorTableEntry_t)KeServiceDescriptorTable;
	}

	//msr[0xc0000082]变成了KiSystemCall64Shadow函数
	//原来我们64位搜索KeServiceDescriptorTable是通过msr的0xc0000082获得KiSystemCall64字段, 但是现在msr[0xc0000082]变成了KiSystemCall64Shadow函数, 而且这个函数无法直接搜索到KeServiceDescriptorTable。
	ULONG_PTR KiSystemServiceUser = 0;
	ULONG_PTR templong = 0xffffffffffffffff;
	for (PUCHAR i = (PUCHAR)pKiSystemCall64; i < (PUCHAR)((ULONG_PTR)EndSearchAddress + 0xff); i++)
	{
		if (*(PUCHAR)i == 0xe9 && *(PUCHAR)(i + 5) == 0xc3)
		{
			//fffff803`23733383 e9631ae9ff      jmp     nt!KiSystemServiceUser(fffff803`235c4deb)
			//fffff803`23733388 c3              ret
			RtlCopyMemory(&templong, (PUCHAR)(i + 1), 4);
			KiSystemServiceUser = templong + 5 + (ULONG_PTR)i;//KiSystemServiceUser
			EndSearchAddress = (PUCHAR)(KiSystemServiceUser + 0x500);
			KeServiceDescriptorTable = FindKeServiceDescriptorTable64((PUCHAR)KiSystemServiceUser, EndSearchAddress);
			return (PServiceDescriptorTableEntry_t)KeServiceDescriptorTable;
		}
	}
	return 0;

#else

	return (PServiceDescriptorTableEntry_t)CPeModule::GetProcAddress("KeServiceDescriptorTable");

#endif // _WIN64
}

PServiceDescriptorTableEntry_t CKernelTable::GetKeServiceDescriptorTableShadow()
{
#ifdef _WIN64

	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x1d) //4c8d1d
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return (PServiceDescriptorTableEntry_t)((PUCHAR)addr+ sizeof(ServiceDescriptorTableEntry_t));
			}
		}
	}
	return 0;
#else

	if (g_SystemData.WinVersion == 7601)
	{
		/*nt!KeAddSystemServiceTable + 0x1a:
		83fc5022 8d88002afa83    lea     ecx, nt!KeServiceDescriptorTableShadow(83fa2a00)[eax]
		83fc5028 833900          cmp     dword ptr[ecx], 0*/
		TZM tzm[5] = { {0x8d,-2},{0x88,-1},{0x83,4},{0x39,5},{0x00,6} };
		PVOID find = CMemroy::FindMemory((PVOID)CPeModule::GetProcAddress("KeAddSystemServiceTable"), 0x100, CMemroy::Normal, tzm);
		if (find)
		{
			return (ServiceDescriptorTableEntry_t) (*(PULONG)find+ sizeof(ServiceDescriptorTableEntry_t));
		}
	}
	return 0;


#endif // _WIN64

}


BOOLEAN CKernelTable::GetFunctionNameFromIndex(
	OUT CHAR* FunctionName,
	IN  UINT32 Index
)
{
#ifdef _WIN64

	/* Win7 64bit
	004> u zwopenprocess
	ntdll!ZwOpenProcess:
	00000000`774c1570 4c8bd1          mov     r10,rcx
	00000000`774c1573 b823000000      mov     eax,23h
	00000000`774c1578 0f05            syscall
	00000000`774c157a c3              ret
	00000000`774c157b 0f1f440000      nop     dword ptr [rax+rax]
	*/

	UINT32    Offset_SSDTFunctionIndexInNtdllExportFunctionAddress = 4;

#else

	/* 	Win7 32bit
	kd> u zwopenProcess
	nt!ZwOpenProcess:
	83e9162c b8be000000      mov     eax,0BEh
	83e91631 8d542404        lea     edx,[esp+4]
	83e91635 9c              pushfd
	83e91636 6a08            push    8
	83e91638 e8b1190000      call    nt!KiSystemService (83e92fee)
	83e9163d c21000          ret     10h
	*/

	/* WinXp 32bit
	kd> u zwopenprocess
	nt!ZwOpenProcess:
	804ff720 b87a000000      mov     eax,7Ah
	804ff725 8d542404        lea     edx,[esp+4]
	804ff729 9c              pushfd
	804ff72a 6a08            push    8
	804ff72c e850ed0300      call    nt!KiSystemService (8053e481)
	804ff731 c21000          ret     10h

	*/
	UINT32    Offset_SSDTFunctionIndexInNtdllExportFunctionAddress = 1;

#endif

	// 使用内存映射将Ntdll模块映射到System进程的内存空间进行查找(Ntdll.dll模块的导出表中进行搜索)

	WCHAR					wzFileFullPath[] = L"\\SystemRoot\\System32\\ntdll.dll";
	PVOID					MappingBaseAddress = NULL;
	SIZE_T					MappingViewSize = 0;
	PIMAGE_NT_HEADERS		NtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PUINT32					AddressOfFunctions = NULL;			// offset
	PUINT32					AddressOfNames = NULL;				// offset
	PUINT16					AddressOfNameOrdinals = NULL;		// Ordinal
	CHAR* szFunctionName = NULL;
	UINT32					FunctionOrdinal = 0;
	UINT_PTR				FunctionAddress = 0;
	BOOLEAN					bOk = FALSE;
	UINT32					i = 0;


	BOOLEAN boole = FALSE;
	//将Ntdll.dll 当前的空间中

	bOk = CPeModule::MappingFileToKernel(wzFileFullPath, &MappingBaseAddress, &MappingViewSize);
	if (bOk == FALSE)
	{
		return FALSE;
	}

	__try
	{
		NtHeader = RtlImageNtHeader(MappingBaseAddress);		// 转换成ntheader
		if (NtHeader && NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		{
			ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)MappingBaseAddress + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);		// 导出表地址

			AddressOfFunctions = (PUINT32)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfFunctions);
			AddressOfNames = (PUINT32)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfNames);
			AddressOfNameOrdinals = (PUINT16)((PUINT8)MappingBaseAddress + ExportDirectory->AddressOfNameOrdinals);

			// 这里不处理转发，ntdll应该不存在转发
			for (i = 0; i < ExportDirectory->NumberOfNames; i++)
			{
				szFunctionName = (CHAR*)((PUINT8)MappingBaseAddress + AddressOfNames[i]);   // 获得函数名称
				FunctionOrdinal = AddressOfNameOrdinals[i];
				FunctionAddress = (UINT_PTR)((PUINT8)MappingBaseAddress + AddressOfFunctions[FunctionOrdinal]);

				if (szFunctionName[0] == 'N' && szFunctionName[1] == 't')
				{
					if (*(PUINT32)(FunctionAddress + Offset_SSDTFunctionIndexInNtdllExportFunctionAddress) == Index)
					{
						strcpy(FunctionName, szFunctionName);
						boole = TRUE;
						break;
					}
				}
			}
			if (!boole)//过滤有些SSDT函数不进入内核，则手动硬编码填充函数名
			{
				szFunctionName = "NtQuerySystemTime";
				strcpy(FunctionName, szFunctionName);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		boole = FALSE;
		KdPrint(("GetFunctionNameByIndex error!\n"));
	}

	ZwUnmapViewOfSection(NtCurrentProcess(), MappingBaseAddress);


	return boole;
}
BOOLEAN CKernelTable::GetOldAddressFromIndex(
	OUT PVOID* OldFunctionAddress,
	IN UINT32 Index,
	IN PVOID NewImageBass)
{

	PServiceDescriptorTableEntry_t  KeServiceDescriptorTable = g_KeServiceDescriptorTable;
	if (!MmIsAddressValid(KeServiceDescriptorTable) || !NewImageBass || Index > KeServiceDescriptorTable->NumberOfServices)
	{
		return FALSE;
	}
	PULONG_PTR ServiceTableBase = (PULONG_PTR)((ULONG_PTR)KeServiceDescriptorTable->ServiceTableBase - g_SystemData.KernelModuleBass + (ULONG_PTR)NewImageBass);
	PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader((PVOID)NewImageBass);
	_try
	{
#ifdef _WIN64
		* OldFunctionAddress = (PVOID)(ServiceTableBase[Index] - NtHeader->OptionalHeader.ImageBase + g_SystemData.KernelModuleBass);
#else
		* OldFunctionAddress = (PVOID)KeServiceDescriptorTable->ServiceTableBase[Index];
#endif // _WIN64
	}
		_except(1)
	{
		KdPrint(("ServiceTableBase error!"));
		return FALSE;
	}


	return TRUE;
}

BOOLEAN CKernelTable::GetShadowOldAddressFromIndex(
	OUT PVOID* OldFunctionAddress,
	UINT32 Index,
	IN PVOID NewImageBass, 
	IN PVOID OldBass)
{
	BOOLEAN boole = FALSE;
	PServiceDescriptorTableEntry_t  KeServiceDescriptorTable = g_KeServiceDescriptorTableShadow;
	if (!MmIsAddressValid(KeServiceDescriptorTable) || !NewImageBass || Index > KeServiceDescriptorTable->NumberOfServices)
	{
		return boole;
	}
	PULONG_PTR ServiceTableBase = (PULONG_PTR)((INT_PTR)KeServiceDescriptorTable->ServiceTableBase - (INT_PTR)OldBass + (INT_PTR)NewImageBass);
	PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader((PVOID)NewImageBass);

	_try
	{
#ifdef _WIN64
		* OldFunctionAddress = (PVOID)(ServiceTableBase[Index] - NtHeader->OptionalHeader.ImageBase + (INT_PTR)OldBass);
#else
		* OldFunctionAddress = (PVOID)KeServiceDescriptorTable->ServiceTableBase[Index];
#endif // _WIN64


	}
		_except(1)
	{

		KdPrint(("ServiceTableBase error!"));
		return FALSE;
	}


	return TRUE;
}


PVOID CKernelTable::GetAddressFromName(CHAR* FunctionName)
{
	UINT32 Index =0;
	if (!GetIndexFromName(FunctionName, &Index))
	{
		return 0;
	}
	DbgPrint("111111111111111:%d\n", Index);
	return GetAddressFromIndex(Index);
}