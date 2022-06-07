#include "CPeModule.h"
#include "KernelExportAPI.h"

BOOLEAN CPeModule::MappingFileToKernel
(
	IN WCHAR* FilePath,
	OUT PVOID* MappingBaseAddress,
	OUT ULONG_PTR* MappingViewSize)
{
	UNICODE_STRING    uniFileFullPath = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	NTSTATUS          Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK   Iosb = { 0 };
	HANDLE			  FileHandle = NULL;
	HANDLE			  SectionHandle = NULL;

	if (!FilePath || !MappingBaseAddress)
	{
		return FALSE;
	}
	*MappingBaseAddress = 0;
	*MappingViewSize = 0;

	RtlInitUnicodeString(&uniFileFullPath, FilePath);		// 常量指针格式化到unicode
	InitializeObjectAttributes(&oa,									// 初始化 oa
		&uniFileFullPath,											// Dll完整路径
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,					// 不区分大小写 | 内核句柄
		NULL,
		NULL
	);

	Status = IoCreateFile(&FileHandle,								// 获得文件句柄
		GENERIC_READ | SYNCHRONIZE,									// 同步读
		&oa,														// 文件绝对路径
		&Iosb,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING
	);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	//	oa.ObjectName = NULL;

	InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwCreateSection(&SectionHandle,			// 创建节对象,用于后面文件映射 （CreateFileMapping）
		SECTION_QUERY | SECTION_MAP_READ,
		&oa,
		NULL,
		PAGE_WRITECOPY,
		SEC_IMAGE,
		FileHandle
	);

	ZwClose(FileHandle);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	Status = ZwMapViewOfSection(
		SectionHandle,
		ZwCurrentProcess(),				// 映射到当前进程的内存空间中 System
		MappingBaseAddress,
		0,
		0,
		0,
		MappingViewSize,
		ViewUnmap,
		0,
		PAGE_WRITECOPY
	);

	ZwClose(SectionHandle);
	if (!NT_SUCCESS(Status))
	{

		KdPrint(("Status: %x", Status));

		return FALSE;
	}

	return TRUE;
}

BOOLEAN CPeModule::GetImageSection(
	IN PVOID KernelModuleBass,
	IN const char* SectionName,
	OUT PULONG SizeOfSection,
	OUT PVOID* SectionAddress
) 
{

	if (!MmIsAddressValid(SizeOfSection) || !MmIsAddressValid(SectionAddress) || !MmIsAddressValid(KernelModuleBass))
	{
		return FALSE;
	}


	//
	// Get the IMAGE_NT_HEADERS.
	//
	PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(KernelModuleBass);
	if (!NtHeaders)
	{
		return FALSE;
	}


	//
	// Walk the PE sections, looking for our target section.
	//
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++SectionHeader)
	{
		if (!_strnicmp((const char*)SectionHeader->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME))
		{
			*SizeOfSection = SectionHeader->SizeOfRawData;
			*SectionAddress = (PVOID)((uintptr_t)KernelModuleBass + SectionHeader->VirtualAddress);
			return TRUE;
		}
	}

	return FALSE;
}

NTSTATUS CPeModule::UnMappingFileToKernel(
	_In_opt_ PVOID BaseAddress
)
{
	return ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);
}

BOOLEAN CPeModule::GetSystemKernelModuleInfo(
	OUT WCHAR** SystemKernelModulePath,
	OUT PULONG_PTR SystemKernelModuleBase,
	OUT PULONG_PTR SystemKernelModuleSize
)
{

	NTSTATUS status;
	ULONG ulSize, i;
	PMODULES pModuleList;
	char* lpszKernelName = NULL;
	ANSI_STRING AnsiKernelModule;
	UNICODE_STRING UnicodeKernelModule;
	BOOLEAN bRet = TRUE;

	__try
	{
		status = ZwQuerySystemInformation(
			11,
			NULL,
			0,
			&ulSize
		);
		if (status != STATUS_INFO_LENGTH_MISMATCH)
		{
			return FALSE;
		}
		pModuleList = (PMODULES)ExAllocatePool(NonPagedPool, ulSize);
		if (pModuleList)
		{
			status = ZwQuerySystemInformation(
				11,
				pModuleList,
				ulSize,
				&ulSize
			);
			if (!NT_SUCCESS(status))
			{
				bRet = FALSE;
			}
		}
		if (!bRet)
		{
			if (pModuleList)
				ExFreePool(pModuleList);
			return FALSE;
		}
		*SystemKernelModulePath = (WCHAR*)ExAllocatePool(NonPagedPool, 260 * 2);
		if (*SystemKernelModulePath == NULL)
		{
			*SystemKernelModuleBase = 0;
			*SystemKernelModuleSize = 0;
			return FALSE;
		}

		lpszKernelName = pModuleList->smi[0].ModuleNameOffset + pModuleList->smi[0].ImageName;
		RtlInitAnsiString(&AnsiKernelModule, lpszKernelName);
		RtlAnsiStringToUnicodeString(&UnicodeKernelModule, &AnsiKernelModule, TRUE);

		RtlZeroMemory(*SystemKernelModulePath, 260 * 2);
		wcscat(*SystemKernelModulePath, L"\\SystemRoot\\system32\\");

		memcpy(
			*SystemKernelModulePath + wcslen(L"\\SystemRoot\\system32\\"),
			UnicodeKernelModule.Buffer,
			UnicodeKernelModule.Length
		);

		*SystemKernelModuleBase = (ULONG_PTR)pModuleList->smi[0].Base;
		*SystemKernelModuleSize = (ULONG_PTR)pModuleList->smi[0].Size;
		ExFreePool(pModuleList);
		RtlFreeUnicodeString(&UnicodeKernelModule);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	return TRUE;
}

