#pragma once

#include <ntifs.h>

class CPeModule
{
public:
	/************************************************************************
*  Name : MappingPEFileInKernelSpace
*  Param: FilePath		        PE文件完整NT路径
*  Param: MappingBaseAddress	映射后的基地址 （OUT）
*  Param: MappingViewSize		文件映射大小   （OUT）
*  Ret  : BOOLEAN
*  将PE文件映射到内核空间，使用完成ZwUnmapViewOfSection释放
************************************************************************/
	static BOOLEAN MappingFileToKernel
	(
		IN WCHAR* FilePath,
		OUT PVOID* MappingBaseAddress,
		OUT ULONG_PTR* MappingViewSize);

	static NTSTATUS UnMappingFileToKernel(
		_In_opt_ PVOID BaseAddress
	);
	/************************************************************************
*  Name : GetImageSection
*  Param: KernelModuleBass	模块基址
*  Param: SectionName	    区段名 ".data"
*  Param: SizeOfSection		输出区段大小
*  Param: SectionAddress	输出区段地址
*  Ret  : BOOLEAN
*  获取指定模块区段地址和大小
************************************************************************/
	static BOOLEAN GetImageSection(
		IN PVOID KernelModuleBass,
		IN const char* SectionName,
		OUT PULONG SizeOfSection,
		OUT PVOID* SectionAddress
	);

	/************************************************************************
*  Name : GetSystemKernelModuleInfo
*  Param: SystemKernelModulePath	   输出模块路径
*  Param: SystemKernelModuleBase	   输出模块基址
*  Param: SystemKernelModuleSize	   输出模块大小
*  Ret  : BOOLEAN
*  获取系统模块基址、路径、大小
************************************************************************/
	static BOOLEAN GetSystemKernelModuleInfo(
		OUT WCHAR** SystemKernelModulePath,
		OUT PULONG_PTR SystemKernelModuleBase,
		OUT PULONG_PTR SystemKernelModuleSize










	);
};

#define SEC_IMAGE  0x01000000