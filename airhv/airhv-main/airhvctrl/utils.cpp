#include <ntddk.h>
#include <ntifs.h>
#include "nt.h"

#define NUMBER_OF_CODE_CAVES 10

void* kernel_code_caves[NUMBER_OF_CODE_CAVES] = { 0 };

bool get_kernel_module(const char* name, unsigned __int64& image_size, void*& image_base)
{
	ULONG bytes;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &bytes);
	PSYSTEM_MODULE_INFORMATION mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bytes, 'xxxx');

	RtlSecureZeroMemory(mods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, mods, bytes, &bytes);
	if (NT_SUCCESS(status) == FALSE)
	{
		ExFreePoolWithTag(mods, 'xxxx');
		return FALSE;
	}

	PSYSTEM_MODULE_ENTRY mod = mods->Modules;
	for (ULONG i = 0; i < mods->ModulesCount; i++)
	{
		if (strstr((const char*)mod[i].FullPathName, name) != 0)
		{
			if (mod[i].ImageSize != 0)
			{
				image_size = mod[i].ImageSize;
				image_base = mod[i].ImageBase;
				ExFreePoolWithTag(mods, 'xxxx');
				return true;
			}
		}
	}

	ExFreePoolWithTag(mods, 'xxxx');
	return false;
}

bool find_code_caves()
{
	unsigned __int64 kernel_text_section_size = 0;
	void* kernel_text_section_base = 0;

	if (get_kernel_module("ntoskrnl.exe", kernel_text_section_size, kernel_text_section_base) == false)
		return false;

	kernel_text_section_base = (void*)((unsigned __int64)kernel_text_section_base + 0x1000);

	unsigned __int64 kernel_code_cave_index = 0;
	unsigned __int64 kernel_code_cave_size = 0;

	for (unsigned __int64 memory_location = (unsigned __int64)kernel_text_section_base; memory_location < kernel_text_section_size, kernel_code_cave_index < NUMBER_OF_CODE_CAVES; memory_location++)
	{
		*(unsigned __int8*)memory_location == 0xCC ? kernel_code_cave_size++ : kernel_code_cave_size = 0;

		if (kernel_code_cave_size == 14)
		{
			if (PAGE_ALIGN(memory_location) != PAGE_ALIGN(memory_location - 13))
				continue;

			kernel_code_caves[kernel_code_cave_index] = (void*)(memory_location - 13);
			kernel_code_cave_index++;
		}
	}

	return TRUE;
}