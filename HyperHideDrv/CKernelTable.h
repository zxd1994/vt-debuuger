#pragma once
#include "Header.h"

class CKernelTable
{
public:
	CKernelTable();
	~CKernelTable();

	PVOID GetAddressFromIndex(
		ULONG Index);
	BOOLEAN GetIndexFromName(
		IN CHAR* FunctionName,
		OUT PUINT32 Index);
	BOOLEAN GetFunctionNameFromIndex(
		OUT CHAR* FunctionName,
		IN  UINT32 Index
	);
	BOOLEAN GetOldAddressFromIndex(
		OUT PVOID* OldFunctionAddress,
		IN UINT32 Index,
		IN PVOID NewImageBass);
	PVOID CKernelTable::GetShadowAddressFromIndex(
		ULONG Index);
	BOOLEAN GetShadowOldAddressFromIndex(
		OUT PVOID* OldFunctionAddress,
		UINT32 Index,
		IN PVOID NewImageBass,
		IN PVOID OldBass);
	PVOID GetAddressFromName(CHAR* FunctionName);
private:
	PVOID FindKeServiceDescriptorTable64(
		PUCHAR StartSearchAddress,
		PUCHAR EndSearchAddress);
	PServiceDescriptorTableEntry_t GetKeServiceDescriptorTable();
	PServiceDescriptorTableEntry_t GetKeServiceDescriptorTableShadow();
};

