#include "wrRegstry.h"

LARGE_INTEGER cookie = { 0 };

NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
NTKERNELAPI PVOID  PsGetProcessWow64Process(IN PEPROCESS Process);
NTKERNELAPI PVOID  PsGetProcessPeb(IN PEPROCESS Process);

NTSTATUS RegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	NTSTATUS status = STATUS_SUCCESS;
	REG_NOTIFY_CLASS NotifyClass;
	PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo;
	PMyDriverStruct DriverInfo = NULL;

	PEPROCESS				process = NULL;
	KAPC_STATE				apc;

	PMDL temp_pMdl = NULL;
	PVOID temp_address1 = NULL;

	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;

	BOOLEAN IsWow64 = FALSE;
	ULONG64 Moudule_Address = 0;
	UNICODE_STRING usCurrentName = { 0 };
	UNICODE_STRING Target_MouduleName = { 0 };


	if (Argument1 == NULL || Argument2 == NULL)  return STATUS_SUCCESS;
	NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
	if (NotifyClass != RegNtPreSetValueKey)   return STATUS_SUCCESS;

	PreSetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
	if (PreSetValueInfo->Type != REG_BINARY || PreSetValueInfo->DataSize != sizeof(MyDriverStruct))    return STATUS_SUCCESS;
	DriverInfo = (PMyDriverStruct)PreSetValueInfo->Data;
	if (DriverInfo->Flag == 1)  //读内存
	{
		status = PsLookupProcessByProcessId((HANDLE)DriverInfo->Pid, &process);

		if (status != STATUS_SUCCESS || process == NULL)  return STATUS_SUCCESS;

		temp_pMdl = IoAllocateMdl((PVOID)DriverInfo->Buff, DriverInfo->Size, 0, 0, NULL);

		if (temp_pMdl != NULL)
		{
			MmBuildMdlForNonPagedPool(temp_pMdl);
			temp_address1 = MmMapLockedPages(temp_pMdl, KernelMode);
			if (temp_address1 != NULL)
			{
				if (DriverInfo->MDL_Flag == 0)  //不启动MDL读写
				{
					KeStackAttachProcess(process, &apc);
					if (MmIsAddressValid((PVOID)DriverInfo->Address))
					{
						RtlCopyMemory(temp_address1, (PVOID)DriverInfo->Address, DriverInfo->Size);//往内核地址里拷贝目标地址数据
					}
					KeUnstackDetachProcess(&apc);
					MmUnmapLockedPages(temp_address1, temp_pMdl);
					IoFreeMdl(temp_pMdl);
				}
				else if (DriverInfo->MDL_Flag == 1) //启动MDL读写
				{
					KeStackAttachProcess(process, &apc);
					if (MmIsAddressValid((PVOID)DriverInfo->Address))
					{
						pMdl = MmCreateMdl(NULL, (PVOID)DriverInfo->Address, DriverInfo->Size);
						if (pMdl != NULL)
						{
							MmBuildMdlForNonPagedPool(pMdl);
							pNewAddress = MmMapLockedPages(pMdl, KernelMode);
							if (pNewAddress != NULL)
							{
								RtlCopyMemory(temp_address1, pNewAddress, DriverInfo->Size);//往内核地址里拷贝目标地址数据
								MmUnmapLockedPages(pNewAddress, pMdl);
								IoFreeMdl(pMdl);
							}
							else
							{
								IoFreeMdl(pMdl);
							}
						}
					}
					KeUnstackDetachProcess(&apc);
					MmUnmapLockedPages(temp_address1, temp_pMdl);
					IoFreeMdl(temp_pMdl);
				}
				else
				{
					IoFreeMdl(temp_pMdl);
				}

			}
		}
		ObDereferenceObject(process);
	}
	else if (DriverInfo->Flag == 2) //写内存
	{
		status = PsLookupProcessByProcessId((HANDLE)DriverInfo->Pid, &process);
		if (status != STATUS_SUCCESS || process == NULL)  return STATUS_SUCCESS;
		temp_address1 = ExAllocatePool(NonPagedPool, DriverInfo->Size);
		if (temp_address1 != NULL)
		{
			RtlZeroMemory(temp_address1, DriverInfo->Size);
			RtlCopyMemory(temp_address1, (PVOID)DriverInfo->Buff, DriverInfo->Size);
			KeStackAttachProcess(process, &apc);
			if (MmIsAddressValid((PVOID)DriverInfo->Address))
			{
				pMdl = MmCreateMdl(NULL, (PVOID)DriverInfo->Address, DriverInfo->Size);
				if (pMdl != NULL)
				{
					MmBuildMdlForNonPagedPool(pMdl);
					pNewAddress = MmMapLockedPages(pMdl, KernelMode);
					if (pNewAddress != NULL)
					{
						RtlCopyMemory(pNewAddress, temp_address1, DriverInfo->Size);
						MmUnmapLockedPages(pNewAddress, pMdl);
						IoFreeMdl(pMdl);
					}
					else
					{
						IoFreeMdl(pMdl);
					}
				}
			}
			KeUnstackDetachProcess(&apc);
			ExFreePool(temp_address1);
		}
		ObDereferenceObject(process);
	}
	else if (DriverInfo->Flag == 3)//取模块地址
	{
		status = PsLookupProcessByProcessId((HANDLE)DriverInfo->Pid, &process);
		if (status != STATUS_SUCCESS || process == NULL)  return STATUS_SUCCESS;
		IsWow64 = (PsGetProcessWow64Process(process) != NULL) ? TRUE : FALSE;

		if (IsWow64)
		{
			temp_address1 = ExAllocatePool(NonPagedPool, DriverInfo->Size + (ULONG64)1);
			if (temp_address1 != NULL)
			{
				RtlZeroMemory(temp_address1, DriverInfo->Size + (ULONG64)1);
				RtlCopyMemory(temp_address1, (PVOID)DriverInfo->Address, DriverInfo->Size);
				KeStackAttachProcess(process, &apc);

				PPEB32 pPeb = (PPEB32)PsGetProcessWow64Process(process);
				RtlInitUnicodeString(&Target_MouduleName, (PWCHAR)temp_address1);
				for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList.Flink;
					pListEntry != &((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList;
					pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
					if (LdrEntry->BaseDllName.Buffer == NULL) continue;
					RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);
					if (RtlEqualUnicodeString(&Target_MouduleName, &usCurrentName, TRUE))
					{
						Moudule_Address = (ULONG64)LdrEntry->DllBase;
						break;
					}
				}
				KeUnstackDetachProcess(&apc);
				ExFreePool(temp_address1);
				RtlCopyMemory((PVOID)DriverInfo->Buff, (PVOID)&Moudule_Address, sizeof(ULONG64));
			}
		}
		else
		{
			temp_address1 = ExAllocatePool(NonPagedPool, DriverInfo->Size + (ULONG64)1);
			if (temp_address1 != NULL)
			{
				RtlZeroMemory(temp_address1, DriverInfo->Size + (ULONG64)1);
				RtlCopyMemory(temp_address1, (PVOID)DriverInfo->Address, DriverInfo->Size);
				KeStackAttachProcess(process, &apc);

				PPEB64 pPeb = (PPEB64)PsGetProcessPeb(process);

				RtlInitUnicodeString(&Target_MouduleName, (PWCHAR)temp_address1);


				for (PLIST_ENTRY64 pListEntry = (PLIST_ENTRY64)((PPEB_LDR_DATA64)pPeb->Ldr)->InLoadOrderModuleList.Flink;
					pListEntry != &((PPEB_LDR_DATA64)pPeb->Ldr)->InLoadOrderModuleList;
					pListEntry = (PLIST_ENTRY64)pListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY64 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);
					if (LdrEntry->BaseDllName.Buffer == NULL)     continue;

					RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);
					if (RtlEqualUnicodeString(&usCurrentName, &Target_MouduleName,TRUE))
					{
						Moudule_Address = LdrEntry->DllBase;
						break;
					}
				}
				KeUnstackDetachProcess(&apc);
				ExFreePool(temp_address1);
				RtlCopyMemory((PVOID)DriverInfo->Buff, (PVOID)&Moudule_Address, sizeof(ULONG64));
			}
		}
		ObDereferenceObject(process);
	}
	return STATUS_SUCCESS;
}




VOID DriverUnload1(_In_ PDRIVER_OBJECT DriverObject)
{
	CmUnRegisterCallback(cookie);
}

NTSTATUS DriverEntry1(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING  RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	DriverObject->DriverUnload = DriverUnload1;
	status = CmRegisterCallback(RegistryCallback,NULL,&cookie);
	return status;
}