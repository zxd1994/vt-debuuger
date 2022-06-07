#pragma warning( disable : 4201)

#include <ntifs.h>
#include <ntimage.h>
#include "Ntapi.h"
#include "Utils.h"
#include "Log.h"
#include "GlobalData.h"
#include "Peb.h"
#include "KernelDbgStruct.h"
#include"Ntapi.h"

extern HYPER_HIDE_GLOBAL_DATA g_HyperHide;

NTAPI_OFFSETS NtapiOffsets;

INT64(__fastcall* MiGetPteAddress)(UINT64);

BOOLEAN RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive)
{
	if (Str == NULL || SubStr == NULL || Str->Length < SubStr->Length)
		return FALSE;

	CONST USHORT NumCharsDiff = (Str->Length - SubStr->Length) / sizeof(WCHAR);
	UNICODE_STRING Slice = *Str;
	Slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= sizeof(WCHAR))
	{
		if (RtlEqualUnicodeString(&Slice, SubStr, CaseInsensitive))
			return TRUE;
	}
	return FALSE;
}

BOOLEAN RtlStringContains(PSTRING Str, PSTRING SubStr, BOOLEAN CaseInsensitive)
{
	if (Str == NULL || SubStr == NULL || Str->Length < SubStr->Length)
		return FALSE;

	CONST USHORT NumCharsDiff = (Str->Length - SubStr->Length);
	STRING Slice = *Str;
	Slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= 1)
	{
		if (RtlEqualString(&Slice, SubStr, CaseInsensitive))
			return TRUE;
	}
	return FALSE;
}

UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess)
{
	UNICODE_STRING TruncatedFullImageName = { 0 };

	__try
	{
		PUNICODE_STRING FullImageName = (PUNICODE_STRING) * (ULONG64*)((ULONG64)TargetProcess + NtapiOffsets.SeAuditProcessCreationInfoOffset);
		if (FullImageName->Buffer != NULL || FullImageName->Length != 0)
		{
			for (size_t i = FullImageName->Length / 2; i > 0; i--)
			{
				if (FullImageName->Buffer[i] == L'\\')
				{
					RtlInitUnicodeString(&TruncatedFullImageName, &FullImageName->Buffer[i + 1]);
					break;
				}
			}
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	return TruncatedFullImageName;
}

PEPROCESS GetCsrssProcess()
{
	PEPROCESS Process = 0;

	// Sometimes it doesn't return csrss process at the first try which is strange because it must exist
	do
	{
		Process = GetProcessByName(L"csrss.exe");
	} while (Process == 0);

	return Process;
}

PVOID FindSignature(PVOID Memory, ULONG64 Size, PCSZ Pattern, PCSZ Mask)
{
	ULONG64 SigLength = strlen(Mask);
	if (SigLength > Size) return NULL;

	for (ULONG64 i = 0; i < Size - SigLength; i++)
	{
		BOOLEAN Found = TRUE;
		for (ULONG64 j = 0; j < SigLength; j++)
			Found &= Mask[j] == '?' || Pattern[j] == *((PCHAR)Memory + i + j);

		if (Found)
			return (PCHAR)Memory + i;
	}
	return NULL;
}

ULONG64 GetPteAddress(ULONG64 Address)
{
	if (g_HyperHide.CurrentWindowsBuildNumber <= WINDOWS_10_VERSION_THRESHOLD2)
	{
		return (ULONG64)(((Address >> 9) & 0x7FFFFFFFF8) - 0x98000000000);
	}
	else
	{
		if (MiGetPteAddress == NULL)
		{
			CHAR* MiGetPteAddressPattern = "\x48\xC1\xE9\x00\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x23\xC8\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3";
			CHAR* MiGetPteAddressMask = "xxx?xx????????xxxxx????????xxxx";

			ULONG64 KernelTextSectionSize = 0;
			PVOID KernelTextSectionBase = 0;

			if (GetSectionData("ntoskrnl.exe", ".text", KernelTextSectionSize, KernelTextSectionBase) == FALSE)
			{
				LogError("Couldn't get ntoskrnl.exe .text section data");
				return FALSE;
			}

			MiGetPteAddress = (INT64(__fastcall*)(UINT64))FindSignature(KernelTextSectionBase, KernelTextSectionSize, MiGetPteAddressPattern, MiGetPteAddressMask);
			if ((ULONG64)MiGetPteAddress <= (ULONG64)KernelTextSectionBase || (ULONG64)MiGetPteAddress >= (ULONG64)KernelTextSectionBase + KernelTextSectionSize)
			{
				LogError("Couldn't get MiGetPte function address");
				return FALSE;
			}

			LogInfo("MiGetPte address: 0x%llx", MiGetPteAddress);
		}

		return MiGetPteAddress(Address);
	}
}

BOOLEAN GetSectionData(CONST CHAR* ImageName, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress)
{
	ULONG64 ImageSize = 0;
	PVOID ImageBase = 0;

	if (GetProcessInfo(ImageName, ImageSize, ImageBase) == FALSE)
		return FALSE;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)(DosHeader->e_lfanew + (ULONG64)ImageBase);
	ULONG NumSections = NtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

	STRING TargetSectionName;
	RtlInitString(&TargetSectionName, SectionName);

	for (ULONG i = 0; i < NumSections; i++)
	{
		STRING CurrentSectionName;
		RtlInitString(&CurrentSectionName, (PCSZ)Section->Name);
		if (CurrentSectionName.Length > 8)
			CurrentSectionName.Length = 8;

		if (RtlCompareString(&CurrentSectionName, &TargetSectionName, FALSE) == 0)
		{
			SectionSize = Section->Misc.VirtualSize;
			SectionBaseAddress = (PVOID)((ULONG64)ImageBase + (ULONG64)Section->VirtualAddress);

			return TRUE;
		}
		Section++;
	}

	return FALSE;
}

BOOLEAN GetProcessInfo(CONST CHAR* Name, ULONG64& ImageSize, PVOID& ImageBase)
{
	ULONG Bytes;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Bytes);
	PSYSTEM_MODULE_INFORMATION Mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Bytes, DRIVER_TAG);
	if (Mods == NULL)
		return FALSE;

	RtlSecureZeroMemory(Mods, Bytes);

	Status = ZwQuerySystemInformation(SystemModuleInformation, Mods, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(Mods, DRIVER_TAG);
		return FALSE;
	}

	STRING TargetProcessName;
	RtlInitString(&TargetProcessName, Name);

	for (ULONG i = 0; i < Mods->ModulesCount; i++)
	{
		STRING CurrentModuleName;
		RtlInitString(&CurrentModuleName, (PCSZ)Mods->Modules[i].FullPathName);

		if (RtlStringContains(&CurrentModuleName, &TargetProcessName, TRUE) != NULL)
		{
			if (Mods->Modules[i].ImageSize != NULL)
			{
				ImageSize = Mods->Modules[i].ImageSize;
				ImageBase = Mods->Modules[i].ImageBase;
				ExFreePoolWithTag(Mods, DRIVER_TAG);
				return TRUE;
			}
		}
	}

	ExFreePoolWithTag(Mods, DRIVER_TAG);
	return FALSE;
}

PEPROCESS GetProcessByName(WCHAR* ProcessName)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, DRIVER_TAG);
	if (ProcInfo == NULL)
		return NULL;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return NULL;
	}

	UNICODE_STRING ProcessImageName;
	RtlCreateUnicodeString(&ProcessImageName, ProcessName);

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (Entry->ImageName.Buffer != NULL)
		{
			if (RtlCompareUnicodeString(&Entry->ImageName, &ProcessImageName, TRUE) == 0)
			{
				PEPROCESS CurrentPeprocess = PidToProcess(Entry->ProcessId);
				ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
				return CurrentPeprocess;
			}
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return NULL;
}

PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, CONST CHAR* ExportedFunctionName)
{
	KAPC_STATE State;
	PVOID FunctionAddress = 0;
	if (TargetProcess != NULL)
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	do
	{
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(DosHeader->e_lfanew + (ULONG64)ModuleBase);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (ImageDataDirectory.Size == 0 || ImageDataDirectory.VirtualAddress == 0)
			break;

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase + ImageDataDirectory.VirtualAddress);
		ULONG* Address = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfFunctions);
		ULONG* Name = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNames);
		USHORT* Ordinal = (USHORT*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNameOrdinals);

		STRING TargetExportedFunctionName;
		RtlInitString(&TargetExportedFunctionName, ExportedFunctionName);

		for (size_t i = 0; ExportDirectory->NumberOfFunctions; i++)
		{
			STRING CurrentExportedFunctionName;
			RtlInitString(&CurrentExportedFunctionName, (PCHAR)ModuleBase + Name[i]);

			if (RtlCompareString(&TargetExportedFunctionName, &CurrentExportedFunctionName, TRUE) == 0)
			{
				FunctionAddress = (PVOID)((ULONG64)ModuleBase + Address[Ordinal[i]]);
				break;
			}
		}

	} while (0);

	if (TargetProcess != NULL)
		KeUnstackDetachProcess(&State);

	return FunctionAddress;
}

PVOID GetUserModeModule(PEPROCESS TargetProcess, CONST WCHAR* ModuleName, BOOLEAN IsWow64)
{
	if (TargetProcess == NULL)
		return NULL;

	KAPC_STATE State;
	PVOID Address = NULL;
	KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	UNICODE_STRING TargetModuleName;
	RtlCreateUnicodeString(&TargetModuleName, ModuleName);

	__try
	{
		do
		{
			if (IsWow64 == TRUE)
			{
				PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(TargetProcess);

				for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink;
					ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList;
					ListEntry = (PLIST_ENTRY32)ListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY32 Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

					UNICODE_STRING CurrentModuleName;
					RtlCreateUnicodeString(&CurrentModuleName, (PWCH)Entry->BaseDllName.Buffer);

					if (RtlCompareUnicodeString(&CurrentModuleName, &TargetModuleName, TRUE) == 0)
					{
						Address = (PVOID)Entry->DllBase;
						break;
					}
				}
			}

			else
			{
				PPEB Peb = PsGetProcessPeb(TargetProcess);
				for (PLIST_ENTRY ListEntry = Peb->Ldr->InLoadOrderModuleList.Flink;
					ListEntry != &Peb->Ldr->InLoadOrderModuleList;
					ListEntry = ListEntry->Flink)
				{
					PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

					UNICODE_STRING CurrentModuleName;
					RtlCreateUnicodeString(&CurrentModuleName, Entry->BaseDllName.Buffer);

					if (RtlCompareUnicodeString(&CurrentModuleName, &TargetModuleName, TRUE) == 0)
					{
						Address = Entry->DllBase;
						break;
					}
				}
			}

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}

	KeUnstackDetachProcess(&State);
	return Address;
}

BOOLEAN ClearBypassProcessFreezeFlag(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	if (g_HyperHide.CurrentWindowsBuildNumber < WINDOWS_10_VERSION_19H1)
	{
		LogError("This flag doesn't exit on this version of windows");
		return FALSE;
	}

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, DRIVER_TAG);

	if (ProcInfo == NULL)
		return FALSE;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;
				Status = PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread);

				if (NT_SUCCESS(Status) == TRUE)
					*(ULONG*)((ULONG64)Thread + NtapiOffsets.BypassProcessFreezeFlagOffset) &= ~(1 << 21);
			}

			ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
			return TRUE;
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return FALSE;
}

BOOLEAN ClearThreadHideFromDebuggerFlag(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, DRIVER_TAG);

	if (ProcInfo == NULL)
		return FALSE;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;
				Status = PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread);

				if (NT_SUCCESS(Status) == TRUE)
				{
					if (*(ULONG*)((ULONG64)Thread + NtapiOffsets.ThreadHideFromDebuggerFlagOffset) & 0x4)
					{
						Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(TargetProcess, Thread);
						if (HiddenThread != NULL)
							HiddenThread->IsThreadHidden = TRUE;

						*(ULONG*)((ULONG64)Thread + NtapiOffsets.ThreadHideFromDebuggerFlagOffset) &= ~0x4LU;
					}
				}
			}

			ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
			return TRUE;
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return FALSE;
}

BOOLEAN ClearProcessBreakOnTerminationFlag(Hider::PHIDDEN_PROCESS HiddenProcess)
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG BreakOnTermination;
		if (ZwQueryInformationProcess(ProcessHandle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG), NULL) >= 0)
		{
			HiddenProcess->ValueProcessBreakOnTermination = BreakOnTermination & 1;

			BreakOnTermination = 0;
			if (ZwSetInformationProcess(ProcessHandle, ProcessBreakOnTermination, &BreakOnTermination, sizeof(ULONG)) >= 0)
				return TRUE;
		}

		ObCloseHandle(ProcessHandle, KernelMode);
	}

	return FALSE;
}

VOID SaveProcessDebugFlags(Hider::PHIDDEN_PROCESS HiddenProcess)
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG DebugFlags;
		if (ZwQueryInformationProcess(ProcessHandle, ProcessDebugFlags, &DebugFlags, sizeof(ULONG), NULL) >= 0 && PsIsProcessBeingDebugged(HiddenProcess->DebuggedProcess) == FALSE)
		{
			HiddenProcess->ValueProcessDebugFlags = !DebugFlags;
		}

		ObCloseHandle(ProcessHandle, KernelMode);
	}
}

VOID SaveProcessHandleTracing(Hider::PHIDDEN_PROCESS HiddenProcess)
{
	HANDLE ProcessHandle;
	if (ObOpenObjectByPointer(HiddenProcess->DebuggedProcess, OBJ_KERNEL_HANDLE, NULL, NULL, *PsProcessType, KernelMode, &ProcessHandle) >= 0)
	{
		ULONG64 ProcessInformationBuffer[2] = { 0 };

		NTSTATUS Status = ZwQueryInformationProcess(ProcessHandle, ProcessHandleTracing, &ProcessInformationBuffer[0], 16, NULL);
		if (Status == STATUS_SUCCESS)
			HiddenProcess->ProcessHandleTracingEnabled = 1;
		else if (Status == STATUS_INVALID_PARAMETER)
			HiddenProcess->ProcessHandleTracingEnabled = 0;

		ObCloseHandle(ProcessHandle, KernelMode);
	}
}

BOOLEAN ClearThreadBreakOnTerminationFlags(PEPROCESS TargetProcess)
{
	NTSTATUS Status;
	ULONG Bytes;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
	PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, DRIVER_TAG);
	if (ProcInfo == NULL)
		return FALSE;

	RtlSecureZeroMemory(ProcInfo, Bytes);

	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
		return FALSE;
	}

	for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
	{
		if (PidToProcess(Entry->ProcessId) == TargetProcess)
		{
			for (size_t i = 0; i < Entry->NumberOfThreads; i++)
			{
				PETHREAD Thread;
				if (PsLookupThreadByThreadId(Entry->Threads[i].ClientId.UniqueThread, (PETHREAD*)&Thread) >= 0)
				{
					if (*(ULONG*)((ULONG64)Thread + NtapiOffsets.ThreadBreakOnTerminationFlagOffset) & 0x20)
					{
						Hider::PHIDDEN_THREAD HiddenThread = Hider::AppendThreadList(TargetProcess, Thread);
						if (HiddenThread != NULL)
						{
							HiddenThread->BreakOnTermination = TRUE;

							*(ULONG*)((ULONG64)Thread + NtapiOffsets.ThreadBreakOnTerminationFlagOffset) &= ~0x20;

							ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
							return TRUE;
						}
					}
				}
			}
		}
	}

	ExFreePoolWithTag(ProcInfo, DRIVER_TAG);
	return FALSE;
}

BOOLEAN RsumeProcessGrantedAccess(PEPROCESS_S TargetProcess)
{
	return 0;
}

BOOLEAN IsPicoContextNull(PETHREAD TargetThread)
{
	if (g_HyperHide.CurrentWindowsBuildNumber < WINDOWS_8_1)
		return TRUE;
	else
		return !(*(ULONG64*)((ULONG64)TargetThread + NtapiOffsets.PicoContextOffset));
}

BOOLEAN IsSetThreadContextRestricted(PEPROCESS TargetProcess)
{
	if (g_HyperHide.CurrentWindowsBuildNumber < WINDOWS_10_VERSION_REDSTONE2)
		return FALSE;
	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
		return *(ULONG*)((ULONG64)TargetProcess + NtapiOffsets.RestrictSetThreadContextOffset) & 0x2 ? TRUE : FALSE;
	else
		return *(ULONG*)((ULONG64)TargetProcess + NtapiOffsets.RestrictSetThreadContextOffset) & 0x20000 ? TRUE : FALSE;
}

BOOLEAN GetOffsets()
{
	if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_11)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0x74;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x560;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x560;
		NtapiOffsets.PicoContextOffset = 0x630;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x460;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x5c0;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_21H1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_21H2 ||
		g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_20H2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_20H1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0x74;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x510;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x510;
		NtapiOffsets.PicoContextOffset = 0x5e0;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x460;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x5c0;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_19H2 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_19H1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0x74;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6e0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6e0;
		NtapiOffsets.PicoContextOffset = 0x7a8;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x308;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE5)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
		NtapiOffsets.PicoContextOffset = 0x798;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x300;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE4)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
		NtapiOffsets.PicoContextOffset = 0x7a0;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x300;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE3)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6d0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6d0;
		NtapiOffsets.PicoContextOffset = 0x7a0;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x300;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6c8;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6c8;
		NtapiOffsets.PicoContextOffset = 0x798;
		NtapiOffsets.RestrictSetThreadContextOffset = 0x810;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_REDSTONE1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6c0;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6c0;
		NtapiOffsets.PicoContextOffset = 0x790;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD2)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6bc;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6bc;
		NtapiOffsets.PicoContextOffset = 0x788;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x468;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_10_VERSION_THRESHOLD1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6bc;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6bc;
		NtapiOffsets.PicoContextOffset = 0x788;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x460;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8_1)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x6b4;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x6b4;
		NtapiOffsets.PicoContextOffset = 0x770;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x450;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_8)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x42c;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x42c;
		NtapiOffsets.PicoContextOffset = 0x770;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x450;
	}

	else if (g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7_SP1 || g_HyperHide.CurrentWindowsBuildNumber == WINDOWS_7)
	{
		NtapiOffsets.BypassProcessFreezeFlagOffset = 0;
		NtapiOffsets.ThreadHideFromDebuggerFlagOffset = 0x448;
		NtapiOffsets.ThreadBreakOnTerminationFlagOffset = 0x448;
		NtapiOffsets.PicoContextOffset = 0;
		NtapiOffsets.RestrictSetThreadContextOffset = 0;
		NtapiOffsets.SeAuditProcessCreationInfoOffset = 0x390;
	}

	else
	{
		return FALSE;
	}

	return TRUE;
}

ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle)
{
	ULONG Pid = 0;
	PETHREAD Thread;
	if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, ExGetPreviousMode(), (PVOID*)&Thread, nullptr)))
	{
		Pid = (ULONG)(ULONG_PTR)PsGetProcessId(PsGetThreadProcess(Thread));
		ObDereferenceObject(Thread);
	}
	return Pid;
}

ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
	ULONG Pid = 0;
	PEPROCESS Process;
	if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&Process, nullptr)))
	{
		Pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
		ObDereferenceObject(Process);
	}
	return Pid;
}

UCHAR* GetProcessNameFromProcessHandle(HANDLE ProcessHandle)
{
	UCHAR* psname = NULL;
	PEPROCESS Process;
	if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&Process, nullptr)))
	{
		psname = PsGetProcessImageFileName(Process);
		ObDereferenceObject(Process);
	}
	return psname;
}

#include <intrin.h>
KIRQL WPOFF()        //ԭWPOFFx64
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPON(KIRQL irql)        //ԭWPONx64
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

BOOLEAN MdlCopyMemory(IN VOID* address, IN VOID* buffer, IN size_t size) {
	BOOLEAN bRet = FALSE;
	PMDL Mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);

	if (!Mdl) return FALSE;
	__try {
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
		PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		if (Mapping) {
			RtlCopyMemory(buffer, Mapping, size);
			MmUnmapLockedPages(Mapping, Mdl);
			bRet = TRUE;
		}
		MmUnlockPages(Mdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}

	IoFreeMdl(Mdl);
	return bRet;
}

BOOLEAN ReadMemory2(IN PVOID BaseAddress, PVOID buffer, IN SIZE_T BufferSize, PULONG NumberOfBytesReaded, PEPROCESS pEProcess)
{
	BOOLEAN bRet = FALSE;

	if (pEProcess == NULL)
	{
		DbgPrint("获取进程对象失败");
		return FALSE;
	}

	PVOID GetData;
	__try
	{
		GetData = ExAllocatePool(NonPagedPool, BufferSize);
	}
	__except (1)
	{
		DbgPrint("内存分配异常");
		return FALSE;
	}
	if (!GetData)
	{
		DbgPrint("内存分配失败");
		return FALSE;
	}

	KAPC_STATE stack = { 0 };
	KeStackAttachProcess(pEProcess, &stack);
	ProbeForRead(BaseAddress, BufferSize, sizeof(CHAR));
	RtlCopyMemory(GetData, BaseAddress, BufferSize);
	KeUnstackDetachProcess(&stack);

	KeStackAttachProcess(PsGetCurrentProcess(), &stack);
	ProbeForRead(buffer, BufferSize, sizeof(CHAR));
	RtlCopyMemory(buffer, GetData, BufferSize);//yao
	//DbgPrint("ret:%d [%lX][%lX][%lX][%lX] \n",bRet,*(UCHAR*)(buffer), *(UCHAR*)((UINT64)buffer + 1), *(UCHAR*)((UINT64)buffer + 2), *(UCHAR*)((UINT64)buffer + 3));
	KeUnstackDetachProcess(&stack);


	ExFreePool(GetData);
	return bRet;
}


BOOLEAN ReadMemory1(IN PVOID BaseAddress, PVOID buffer, IN SIZE_T BufferSize, PULONG NumberOfBytesReaded, PEPROCESS pEProcess)
{
	BOOLEAN bRet = FALSE;


	if (pEProcess == NULL)
	{
		DbgPrint("获取进程对象失败");
		return FALSE;
	}

	PVOID GetData;
	__try
	{
		GetData = ExAllocatePool(PagedPool, BufferSize);
	}
	__except (1)
	{
		DbgPrint("内存分配异常");
		return FALSE;
	}
	if (!GetData)
	{
		DbgPrint("内存分配失败");
		return FALSE;
	}
	//memset(GetData, 0, BufferSize);
	KAPC_STATE stack = { 0 };
	KeStackAttachProcess(pEProcess, &stack);
	//DbgBreakPoint();//能双机不,没配置，之前蓝屏了重置
	bRet = MdlCopyMemory(BaseAddress, GetData, BufferSize);
	//__try
	//{
	//	ProbeForRead(BaseAddress, BufferSize, 1);
	//	RtlCopyMemory(GetData, BaseAddress, BufferSize);
	//}
	//__except (1)
	//{
	//	DbgPrint("读取内存出错");
	//	bRet = FALSE;
	//}

	//ObDereferenceObject(pEProcess);
	KeUnstackDetachProcess(&stack);

	KeStackAttachProcess(PsGetCurrentProcess(), &stack);
	RtlCopyMemory(buffer, GetData, BufferSize);//yao
	//看看
	//DbgPrint("ret:%d [%lX][%lX][%lX][%lX] \n",bRet,*(UCHAR*)(buffer), *(UCHAR*)((UINT64)buffer + 1), *(UCHAR*)((UINT64)buffer + 2), *(UCHAR*)((UINT64)buffer + 3));
	KeUnstackDetachProcess(&stack);

	/*DbgPrint("进程ID:%d",data->pid);
	for (int i = 0; i < data->size; i++)
	{
		//data->data[i] = GetData[i];
		DbgPrint("地址:%x 数据:%x data:%x", data->address+i,GetData[i],data->data[i]);
	}
	DbgPrint("输出完毕");*/

	ExFreePool(GetData);
	return bRet;
}

BOOLEAN SafeCopyMemory(PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy)
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	if (!MmIsAddressValid(pDestination) || !MmIsAddressValid(pSourceAddress))
		return FALSE;
	pMdl = IoAllocateMdl(pDestination, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);
	if (!pMdl)
		return FALSE;
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
	if (!pSafeAddress)
		return FALSE;
	__try
	{
		RtlMoveMemory(pSafeAddress, pSourceAddress, SizeOfCopy);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		;
	}
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

/*
MmBuildMdlForNonPagedPool 不能与描述内核堆栈上分配的缓冲区的 MDL 一起使用。
若要生成描述内核堆栈缓冲区的 MDL，驱动程序必须调用 MmProbeAndLockPages。
这是因为内核堆栈页可以交易，除非它们被探测并锁定。 即使驱动程序保证内核堆栈无法分页，此规则也适用。
由于 MDL 描述的页面已不可分页且已映射到系统地址空间，因此驱动程序不得尝试使用 MmProbeAndLockPages 例程锁定它们，
也不得尝试使用 MmMapLockedPagesSpecifyCache 例程创建其他系统地址空间映射。
同样，驱动程序不得尝试使用 MmUnlockPages 例程解锁页面，也不得尝试使用 MmUnmapLockedPages 例程释放现有的系统地址空间映射。
如果驱动程序对 MmBuildMdlForNonPagedPool 生成的 MDL 执行上述任何非法操作，则生成的行为是不定义的。
*/
//读取内存
NTSTATUS MyReadMemory(IN PVOID BaseAddress, PVOID buffer, IN SIZE_T BufferSize, PULONG NumberOfBytesReaded, PEPROCESS pEProcess, UINT32 MDL_Flag)
{
	if (!buffer || !BaseAddress || !pEProcess || BufferSize == 0)
	{
		DbgPrint("MyReadMemory:invalid parameter:%p %p %p %d  \n", buffer, BaseAddress, pEProcess, BufferSize);
		return STATUS_UNSUCCESSFUL;
	}


	KAPC_STATE apc; PMDL temp_pMdl = NULL;  PVOID systemVirtalAddress = NULL;
	BOOLEAN battach = FALSE; BOOLEAN bmapLockPages = FALSE; BOOLEAN bProbAndLockPages = FALSE;
	__try
	{
		//创建一个MDL
		temp_pMdl = IoAllocateMdl(buffer, BufferSize, FALSE, FALSE, NULL);
		//temp_pMdl = MmCreateMdl(NULL, buffer, BufferSize);
		if (temp_pMdl)
		{
			DbgPrint("11111111111111111111\n");

			MmBuildMdlForNonPagedPool(temp_pMdl);//!!!!!!!!!!!!!!!!!!!
			MmProbeAndLockPages(temp_pMdl, KernelMode, IoWriteAccess); bProbAndLockPages = TRUE;
			DbgPrint("222222222222222222222\n");
            //systemVirtalAddress = MmMapLockedPages(temp_pMdl, KernelMode);out dated
			systemVirtalAddress = MmMapLockedPagesSpecifyCache(temp_pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);bmapLockPages = TRUE;
			//把mdl安全映射到系统空间，一个mdl不能被映射多次
			// A driver must not try to create more than one system-address-space mapping for an MDL.
			//systemVirtalAddress = MmGetSystemAddressForMdlSafe(temp_pMdl, NormalPagePriority);
			if (systemVirtalAddress)
			{
				KeStackAttachProcess(pEProcess, &apc); battach = TRUE;
				ProbeForRead(BaseAddress, BufferSize, sizeof(CHAR));
				RtlCopyMemory(systemVirtalAddress, BaseAddress, BufferSize);
				KeUnstackDetachProcess(&apc); battach = FALSE;

				//KeStackAttachProcess(IoGetCurrentProcess(), &apc); battach = TRUE;
				//ProbeForWrite(buffer, BufferSize, sizeof(CHAR));
				//RtlCopyMemory(buffer, systemVirtalAddress, BufferSize);
				//KeUnstackDetachProcess(&apc); battach = FALSE;

				MmUnmapLockedPages(systemVirtalAddress, temp_pMdl); bmapLockPages = FALSE;
				MmUnlockPages(temp_pMdl); bProbAndLockPages = FALSE;
				IoFreeMdl(temp_pMdl);
			}
			else
			{
				DbgPrint("MmGetSystemAddressForMdlSafe failed \n");
			}
		}
		else
		{
			DbgPrint("MmCreateMdl failed \n");
		}
	}
	__except (1) {
		DbgPrint("无法访问地址:systemVirtalAddress:%p src:%p size:%llu \n", systemVirtalAddress, BaseAddress, BufferSize);
		if (battach)
		{
			KeUnstackDetachProcess(&apc);
		}

		if (systemVirtalAddress && bmapLockPages)
			MmUnmapLockedPages(systemVirtalAddress, temp_pMdl);

		if (temp_pMdl && bProbAndLockPages)
		{
			MmUnlockPages(temp_pMdl);
			IoFreeMdl(temp_pMdl);
		}

		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Dst,
	IN CONST VOID UNALIGNED* Src,
	IN ULONG Length)
{
	//MDL是一个对物理内存的描述，负责把虚拟内存映射到物理内存
	PMDL pmdl = IoAllocateMdl(Dst, Length, 0, 0, NULL);//分配mdl
	if (pmdl == NULL)
		return STATUS_UNSUCCESSFUL;

	MmBuildMdlForNonPagedPool(pmdl);//build mdl
	unsigned int* Mapped = (unsigned int*)MmMapLockedPages(pmdl, KernelMode);//锁住内存
	if (!Mapped) {
		IoFreeMdl(pmdl);
		return STATUS_UNSUCCESSFUL;
	}

	//KIRQL kirql = KeRaiseIrqlToDpcLevel();
	ProbeForWrite((CONST PVOID)Mapped, Length, sizeof(CHAR));
	RtlCopyMemory(Mapped, Src, Length);
	//KeLowerIrql(kirql);

	MmUnmapLockedPages((PVOID)Mapped, pmdl);
	IoFreeMdl(pmdl);

	return STATUS_SUCCESS;
}


NTSTATUS MyWriteMemory(IN PVOID BaseAddress, PVOID WriteBytes, IN SIZE_T BufferSize, PEPROCESS EProcess)
{
	KeAttachProcess(EProcess);
	if (BufferSize == 1 && (((PUCHAR)WriteBytes)[0] == 0xcc))
	{
		DbgPrint("MyWriteMemory:set breakpoint at:%p \n", BaseAddress);
	}
	__try
	{
		ProbeForWrite((CONST PVOID)BaseAddress, BufferSize, sizeof(CHAR));
		KIRQL tempIrql = WPOFF();
		RtlCopyMemory((CONST PVOID)BaseAddress, WriteBytes, BufferSize);
		WPON(tempIrql);
	}
	__except (1)
	{
		KeDetachProcess();
		return STATUS_UNSUCCESSFUL;
	}

	KeDetachProcess();
	return STATUS_SUCCESS;
}