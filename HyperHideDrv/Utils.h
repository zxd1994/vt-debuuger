#pragma once
#ifndef _NTIFS_H
#define _NTIFS_H
#include <ntifs.h>
#endif // !_NTIFS_H


#include "Ntstructs.h"
#include "Hider.h"


typedef struct _NTAPI_OFFSETS
{
	ULONG SeAuditProcessCreationInfoOffset;
	ULONG BypassProcessFreezeFlagOffset;
	ULONG ThreadHideFromDebuggerFlagOffset;
	ULONG ThreadBreakOnTerminationFlagOffset;
	ULONG PicoContextOffset;
	ULONG RestrictSetThreadContextOffset;
}NTAPI_OFFSETS;

template <typename T>
PEPROCESS PidToProcess(T Pid)
{
	PEPROCESS Process;
	PsLookupProcessByProcessId((HANDLE)Pid, &Process);
	return Process;
}

PEPROCESS GetCsrssProcess();

ULONG64 GetPteAddress(ULONG64 Address);

PVOID FindSignature(PVOID Memory, ULONG64 Size, PCSZ Pattern, PCSZ Mask);

BOOLEAN GetProcessInfo(CONST CHAR* Name, _Out_ ULONG64& ImageSize, _Out_ PVOID& ImageBase);

PEPROCESS GetProcessByName(WCHAR* ProcessName);

BOOLEAN RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, BOOLEAN CaseInsensitive);

BOOLEAN GetSectionData(CONST CHAR* ModuleName, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress);

BOOLEAN ClearBypassProcessFreezeFlag(PEPROCESS Process);

BOOLEAN ClearThreadHideFromDebuggerFlag(PEPROCESS Process);

PVOID GetExportedFunctionAddress(PEPROCESS Process, PVOID ModuleBase, CONST CHAR* ExportedFunctionName);

BOOLEAN ClearProcessBreakOnTerminationFlag(Hider::PHIDDEN_PROCESS HiddenProcess);

BOOLEAN ClearThreadBreakOnTerminationFlags(PEPROCESS TargetProcess);

VOID SaveProcessDebugFlags(Hider::PHIDDEN_PROCESS HiddenProcess);

VOID SaveProcessHandleTracing(Hider::PHIDDEN_PROCESS HiddenProcess);

BOOLEAN IsPicoContextNull(PETHREAD TargetThread);

BOOLEAN IsSetThreadContextRestricted(PEPROCESS TargetProcess);

BOOLEAN GetOffsets();

PVOID GetUserModeModule(PEPROCESS Process, CONST WCHAR* ModuleName, BOOLEAN IsWow64);

UNICODE_STRING PsQueryFullProcessImageName(PEPROCESS TargetProcess);

ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle);

ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle);

UCHAR* GetProcessNameFromProcessHandle(HANDLE ProcessHandle);


//¶ÁÈ¡ÄÚ´æ
NTSTATUS MyReadMemory(IN PVOID BaseAddress, PVOID buffer, IN SIZE_T BufferSize, PULONG NumberOfBytesReaded, PEPROCESS pEProcess, UINT32 MDL_Flag);
NTSTATUS MyWriteMemory(IN PVOID BaseAddress, PVOID WriteBytes, IN SIZE_T BufferSize, PEPROCESS EProcess);

NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Dst,
	IN CONST VOID UNALIGNED* Src,
	IN ULONG Length);

BOOLEAN ReadMemory1(IN PVOID BaseAddress, PVOID buffer, IN SIZE_T BufferSize, PULONG NumberOfBytesReaded, PEPROCESS pEProcess);
BOOLEAN ReadMemory2(IN PVOID BaseAddress, PVOID buffer, IN SIZE_T BufferSize, PULONG NumberOfBytesReaded, PEPROCESS pEProcess);