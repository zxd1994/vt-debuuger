#pragma once
#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#include "KernelDbgStruct.h"


EXTERN_C PPEB  PsGetProcessPeb(PEPROCESS);

EXTERN_C NTKERNELAPI NTSTATUS ObCreateObjectType(
	__in PUNICODE_STRING TypeName,
	__in PVOID ObjectTypeInitializer,
	__in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
	__out PVOID* ObjectType
);

EXTERN_C NTKERNELAPI PVOID PsGetProcessDebugPort(
	_In_ PEPROCESS Process
);

EXTERN_C NTSTATUS NTAPI PsSuspendProcess(
	PEPROCESS Process);

EXTERN_C NTSTATUS NTAPI PsResumeProcess(PEPROCESS Process);


EXTERN_C  NTSTATUS NTAPI NtTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);
EXTERN_C UCHAR* NTAPI PsGetProcessImageFileName(
	__in PEPROCESS Process
);

EXTERN_C NTSTATUS NTAPI PsReferenceProcessFilePointer(//通过EPROCESS获取文件对象
	IN PEPROCESS Process,
	OUT PVOID* pFilePointer
);

EXTERN_C NTSTATUS  NTAPI ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,  //处理进程信息,只需要处理类别为5的即可
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);
EXTERN_C PVOID NTAPI ObGetObjectType(
	IN PVOID pObject);

EXTERN_C HANDLE NTAPI PsGetProcessInheritedFromUniqueProcessId(//获取父进程ID
	PEPROCESS Process);

EXTERN_C PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
	PVOID Base
);
EXTERN_C NTKERNELAPI PVOID PsGetProcessDebugPort(
	_In_ PEPROCESS Process
);
EXTERN_C LONG NTAPI ExSystemExceptionFilter(VOID);
EXTERN_C NTSTATUS ObCreateObject(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID* Object
);

EXTERN_C void ExfAcquirePushLockShared(
	EX_PUSH_LOCK Lock
);
EXTERN_C void ExfReleasePushLockShared(
	EX_PUSH_LOCK Lock
);