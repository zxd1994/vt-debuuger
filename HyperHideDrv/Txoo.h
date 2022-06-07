#include "ntddk.h"
typedef struct _DbgProcess
{
	LIST_ENTRY64 DbgProcessList;
	PEPROCESS DebugProcess;
	PEPROCESS Process;
	POBJECT_TYPE DebugObject;
	HANDLE DbgHanle;
}DbgProcess, *PDbgProcess;

typedef NTSTATUS(__fastcall *pfNtCreateDebugObject)(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	);

typedef NTSTATUS(
	__fastcall*
	pfNtDebugActiveProcess)(IN HANDLE ProcessHandle,
	IN HANDLE DebugHandle);

typedef
NTSTATUS(
__fastcall* pfNtWaitForDebugEvent)(IN HANDLE DebugHandle,
IN BOOLEAN Alertable,
IN PLARGE_INTEGER Timeout OPTIONAL,
OUT ULONG64 StateChange);



typedef
NTSTATUS(
__fastcall*
pfNtDebugContinue)(IN HANDLE DebugHandle,
IN PCLIENT_ID AppClientId,
IN NTSTATUS ContinueStatus);
typedef
NTSTATUS
(__fastcall*
pfNtRemoveProcessDebug)(IN HANDLE ProcessHandle,
IN HANDLE DebugHandle);
typedef NTSTATUS (__fastcall *pfDbgkpQueueMessage)(IN PEPROCESS Process, IN PETHREAD Thread, IN OUT ULONG64 ApiMsg, IN ULONG Flags, IN ULONG64 TargetDebugObject);
typedef VOID(__fastcall *pfDbgkMapViewOfSection)(IN PVOID Processs,
	IN PVOID Section,
	IN ULONG BaseAddress
	);
typedef VOID(__fastcall *pfDbgkUnMapViewOfSection)(IN PEPROCESS PROCESS, IN PVOID BaseAddress);
typedef NTSTATUS (__fastcall *pfDbgkOpenProcessDebugPort)(IN PEPROCESS Process, IN KPROCESSOR_MODE PreviousMode, OUT HANDLE *DebugHandle);
typedef VOID(__fastcall *pfDbgkCopyProcessDebugPort)(IN PEPROCESS Process, IN PEPROCESS Parent,  IN ULONG64 unknow, IN ULONG64 unknow1);
typedef BOOLEAN( __fastcall *pfDbgkForwardException)(IN PEXCEPTION_RECORD ExceptionRecord, IN BOOLEAN DebugPort, IN BOOLEAN SecondChance);
extern pfNtCreateDebugObject  ori_pslp40;//pfNtCreateDebugObject
extern pfNtDebugActiveProcess ori_pslp43;//pfNtDebugActiveProcess
extern pfNtWaitForDebugEvent ori_pslp41;//pfNtWaitForDebugEvent
extern pfNtDebugContinue ori_pslp42;//pfNtDebugContinue
extern pfNtRemoveProcessDebug ori_pslp44;//pfNtRemoveProcessDebug
extern pfDbgkForwardException ori_pslp3;//pfDbgkForwardException
extern pfDbgkCopyProcessDebugPort ori_pslp2;//pfDbgkCopyProcessDebugPort
extern pfDbgkOpenProcessDebugPort ori_pslp4;//pfDbgkOpenProcessDebugPort
extern  pfDbgkUnMapViewOfSection ori_pslp5;//pfDbgkUnMapViewOfSection
extern pfDbgkMapViewOfSection ori_pslp6; //pfDbgkMapViewOfSection
extern pfDbgkpQueueMessage ori_pslp11;//pfDbgkpQueueMessage
VOID NTAPI Debug_ExFreeItem(PDbgProcess Item);
PDbgProcess Debug_FindMyNeedData(PDbgProcess DbgStruct);
PDbgProcess Debug_AddStructToList(PDbgProcess DbgStruct);
EXTERN_C VOID InitialzeDbgprocessList();