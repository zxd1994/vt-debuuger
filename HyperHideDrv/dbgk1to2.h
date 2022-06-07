#include <ntifs.h>
#include "KernelDbgStruct.h"

EXTERN_C
BOOLEAN
__fastcall
proxyDbgkForwardException(IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugPort,
	IN BOOLEAN SecondChance);

EXTERN_C
VOID
proxyDbgkCopyProcessDebugPort(
	IN PEPROCESS_S TargetProcess,
	IN PEPROCESS_S SourceProcess
	, IN ULONG64 unknow, IN ULONG64 unknow1
);

EXTERN_C
NTSTATUS
__fastcall
proxyDbgkOpenProcessDebugPort(IN PEPROCESS_S Process,
	IN KPROCESSOR_MODE PreviousMode,
	OUT HANDLE* DebugHandle);

EXTERN_C
NTSTATUS __fastcall
DbgkpSetProcessDebugObject_2(//∑¥ª„±‡OK
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread
);

typedef
NTSTATUS 
(*OriginalDbgkpSetProcessDebugObject)(//∑¥ª„±‡OK
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread
	); OriginalDbgkpSetProcessDebugObject originalDbgkpSetProcessDebugObject;

EXTERN_C
NTSTATUS __fastcall
DbgkpQueueMessage_2(
	IN PEPROCESS_S Process,
	IN PETHREAD_S Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
);

EXTERN_C
NTSTATUS __fastcall proxyNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
);


EXTERN_C
NTSTATUS DbgkpPostFakeThreadMessages_2(

	PEPROCESS_S	Process,
	PDEBUG_OBJECT	DebugObject,
	PETHREAD	StartThread,
	PETHREAD* pFirstThread,
	PETHREAD* pLastThread
);
typedef
NTSTATUS(*OriginalDbgkpPostFakeThreadMessages)(

	PEPROCESS_S	Process,
	PDEBUG_OBJECT	DebugObject,
	PETHREAD	StartThread,
	PETHREAD* pFirstThread,
	PETHREAD* pLastThread
	);
OriginalDbgkpPostFakeThreadMessages originalDbgkpPostFakeThreadMessages;

EXTERN_C
VOID
__fastcall
proxyDbgkUnMapViewOfSection(IN PEPROCESS_S PROCESS, IN PVOID BaseAddress);

EXTERN_C
NTSTATUS
NTAPI
proxyNtDebugContinue(IN HANDLE DebugHandle,
	IN PCLIENT_ID AppClientId,
	IN NTSTATUS ContinueStatus);


EXTERN_C
NTSTATUS
NTAPI
proxyNtRemoveProcessDebug(IN HANDLE ProcessHandle,
	IN HANDLE DebugHandle);

EXTERN_C
VOID
__fastcall
proxyDbgkpDeleteObject(IN PVOID DebugObject);

EXTERN_C
VOID __fastcall
proxyDbgkpCloseObject(
	IN PEPROCESS_S Process,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG_PTR ProcessHandleCount,
	IN ULONG_PTR SystemHandleCount
);

EXTERN_C
VOID
__fastcall
proxyDbgkMapViewOfSection(IN PVOID Processs,
	IN PVOID Section,
	IN ULONG64 BaseAddress
);

EXTERN_C
VOID
__fastcall
proxyDbgkExitProcess(IN NTSTATUS ExitStatus);

EXTERN_C
VOID
__fastcall
proxyDbgkExitThread(IN NTSTATUS ExitStatus);

EXTERN_C
VOID __fastcall
proxyPspExitThread(
	IN NTSTATUS ExitStatus
);

typedef
VOID
(*pfPspExitThread)(
	IN NTSTATUS ExitStatus
	); 
EXTERN_C pfPspExitThread originalproxyPspExitThread;


typedef
NTSTATUS
(__fastcall* DbgkpPostFakeThreadMessagesx)(IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD StartThread,
	OUT PETHREAD* FirstThread,
	OUT PETHREAD* LastThread);
EXTERN_C  DbgkpPostFakeThreadMessagesx DbgkpPostFakeThreadMessages;

typedef NTSTATUS(__fastcall* pfDbgkpPostFakeProcessCreateMessages)(
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD* pLastThread
	); EXTERN_C  pfDbgkpPostFakeProcessCreateMessages DbgkpPostFakeProcessCreateMessages;


typedef NTSTATUS(__fastcall*
	pfDbgkpSetProcessDebugObject)(
		IN PEPROCESS_S Process,
		IN PDEBUG_OBJECT DebugObject,
		IN NTSTATUS MsgStatus,
		IN PETHREAD LastThread); EXTERN_C  pfDbgkpSetProcessDebugObject DbgkpSetProcessDebugObject;

typedef INT64(__fastcall* pfnPsSynchronizeWithThreadInsertion)(__int64 a1, __int64 a2);
EXTERN_C  pfnPsSynchronizeWithThreadInsertion PsSynchronizeWithThreadInsertion;

typedef NTSTATUS(__fastcall* DbgkpPostModuleMessagesx)(PEPROCESS_S process, PKTHREAD THREAD, PDEBUG_OBJECT debug);
EXTERN_C  DbgkpPostModuleMessagesx DbgkpPostModuleMessages;

typedef void (__fastcall* pfDbgkSendSystemDllMessages)(PETHREAD pethread, PDEBUG_OBJECT pdebugobj, PDBGKM_MSG pdbgMsg);
EXTERN_C  pfDbgkSendSystemDllMessages DbgkSendSystemDllMessages;

typedef PETHREAD(__fastcall* PsGetNextProcessThreadx)(PEPROCESS_S process, PETHREAD THREAD);
//typedef PETHREAD(__fastcall* PsGetNextProcessThreadx)(PEPROCESS_wrk process, PKTHREAD THREAD);
EXTERN_C  PsGetNextProcessThreadx PsGetNextProcessThread;

typedef PVOID(__fastcall* pfPsQuerySystemDllInfo)(int index);
EXTERN_C  pfPsQuerySystemDllInfo PsQuerySystemDllInfo;

typedef BOOLEAN(__stdcall* pfExAcquireRundownProtection_0)(PEX_RUNDOWN_REF RunRef);
EXTERN_C  pfExAcquireRundownProtection_0 ExAcquireRundownProtection_0;

typedef NTSTATUS(__fastcall* PsSuspendThreadx)(IN PETHREAD_S Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
EXTERN_C  PsSuspendThreadx PsSuspendThread;

typedef NTSTATUS(__fastcall* PsResumeThreadx)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
EXTERN_C  PsResumeThreadx PsResumeThread;

typedef __int64(__fastcall* pfPsThawProcess)(PEPROCESS process, __int64 a2);
EXTERN_C  pfPsThawProcess PsThawProcess;

typedef char (__fastcall* pfPsFreezeProcess)(PEPROCESS process, char a2);
EXTERN_C  pfPsFreezeProcess PsFreezeProcess;

typedef NTSTATUS(__fastcall* MmGetFileNameForSectionx)(IN PVOID Thread, OUT POBJECT_NAME_INFORMATION* FileName OPTIONAL);
EXTERN_C  MmGetFileNameForSectionx MmGetFileNameForSection;

typedef BOOLEAN(__fastcall* pfPsTestProtectedProcessIncompatibility)(__int64 a1, __int64 a2, __int64 a3);
EXTERN_C  pfPsTestProtectedProcessIncompatibility PsTestProtectedProcessIncompatibility;

typedef __int64(__fastcall* pfPsRequestDebugSecureProcess)(__int64 a1, unsigned __int8 a2);
EXTERN_C  pfPsRequestDebugSecureProcess PsRequestDebugSecureProcess;

typedef NTSTATUS(__fastcall* pfLpcRequestWaitReplyPortEx)(PVOID64 port, PPORT_MESSAGE Message, PPORT_MESSAGE Buffer);
EXTERN_C  pfLpcRequestWaitReplyPortEx LpcRequestWaitReplyPortEx;

typedef char(__fastcall* pfDbgkpSuspendProcess)(PEPROCESS_S ps);
EXTERN_C  pfDbgkpSuspendProcess DbgkpSuspendProcess;

typedef void (*OriginalproxyDbgkExitProcess)(IN NTSTATUS ExitStatus);
EXTERN_C  OriginalproxyDbgkExitProcess originalproxyDbgkExitProcess;


typedef NTSTATUS
(*ObDuplicateObject1)(
	IN PEPROCESS_S SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS_S TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
	);
EXTERN_C  ObDuplicateObject1 ObDuplicateObject;

typedef
VOID
(__fastcall*
	PfDbgkpFreeDebugEvent)(IN PDEBUG_EVENT DebugEvent);


typedef NTSTATUS(__stdcall* OBCREATEOBJECT)(
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

typedef
LONG(__fastcall* pfDbgkpWakeTarget)(PVOID P);
EXTERN_C  pfDbgkpWakeTarget DbgkpWakeTarget_2;

typedef VOID(*pfnDbgkpMarkProcessPeb)(PEPROCESS_S Process);
EXTERN_C  pfnDbgkpMarkProcessPeb originalDbgkpMarkProcessPeb;

EXTERN_C __int64 DbgkpSetProcessDebugObject_asm(ULONG_PTR BugCheckParameter1, PRKEVENT Event, int a3, ...);

EXTERN_C int  initDbgk();


