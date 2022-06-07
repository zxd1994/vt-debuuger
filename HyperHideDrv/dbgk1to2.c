//#include "KernelDbgStruct.h"

#include "dbgk1to2.h"
//#include "KernelStruct1.h"
#include <ntimage.h>
#include<ntstrsafe.h>
#include"Log.h"
#include "DRRWE.h"
#include "dbgtool.h"
#include "Txoo.h" 
#include "ActiveProcessDbgList.h"
//#include "Utils.h"

POBJECT_TYPE* g_DbgkDebugObjectType = 0;

#ifndef _DBGKTYPES_H
#define _DBGKTYPES_H

//
// Dependencies
//



//
// Debug Object Access Masks
//
#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)

//
// Debug Event Flags
//
#define DEBUG_EVENT_READ                  (0x01)
#define DEBUG_EVENT_NOWAIT                (0x02)
#define DEBUG_EVENT_INACTIVE              (0x04)
#define DEBUG_EVENT_RELEASE               (0x08)
#define DEBUG_EVENT_PROTECT_FAILED        (0x10)
#define DEBUG_EVENT_SUSPEND               (0x20)

//
// NtCreateDebugObject Flags
//
#define DBGK_KILL_PROCESS_ON_EXIT         (0x1)
#define DBGK_ALL_FLAGS                    (DBGK_KILL_PROCESS_ON_EXIT)

typedef enum _LPC_TYPE
{
	LPC_NEW_MESSAGE,
	LPC_REQUEST1,
	LPC_REPLY1,
	LPC_DATAGRAM1,
	LPC_LOST_REPLY1,
	LPC_PORT_CLOSED1,
	LPC_CLIENT_DIED1,
	LPC_EXCEPTION1,
	LPC_DEBUG_EVENT1,
	LPC_ERROR_EVENT1,
	LPC_CONNECTION_REQUEST1,
	LPC_CONNECTION_REFUSED,
	LPC_MAXIMUM
} LPC_TYPE;

//
// Debug Object Information Classes for NtQueryDebugObject
//
typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectUnusedInformation,
	DebugObjectKillProcessOnExitInformation
} DEBUGOBJECTINFOCLASS, * PDEBUGOBJECTINFOCLASS;



//
// Debug Object Information Structures
//
typedef struct _DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION
{
	ULONG KillProcessOnExit;
} DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION, * PDEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION;

#ifndef NTOS_MODE_USER


#endif






#ifndef NTOS_MODE_USER



#endif

#endif
#ifndef _DBGFUNC
#define _DBGFUNC
//NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS *Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);

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

VOID SetDbgMsgNotify(BOOLEAN IsLoad);
p_save_handlentry PmainList;

typedef NTSTATUS(__fastcall*
	pfDbgkpSetProcessDebugObject)(
		IN PEPROCESS_S Process,
		IN PDEBUG_OBJECT DebugObject,
		IN NTSTATUS MsgStatus,
		IN PETHREAD LastThread);

typedef NTSTATUS(__fastcall* pfMmGetFileNameForAddress)(PIMAGE_NT_HEADERS pnt, PUNICODE_STRING modname);
typedef NTSTATUS(__fastcall* pfDbgkpPostFakeProcessCreateMessages)(
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD* pLastThread
	);
NTSTATUS NTAPI DbgkClearProcessDebugObject(IN PEPROCESS_S Process, IN PDEBUG_OBJECT SourceDebugObject OPTIONAL);
NTSTATUS __fastcall DbgkpSendApiMessage_2(IN OUT PDBGKM_MSG ApiMsg, IN BOOLEAN SuspendProcess);
BOOLEAN DbgkpSuppressDbgMsg(IN PTEB64 Teb);
VOID NTAPI DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent);

EXTERN_C
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

#define ProbeForWriteGenericType(Ptr, Type)                                    \
	do {                                                                       \
	if ((ULONG_PTR)(Ptr) + sizeof(Type) - 1 < (ULONG_PTR)(Ptr) ||          \
	(ULONG_PTR)(Ptr) + sizeof(Type) - 1 >= (ULONG_PTR)MmUserProbeAddress) { \
	ExRaiseAccessViolation();                                          \
								}                                                                      \
		*(volatile Type *)(Ptr) = *(volatile Type *)(Ptr);                     \
							} while (0)

#define ProbeForWriteHandle(Ptr) ProbeForWriteGenericType(Ptr, HANDLE)

#define PspSetProcessFlag(Flags, Flag) \
	RtlInterlockedSetBitsDiscardReturn (Flags, Flag)
void ZwFlushInstructionCache(HANDLE process, ULONG64 UNKNOW, ULONG64 UNKNOW1);
ULONG64 fc_DbgkGetAdrress(PUNICODE_STRING64 funcstr);
typedef NTSTATUS
(*OBINSERTOBJECT)(
	__in PVOID Object,
	__inout_opt PACCESS_STATE PassedAccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in ULONG ObjectPointerBias,
	__out_opt PVOID* NewObject,
	__out_opt PHANDLE Handle
	);

typedef
VOID
(__fastcall*
	PfDbgkpFreeDebugEvent)(IN PDEBUG_EVENT DebugEvent);

typedef
LONG(__fastcall* pfDbgkpWakeTarget)(PVOID P);

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
typedef NTSTATUS
(*OBOPENOBJECTBYPOINTER)(
	__in PVOID Object,
	__in ULONG HandleAttributes,
	__in_opt PACCESS_STATE PassedAccessState,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__out PHANDLE Handle
	);


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
typedef PETHREAD(__fastcall* PsGetNextProcessThreadx)(PEPROCESS_S process, PETHREAD THREAD);
typedef NTSTATUS(__fastcall* DbgkpPostModuleMessagesx)(PEPROCESS_S process, PKTHREAD THREAD, PDEBUG_OBJECT debug);
typedef NTSTATUS(__fastcall* KeThawAllThreadsx)();
typedef __int64(__fastcall* pfPsThawProcess)(PEPROCESS process, __int64 a2);
pfPsThawProcess PsThawProcess = 0;
typedef char(__fastcall* pfPsFreezeProcess)(PEPROCESS process, char a2);
pfPsFreezeProcess PsFreezeProcess = 0;

typedef NTSTATUS(__fastcall* PsResumeThreadx)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(__fastcall* PsSuspendThreadx)(IN PETHREAD_S Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(__fastcall* MmGetFileNameForSectionx)(IN PVOID Thread, OUT POBJECT_NAME_INFORMATION* FileName OPTIONAL);
typedef NTSTATUS(__fastcall* PsTerminateProcessx)(IN PEPROCESS_S Process, NTSTATUS STATUS);

typedef INT64(__fastcall* pfnPsSynchronizeWithThreadInsertion)(__int64 a1, __int64 a2);
pfnPsSynchronizeWithThreadInsertion PsSynchronizeWithThreadInsertion = 0;
//proxyDbgkpSendApiMessage DbgkpSendApiMessage;

typedef void(__fastcall* pfDbgkSendSystemDllMessages)(PETHREAD pethread, PDEBUG_OBJECT pdebugobj, PDBGKM_MSG pdbgMsg);
pfDbgkSendSystemDllMessages DbgkSendSystemDllMessages;

typedef PVOID(__fastcall* pfPsQuerySystemDllInfo)(int index);
pfPsQuerySystemDllInfo PsQuerySystemDllInfo = 0;

typedef NTSTATUS(__fastcall* PsGetNextProcessx)(POBJECT_TYPE object);

typedef NTSTATUS(__fastcall*
	proxyDbgkpQueueMessage)(
		IN PEPROCESS_S Process,
		IN PETHREAD Thread,
		IN OUT PDBGKM_MSG ApiMsg,
		IN ULONG Flags,
		IN PDEBUG_OBJECT TargetDebugObject
		);
typedef NTSTATUS
(__fastcall*
	proxyDbgkpSendApiMessage)(
		IN ULONG SuspendProcess, IN OUT PDBGKM_MSG ApiMsg);
typedef NTSTATUS(__fastcall* pfLpcRequestWaitReplyPortEx)(PVOID64 port, PPORT_MESSAGE Message, PPORT_MESSAGE Buffer);
pfLpcRequestWaitReplyPortEx LpcRequestWaitReplyPortEx;
typedef NTSTATUS(__fastcall* KeFreezeAllThreadsx)();


NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);


typedef LONG(*EXSYSTEMEXCEPTIONFILTER)(VOID);
typedef VOID(__fastcall* KiCheckForKernelApcDelivery1)();

PsGetNextProcessx PsGetNextProcess;
PsTerminateProcessx PsTerminateProcess;
MmGetFileNameForSectionx MmGetFileNameForSection = 0;
KeThawAllThreadsx KeThawAllThreads;
PsGetNextProcessThreadx PsGetNextProcessThread;
DbgkpPostModuleMessagesx DbgkpPostModuleMessages;
EXSYSTEMEXCEPTIONFILTER  ExSystemExceptionFilter;
//OBINSERTOBJECT ObInsertObject;
//OBCREATEOBJECT ObCreateObject;
//OBOPENOBJECTBYPOINTER ObOpenObjectByPointer;
PsResumeThreadx PsResumeThread;
PsSuspendThreadx PsSuspendThread;
FAST_MUTEX DbgkFastMutex;
PFAST_MUTEX DbgkFastMutex2;
ULONG64 DbgkpProcessDebugPortMutex;
ObDuplicateObject1 ObDuplicateObject;
KiCheckForKernelApcDelivery1 KiCheckForKernelApcDelivery12;
POBJECT_TYPE_S DbgkDebugObjectType;
POBJECT_TYPE_S* NewDbgObject;
POBJECT_TYPE_S* ObTypeIndexTable = 0;
ULONG64* PspSystemDlls;
ULONG64 PspNotifyEnableMask;
PDEBUG_OBJECT g_pdebugObj = 0;
DEBUG_OBJECT g_debugObj = { 0 };

DbgkpPostFakeThreadMessagesx DbgkpPostFakeThreadMessages = 0;
KeFreezeAllThreadsx KeFreezeAllThreads;
proxyDbgkpSendApiMessage DbgkpSendApiMessage;
proxyDbgkpQueueMessage DbgkpQueueMessage;
pfMmGetFileNameForAddress MmGetFileNameForAddress;
pfDbgkpPostFakeProcessCreateMessages DbgkpPostFakeProcessCreateMessages;
pfDbgkpSetProcessDebugObject DbgkpSetProcessDebugObject;
pfDbgkpWakeTarget DbgkpWakeTarget_2;
typedef VOID(*pfnDbgkpMarkProcessPeb)(PEPROCESS_S Process);
pfnDbgkpMarkProcessPeb originalDbgkpMarkProcessPeb;

typedef BOOLEAN(__fastcall* pfPsTestProtectedProcessIncompatibility)(__int64 a1, __int64 a2, __int64 a3);
pfPsTestProtectedProcessIncompatibility PsTestProtectedProcessIncompatibility = 0;

typedef __int64(__fastcall* pfPsRequestDebugSecureProcess)(__int64 a1, unsigned __int8 a2);
pfPsRequestDebugSecureProcess PsRequestDebugSecureProcess = 0;

typedef char(__fastcall* pfDbgkpSuspendProcess)(PEPROCESS_S ps);
pfDbgkpSuspendProcess DbgkpSuspendProcess;

#endif

//根据线程ID返回线程ETHREAD，失败返回NULL
PETHREAD LookupThread(HANDLE Tid)
{
	PETHREAD ethread;
	if (NT_SUCCESS(PsLookupThreadByThreadId(Tid, &ethread)))
		return ethread;
	else
		return NULL;
}

PETHREAD g_pethreadArray[128] = { "" };
UINT32 g_threadCount = 0;

//枚举指定进程中的线程
void EnumThread(PEPROCESS Process)
{
	g_threadCount = 0;
	ULONG i = 0, c = 0;
	PETHREAD ethrd = NULL;
	PEPROCESS eproc = NULL;
	for (i = 4; i < 262144; i = i + 4) // 一般来说没有超过100000的PID和TID
	{
		ethrd = LookupThread((HANDLE)i);
		if (ethrd != NULL)
		{
			//获得线程所属进程
			eproc = IoThreadToProcess(ethrd);
			if (eproc == Process)
			{
				//打印出ETHREAD和TID
				DbgPrint("线程: ETHREAD=%p TID=%ld\n", ethrd, (ULONG)PsGetThreadId(ethrd));
				g_pethreadArray[g_threadCount] = ethrd;
				g_threadCount++;
			}
			ObDereferenceObject(ethrd);
		}
	}
}

VOID __fastcall
proxyDbgkpCloseObject(
	IN PEPROCESS_S Process,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG_PTR ProcessHandleCount,
	IN ULONG_PTR SystemHandleCount
)
/*++

Routine Description:

Called by the object manager when a handle is closed to the object.

Arguments:

Process - Process doing the close
Object - Debug object being deleted
GrantedAccess - Access ranted for this handle
ProcessHandleCount - Unused and unmaintained by OB
SystemHandleCount - Current handle count for this object

Return Value:

None.

--*/
{
	PDEBUG_OBJECT DebugObject = Object;
	PDEBUG_EVENT DebugEvent;
	PLIST_ENTRY ListPtr;
	BOOLEAN Deref;

	PAGED_CODE();

	UNREFERENCED_PARAMETER(GrantedAccess);
	UNREFERENCED_PARAMETER(ProcessHandleCount);

	DbgPrint("proxyDbgkpCloseObject\n");

	//
	// If this isn't the last handle then do nothing.
	//
	if (SystemHandleCount > 1) {
		return;
	}

	ExAcquireFastMutex(&DebugObject->Mutex);

	//
	// Mark this object as going away and wake up any processes that are waiting.
	//
	DebugObject->Flags |= DEBUG_OBJECT_DELETE_PENDING;

	//
	// Remove any events and queue them to a temporary queue
	//
	ListPtr = DebugObject->EventList.Flink;
	InitializeListHead(&DebugObject->EventList);

	ExReleaseFastMutex(&DebugObject->Mutex);

	//
	// Wake anyone waiting. They need to leave this object alone now as its deleting
	//
	KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);

	//
	// Loop over all processes and remove the debug port from any that still have it.
	// Debug port propagation was disabled by setting the delete pending flag above so we only have to do this
	// once. No more refs can appear now.
	//
	ExAcquireFastMutex(&DbgkFastMutex);
	Deref = Port_RemoveDbgItem(NULL, DebugObject);
	ExReleaseFastMutex(&DbgkFastMutex);


	if (Deref) {
		//	DbgkpMarkProcessPeb(Process);
		//
		// If the caller wanted process deletion on debugger dying (old interface) then kill off the process.
		//
		if (DebugObject->Flags & DEBUG_OBJECT_KILL_ON_CLOSE) {
			//PsTerminateProcess(Process, STATUS_DEBUGGER_INACTIVE);
		}
		ObDereferenceObject(DebugObject);
	}
	/*
		for (Process = PsGetNextProcess(NULL);
			Process != NULL;
			Process = PsGetNextProcess(Process)) {

			if (Process->Pcb.newdbgport == DebugObject)

			{
				Deref = FALSE;
				ExAcquireFastMutex(&DbgkFastMutex);
				if (Process->Pcb.newdbgport == DebugObject) {
					Process->Pcb.newdbgport = NULL;
					Deref = TRUE;
				}
				ExReleaseFastMutex(&DbgkFastMutex);


				if (Deref) {
				//	DbgkpMarkProcessPeb(Process);
					//
					// If the caller wanted process deletion on debugger dying (old interface) then kill off the process.
					//
					if (DebugObject->Flags&DEBUG_OBJECT_KILL_ON_CLOSE) {
						PsTerminateProcess(Process, STATUS_DEBUGGER_INACTIVE);
					}
					ObDereferenceObject(DebugObject);
				}
			}
		}*/
		//
		// Wake up all the removed threads.
		//
	while (ListPtr != &DebugObject->EventList) {
		DebugEvent = CONTAINING_RECORD(ListPtr, DEBUG_EVENT, EventList);
		ListPtr = ListPtr->Flink;
		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}

}

BOOLEAN
proxyDbgkpSuspendProcess(PEPROCESS ps)
{
	DbgPrint("DbgkpSuspendProcess\n");
	if ((((PEPROCESS_S)PsGetCurrentProcess())->Flags &
		PS_PROCESS_FLAGS_PROCESS_DELETE) == 0) {
		//KeEnterCriticalRegion();
		//if (PsFreezeProcess(ps, 0))
			{
				DbgPrint("PsFreezeProcess ok\n");
				return TRUE;
			}
			//KeLeaveCriticalRegion();
	}
	return FALSE;
}
VOID
NTAPI
DbgkpResumeProcess(PEPROCESS ps, __int64 a)
{
	PAGED_CODE();
	DbgPrint("DbgkpResumeProcess\n");
	//KeEnterCriticalRegion();
	//PsThawProcess(ps, 0);
}

HANDLE
FASTCALL
DbgkpSectionToFileHandle(IN PVOID Section)
{
	NTSTATUS Status;
	POBJECT_NAME_INFORMATION FileName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE Handle;
	PAGED_CODE();

	Status = MmGetFileNameForSection(Section, &FileName);
	if (!NT_SUCCESS(Status) || !FileName)
	{
		DbgPrint("DbgkpSectionToFileHandle failed \n");
		return NULL;
	}

	InitializeObjectAttributes(&ObjectAttributes,
		&(FileName->Name),
		OBJ_CASE_INSENSITIVE |
		OBJ_FORCE_ACCESS_CHECK |
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	Status = ZwOpenFile(&Handle,
		GENERIC_READ | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT);

	ExFreePool(FileName);
	if (!NT_SUCCESS(Status)) return NULL;
	return Handle;
}


VOID
__fastcall
proxyDbgkExitThread(IN NTSTATUS ExitStatus)
{
	DbgPrint("proxyDbgkExitThread\n");
	DBGKM_MSG ApiMessage;
	PDBGKM_EXIT_THREAD ExitThread = &ApiMessage.ExitThread;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PETHREAD Thread = PsGetCurrentThread();
	BOOLEAN Suspended;
	PAGED_CODE();

	//if (!Process->Pcb.newdbgport) {
	//	return;
	//}
	//if (!Port_GetPort(Process)) {
	//	DbgPrint("proxyDbgkExitThread: Port_GetPort false\n");
	//	return;
	//}
	//if (((PETHREAD_S)PsGetCurrentThread())->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_DEADTHREAD) {
	//	DbgPrint("proxyDbgkExitThread: CrossThreadFlags PS_CROSS_THREAD_FLAGS_DEADTHREAD\n");
	//	return;
	//}


	ExitThread->ExitStatus = ExitStatus;


	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_EXIT_THREAD));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmExitThreadApi;


	Suspended = proxyDbgkpSuspendProcess(Process);

	DbgPrint("proxyDbgkExitThread: DbgkpSendApiMessage_2\n");
	DbgkpSendApiMessage_2(&ApiMessage, FALSE);

	if (Suspended) DbgkpResumeProcess(Process, 0);
}



typedef void (*OriginalproxyDbgkExitProcess)(IN NTSTATUS ExitStatus);
OriginalproxyDbgkExitProcess originalproxyDbgkExitProcess;

VOID
__fastcall
proxyDbgkExitProcess(IN NTSTATUS ExitStatus)
{
	DbgPrint("proxyDbgkExitProcess\n");
	DBGKM_MSG ApiMessage;
	PDBGKM_EXIT_PROCESS ExitProcess = &ApiMessage.ExitProcess;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PETHREAD Thread = PsGetCurrentThread();
	PAGED_CODE();

	//if (!Process->Pcb.newdbgport) {
	//	return;
	//}


	//if (!Port_GetPort(Process)) {
	//	DbgPrint("proxyDbgkExitProcess: Port_GetPort false\n");
	//	return;
	//}

	//if (((PETHREAD_S)PsGetCurrentThread())->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_DEADTHREAD) {
	//	DbgPrint("proxyDbgkExitProcess: CrossThreadFlags PS_CROSS_THREAD_FLAGS_DEADTHREAD\n");
	//	return;
	//}


	ExitProcess->ExitStatus = ExitStatus;

	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_EXIT_PROCESS));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmExitProcessApi;

	KeQuerySystemTime(&Process->ExitTime);
	DbgPrint("proxyDbgkExitProcess:DbgkpSendApiMessage_2\n");
	DbgkpSendApiMessage_2(&ApiMessage, FALSE);
}


typedef
VOID
(*pfPspExitThread)(
	IN NTSTATUS ExitStatus
	); pfPspExitThread originalproxyPspExitThread;


VOID __fastcall
proxyPspExitThread(
	IN NTSTATUS ExitStatus
)
{
	DbgPrint("PspExitThread\n");


	PETHREAD_S Thread = PsGetCurrentThread();
	PEPROCESS_S Process = IoThreadToProcess(Thread);
	if (Process)
	{
		UCHAR* Name = PsGetProcessImageFileName(Process);
		if (Name)
		{
			if (strcmp(Name, "chrome.exe") == 0 || strcmp(Name, "x64dbg.exe") == 0)
			{
				DbgPrint("proxyPspExitThread:currentProcess:%s\n", Name);
				if (((PTEB64)Thread->Tcb.Teb)->DbgSsReserved)
				{
					DbgPrint("((PTEB64)Thread->Tcb.Teb)->DbgSsReserved[0]:%x\n", ((PTEB64)Thread->Tcb.Teb)->DbgSsReserved[0]);
					((PTEB64)Thread->Tcb.Teb)->DbgSsReserved[0] = 0;
					((PTEB64)Thread->Tcb.Teb)->DbgSsReserved[1] = 0;
				}
				//Process->ActiveThreads--;
				BOOLEAN LastThread = FALSE;
				if (Process->ActiveThreads == 1) {
					LastThread = TRUE;
				}
				//
				// If we need to send debug messages then do so.
				//

				//if (Port_GetPort(Process)) {
				//if (Process->DebugPort != NULL) {
					//
					// Don't report system thread exit to the debugger as we don't report them.
					//
				if (!IS_SYSTEM_THREAD(Thread)) {
					ULONG u1; ULONG u2;
					proxyDbgkpCloseObject(Process, g_pdebugObj, DEBUG_ALL_ACCESS, &u1, &u2);
					if (LastThread) {
						Port_RemoveDbgItem(Process, Port_GetPort(Process));
						//Process->DebugPort = NULL;
						proxyDbgkExitProcess(Process->ExitStatus);
						DbgPrint("proxyDbgkExitProcess SET Process->DebugPort NULL\n");
					}
					else {
						Port_RemoveDbgItem(Process, Port_GetPort(Process));
						//Process->DebugPort = NULL;
						proxyDbgkExitThread(ExitStatus);
						DbgPrint("proxyDbgkExitThread SET Process->DebugPort NULL\n");
					}
				}
				//}
			}
		}
	}

	return originalproxyPspExitThread(ExitStatus);
}

//
//VOID __fastcall
//DbgkCreateThread(
//	PETHREAD_S Thread
//)
//{
//	DBGKM_MSG m;
//	PDBGKM_CREATE_THREAD CreateThreadArgs;
//	PDBGKM_CREATE_PROCESS CreateProcessArgs;
//	PEPROCESS_S Process;
//	PDBGKM_LOAD_DLL LoadDllArgs;
//	NTSTATUS status;
//	PIMAGE_NT_HEADERS NtHeaders;
//	ULONG OldFlags;
//
//	ULONG	index;
//	PMODULE_INFO ModuleInfo;
//	PDEBUG_OBJECT DebugObject;
//	PSYSTEM_DLL	SystemDll;
//	PVOID	Object;
//	PFILE_OBJECT FileObject;
//	PKTHREAD	CurrentThread;
//
//	Process = (PEPROCESS_S)Thread->Tcb.Process;
//
//	OldFlags = PspSetProcessFlag(&Process->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED | PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE);
//
//	if ((OldFlags & PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE) == 0 &&
//		(*(ULONG64*)PspNotifyEnableMask & 0x1))
//	{
//
//		IMAGE_INFO_EX ImageInfoEx;
//		PUNICODE_STRING ImageName;
//		POBJECT_NAME_INFORMATION FileNameInfo;
//
//		//
//		// notification of main .exe
//		//
//
//		ImageInfoEx.ImageInfo.Properties = 0;
//		ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
//		ImageInfoEx.ImageInfo.ImageBase = Process->SectionBaseAddress;
//		ImageInfoEx.ImageInfo.ImageSize = 0;
//
//		try {
//			NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
//
//			if (NtHeaders) {
//				ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, SizeOfImage);
//			}
//		} except(EXCEPTION_EXECUTE_HANDLER) {
//			ImageInfoEx.ImageInfo.ImageSize = 0;
//		}
//		ImageInfoEx.ImageInfo.ImageSelector = 0;
//		ImageInfoEx.ImageInfo.ImageSectionNumber = 0;
//
//		PsReferenceProcessFilePointer((PEPROCESS)Process, &FileObject);
//		status = SeLocateProcessImageName((PEPROCESS)Process, &ImageName);
//		if (!NT_SUCCESS(status))
//		{
//			ImageName = NULL;
//		}
//
//		PsCallImageNotifyRoutines(
//			ImageName,
//			Process->UniqueProcessId,
//			FileObject,
//			&ImageInfoEx);
//
//		if (ImageName)
//		{
//			//因为在SeLocateProcessImageName中为ImageName申请了内存，所以要在此处释放掉
//			ExFreePoolWithTag(ImageName, 0);
//		}
//
//		//PsReferenceProcessFilePointer增加了引用计数
//		ObfDereferenceObject(FileObject);
//
//		index = 0;
//		while (index < 2)
//		{
//			ModuleInfo = (PMODULE_INFO)PsQuerySystemDllInfo(index);
//			if (ModuleInfo != NULL)
//			{
//				ImageInfoEx.ImageInfo.Properties = 0;
//				ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
//				ImageInfoEx.ImageInfo.ImageBase = ModuleInfo->BaseOfDll;
//				ImageInfoEx.ImageInfo.ImageSize = 0;
//
//				try {
//					NtHeaders = RtlImageNtHeader(ModuleInfo->BaseOfDll);
//					if (NtHeaders)
//					{
//						ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, SizeOfImage);
//					}
//				}except(EXCEPTION_EXECUTE_HANDLER) {
//					ImageInfoEx.ImageInfo.ImageSize = 0;
//				}
//
//				ImageInfoEx.ImageInfo.ImageSelector = 0;
//				ImageInfoEx.ImageInfo.ImageSectionNumber = 0;
//
//				//实际就是PspSystemDlls
//				SystemDll = (PSYSTEM_DLL)((ULONG)ModuleInfo - 0x8);
//				Object = ObFastReferenceObject(&SystemDll->FastRef);
//				if (Object == NULL)
//				{
//					CurrentThread = (PKTHREAD)PsGetCurrentThread();
//					KeEnterCriticalRegionThread(CurrentThread);
//
//					ExAcquirePushLockShared(&SystemDll->Lock);
//
//					//由于系统模块不可能得不到，所以逆向发现win7没做判断
//					Object = ObFastReferenceObjectLocked(&SystemDll->FastRef);
//
//					ExReleasePushLockShared(&SystemDll->Lock);
//
//					KeLeaveCriticalRegionThread(CurrentThread);
//
//				}
//
//				FileObject = MmGetFileObjectForSection(Object);
//
//				if (Object != NULL)
//				{
//					ObFastDereferenceObject(
//						&SystemDll->FastRef,
//						Object);
//				}
//
//				PsCallImageNotifyRoutines(
//					&SystemDll->ModuleInfo.FileName,
//					Process->UniqueProcessId,
//					FileObject,
//					&ImageInfoEx);
//
//				ObfDereferenceObject(FileObject);
//			}
//
//			index++;
//		}
//	}
//
//	DebugObject = (PDEBUG_OBJECT)Process->DebugPort;
//
//	if (DebugObject == NULL) {
//		return;
//	}
//
//	if ((OldFlags & PS_PROCESS_FLAGS_CREATE_REPORTED) == 0)
//	{
//
//		CreateThreadArgs = &m.CreateProcess.InitialThread;
//		CreateThreadArgs->SubSystemKey = 0;
//
//		CreateProcessArgs = &m.CreateProcess;
//		CreateProcessArgs->SubSystemKey = 0;
//		CreateProcessArgs->FileHandle = DbgkpSectionToFileHandle(
//			Process->SectionObject
//		);
//		CreateProcessArgs->BaseOfImage = Process->SectionBaseAddress;
//		CreateThreadArgs->StartAddress = NULL;
//		CreateProcessArgs->DebugInfoFileOffset = 0;
//		CreateProcessArgs->DebugInfoSize = 0;
//
//		try {
//
//			NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
//
//			if (NtHeaders) {
//
//				CreateThreadArgs->StartAddress = (PVOID)(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, ImageBase) +
//					DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, AddressOfEntryPoint));
//
//				CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
//				CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
//			}
//		} except(EXCEPTION_EXECUTE_HANDLER) {
//			CreateThreadArgs->StartAddress = NULL;
//			CreateProcessArgs->DebugInfoFileOffset = 0;
//			CreateProcessArgs->DebugInfoSize = 0;
//		}
//
//		DBGKM_FORMAT_API_MSG(m, DbgKmCreateProcessApi, sizeof(*CreateProcessArgs));
//
//		DbgkpSendApiMessage_2(&m, FALSE);
//
//		if (CreateProcessArgs->FileHandle != NULL) {
//			ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
//		}
//
//		proxyDbgkSendSystemDllMessages(
//			NULL,
//			NULL,
//			&m);
//	}
//	else {
//
//		CreateThreadArgs = &m.u.CreateThread;
//		CreateThreadArgs->SubSystemKey = 0;
//		CreateThreadArgs->StartAddress = Thread->Win32StartAddress;
//
//		DBGKM_FORMAT_API_MSG(m, DbgKmCreateThreadApi, sizeof(*CreateThreadArgs));
//
//		DbgkpSendApiMessage(&m, TRUE);
//	}
//
//	if (Thread->ClonedThread == TRUE)
//	{
//		DbgkpPostModuleMessages(
//			Process,
//			Thread,
//			NULL);
//	}
//}

VOID
__fastcall
proxyDbgkUnMapViewOfSection(IN PEPROCESS_S PROCESS, IN PVOID BaseAddress)
{
	DBGKM_MSG ApiMessage;
	PDBGKM_UNLOAD_DLL UnloadDll = &ApiMessage.UnloadDll;
	PEPROCESS Process = PsGetCurrentProcess();
	PETHREAD_S Thread = PsGetCurrentThread();
	DbgProcess dbgmsg = { 0 };
	PTEB64	Teb;
	PAGED_CODE();
	/*
		dbgmsg.DebugProcess = PROCESS;
		if (Debug_FindMyNeedData(&dbgmsg)==FALSE)
		{
			return ori_pslp5(PROCESS, BaseAddress);
		}*/

	if ((ExGetPreviousMode() == KernelMode))
	{
		DbgPrint("proxyDbgkUnMapViewOfSection:ExGetPreviousMode KernelMode\n");
		return;
	}
	if (!Port_GetPort(PROCESS))
	{
		return;
	}

	DbgPrint("proxyDbgkUnMapViewOfSection:Port_GetPort ok\n");

	if (Thread->Tcb.SystemThread != TRUE &&
		Thread->Tcb.ApcStateIndex != 0x1)
	{
		Teb = (PTEB64)Thread->Tcb.Teb;
	}
	else {
		Teb = NULL;
	}

	if (Teb != NULL && Process == PROCESS)
	{
		if (!DbgkpSuppressDbgMsg(Teb))
		{
			//
		}
		else {
			//暂停调试消息的话就退出
			return;
		}
	}


	UnloadDll->BaseAddress = BaseAddress;


	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_UNLOAD_DLL));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmUnloadDllApi;

	DbgPrint("proxyDbgkUnMapViewOfSection:DbgkpSendApiMessage_2 ok\n");
	DbgkpSendApiMessage_2(&ApiMessage, FALSE);
}


VOID
__fastcall
proxyDbgkMapViewOfSection(IN PVOID Processs,
	IN PVOID Section,
	IN ULONG64 BaseAddress
)
{
	DbgProcess dbgmsg = { 0 };
	DBGKM_MSG ApiMessage;
	PDBGKM_LOAD_DLL LoadDll = &ApiMessage.LoadDll;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PETHREAD_S Thread = PsGetCurrentThread();
	PIMAGE_NT_HEADERS NtHeader;
	PTEB64 TEB = (PTEB64)Thread->Tcb.Teb;
	PAGED_CODE();

	/*dbgmsg.DebugProcess = Processs;
	if (Debug_FindMyNeedData(&dbgmsg) == FALSE){
		return ori_pslp6(Processs, Section, BaseAddress);

	}*/

	if ((ExGetPreviousMode() == KernelMode))
	{
		return;
	}

	if (!Port_GetPort(Processs))
	{
		return;
	}

	if (Thread->Tcb.SystemThread != TRUE &&
		Thread->Tcb.ApcStateIndex != 0x1)
	{
		TEB = (PTEB64)Thread->Tcb.Teb;
	}
	else {
		TEB = NULL;
		return;
	}

	if (TEB != NULL && Processs == Process)
	{
		if (!DbgkpSuppressDbgMsg(TEB))
		{
			//
		}
		else {
			//暂停调试消息的话就退出
			DbgPrint("proxyDbgkMapViewOfSection:暂停调试消息的话就退出\n");
			return;
		}
	}

	LoadDll->FileHandle = DbgkpSectionToFileHandle(Section);
	LoadDll->BaseOfDll = BaseAddress;
	LoadDll->DebugInfoFileOffset = 0;
	LoadDll->DebugInfoSize = 0;
	LoadDll->NamePointer = &TEB->NtTib.ArbitraryUserPointer;

	NtHeader = RtlImageNtHeader(BaseAddress);
	if (NtHeader)
	{
		LoadDll->DebugInfoFileOffset = NtHeader->FileHeader.
			PointerToSymbolTable;
		LoadDll->DebugInfoSize = NtHeader->FileHeader.NumberOfSymbols;
	}

	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_LOAD_DLL));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmLoadDllApi;


	DbgkpSendApiMessage_2(&ApiMessage, FALSE);

	ObCloseHandle(LoadDll->FileHandle, KernelMode);
}

BOOLEAN DbgkpSuppressDbgMsg(
	IN PTEB64 Teb)
{
	BOOLEAN bSuppress;
	try {
		bSuppress = (BOOLEAN)Teb->SuppressDebugMsg;
	}except(EXCEPTION_EXECUTE_HANDLER) {
		bSuppress = FALSE;
	}
	return bSuppress;
}

ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
	ULONG Pid = 0;
	PEPROCESS Process;
	if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&Process, NULL)))
	{
		Pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
		ObDereferenceObject(Process);
	}
	return Pid;
}

NTSTATUS __fastcall proxyNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
)
{
	DbgPrint("proxyNtCreateDebugObject\n");

	p_save_handlentry Padd = NULL;

	NTSTATUS status;
	HANDLE Handle;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE        PreviousMode;

	PreviousMode = ExGetPreviousMode();

	try {
		if (PreviousMode != KernelMode) {
			ProbeForWriteHandle(DebugObjectHandle);

			//*DebugObjectHandle = *DebugObjectHandle;
		}
		*DebugObjectHandle = NULL;

	} except(ExSystemExceptionFilter()) {
		return GetExceptionCode();
	}

	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
		return STATUS_INVALID_PARAMETER;
	}

	/*
		Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
		if (Padd == NULL)
		{
			DbgPrint("proxyNtCreateDebugObject");
			return ori_pslp40(DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);

		}*/

		//创建调试对象
	status = ObCreateObject(
		PreviousMode,
		*NewDbgObject,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);


	if (!NT_SUCCESS(status)) {
		DbgPrint("ObCreateObject failed\n");
		return status;
	}
	//初始化调试对象
	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else {
		DebugObject->Flags = 0;
	}

	g_debugObj = *DebugObject;//保存DebugObjet
	g_pdebugObj = &g_debugObj;//保存DebugObjet addr

	status = ObInsertObject(
		DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("ObInsertObject failed\n");
		return status;
	}

	PEPROCESS ps;
	NTSTATUS status1 = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &ps);
	if (NT_SUCCESS(status1))
	{
		UCHAR* Name = PsGetProcessImageFileName(ps);
		DbgPrint("proxyNtCreateDebugObject:PsGetProcessImageFileName:%s\n", Name);
		ObDereferenceObject(ps);
	}

	try {
		*DebugObjectHandle = Handle;
	} except(ExSystemExceptionFilter()) {
		status = GetExceptionCode();
	}

	DbgPrint("proxyNtCreateDebugObject:*DebugObjectHandle:%p\n", *DebugObjectHandle);

	//g_pdebugObj = DebugObject;
	DbgPrint("proxyNtCreateDebugObject:g_pdebugObj:%p\n", g_pdebugObj);

	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd == NULL)
	{
		DbgPrint("proxyNtCreateDebugObject:insertlist\n");
		insertlist(PsGetCurrentProcessId(), PsGetCurrentProcess(), PmainList);
	}


	return status;
}

VOID SendForWarExcept_Thread() {

	DBGKM_MSG ApiMessage = { 0 };
	PDBGKM_CREATE_THREAD CreateThreadArgs = &ApiMessage.CreateThread;


	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_CREATE_THREAD));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmCreateThreadApi;

	CreateThreadArgs->StartAddress = 0x1008611;
	CreateThreadArgs->SubSystemKey = 0;
	DbgPrint("SendForWarExcept_Thread: DbgkpSendApiMessage_2\n");
	DbgkpSendApiMessage_2(&ApiMessage, FALSE);

}

BOOLEAN __fastcall MarkDbgProcess() {
	PEPROCESS_S Process = PsGetCurrentProcess();
	PDbgPortList DbgList = NULL;

	DbgList = Port_FindProcessList(Process, NULL);
	if (DbgList != NULL && MmIsAddressValid(DbgList) == TRUE && DbgList->markdbg == FALSE)
	{

		InterlockedExchange8(&DbgList->markdbg, TRUE);
		//	Process->Pcb.Unused3 = TRUE;
		SendForWarExcept_Thread(); //SendCreateThreadMsg

		return TRUE;

	}
	else {


		return FALSE;
	}
}

NTSTATUS
NTAPI
proxyNtRemoveProcessDebug(IN HANDLE ProcessHandle,
	IN HANDLE DebugHandle)
{
	DbgPrint("proxyNtRemoveProcessDebug \n");
	DbgProcess dbgmsg = { 0 };
	PEPROCESS_S Process;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	NTSTATUS Status;
	PAGED_CODE();
	PDbgProcess pdbgmsg = NULL;

	PEPROCESS ps;
	NTSTATUS status1 = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &ps);
	if (NT_SUCCESS(status1))
		if (ps)
		{
			UCHAR* Name = PsGetProcessImageFileName(ps);
			if (Name)
			{
				if (_stricmp(Name, "TslGame.exe") == 0)
				{
					DbgPrint("proxyNtRemoveProcessDebug:currentProcess:%s\n", Name);
					return STATUS_DEBUGGER_INACTIVE;
				}
			}
		}

	/*dbgmsg.DbgHanle = DebugHandle;
	pdbgmsg = Debug_FindMyNeedData(&dbgmsg);
	if (pdbgmsg == FALSE)
	{

		return ori_pslp44(ProcessHandle, DebugHandle);

	}*/
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SUSPEND_RESUME,
		*PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(Status)) return Status;


	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_ADD_REMOVE_PROCESS,
		*NewDbgObject,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
	/*Status = ObReferenceObjectByHandle(DebugHandle,
	DEBUG_OBJECT_ADD_REMOVE_PROCESS,
	*(ULONG64*)DbgkDebugObjectType,
	PreviousMode,
	(PVOID*)&DebugObject,
	NULL);*/
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("proxyNtRemoveProcessDebug:DEBUG_OBJECT_ADD_REMOVE_PROCESS failed with status:%p \n", Status, DebugObject);
		ObDereferenceObject(Process);
		return Status;
	}

	DbgPrint("DbgkClearProcessDebugObject \n");
	Status = DbgkClearProcessDebugObject(Process, DebugObject);

	//	Debug_ExFreeItem(pdbgmsg);
	ObDereferenceObject(Process);
	ObDereferenceObject(DebugObject);
	return Status;
}

typedef NTSTATUS(*OriginalNtDebugContinue)(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus);
OriginalNtDebugContinue originalNtDebugContinue;

NTSTATUS
NTAPI
proxyNtDebugContinue(IN HANDLE DebugHandle,
	IN PCLIENT_ID AppClientId,
	IN NTSTATUS ContinueStatus)
{
	//return originalNtDebugContinue(DebugHandle, AppClientId, ContinueStatus);

	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent, FoundDebugEvent;
	KPROCESSOR_MODE PreviousMode;
	CLIENT_ID Clid;
	PLIST_ENTRY Entry;
	BOOLEAN GotEvent;

	PreviousMode = ExGetPreviousMode();

	try {
		if (PreviousMode != KernelMode) {
			ProbeForRead(AppClientId, sizeof(CLIENT_ID), sizeof(ULONG));
		}
		Clid = *AppClientId;

	} except(ExSystemExceptionFilter()) {
		return GetExceptionCode();
	}

	//判断继续操作的类型，此函数就这里和wrk中的不同而已
	switch (ContinueStatus) {
	case DBG_EXCEPTION_NOT_HANDLED:
	case DBG_CONTINUE:
	case DBG_TERMINATE_PROCESS:
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	}

	//得到调试对象
	Status = ObReferenceObjectByHandle(
		DebugHandle,
		0x1,
		*NewDbgObject,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	//如果获得指定的调试消息就设置为ture，初始化时为false
	GotEvent = FALSE;
	//保存寻找到调试消息的变量
	FoundDebugEvent = NULL;

	//这个锁很重要
	ExAcquireFastMutex(&DebugObject->Mutex);

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		Entry = Entry->Flink) {

		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);

		//这里几个判断就是为了找到指定消息
		if (DebugEvent->ClientId.UniqueProcess == Clid.UniqueProcess) {
			//如果还没有寻找到，进入if
			if (!GotEvent) {
				//这里的DEBUG_EVENT_READ是表示这个消息有没有没读取过，也就是说有没有被处理过。
				//如果被处理过，而且确实是我们要找的消息，那么就从消息链中移除，并保存，然后
				//设置标记说找到了。这里DEBUG_EVENT_READ的意义十分重要，解读它我是逆向了
				//NtWaitForDebugEvent函数才知晓了这个意义
				if (DebugEvent->ClientId.UniqueThread == Clid.UniqueThread &&
					(DebugEvent->Flags & 0x1) != 0) {
					RemoveEntryList(Entry);
					FoundDebugEvent = DebugEvent;
					GotEvent = TRUE;
				}
			}
			else {
				//会进入这里说明我们已经找到了指定的消息，并且此调试事件链表还不是空的，
				//那么这里就设置完成获取的这个事件；注意，这里这样写是非常有意义的，至于
				//为何要等到分析NtWaitForDebugEvent的时候再揭晓
				DebugEvent->Flags &= ~0x4;
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
				break;
			}
		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	ObfDereferenceObject(DebugObject);

	if (GotEvent) {
		//找到的话，这个消息也就算彻底完成任务了。注意这里的DbgkpWakeTarget函数里，一般非阻塞消息
		//是直接释放所占内存的
		FoundDebugEvent->ApiMsg.ReturnedStatus = ContinueStatus;
		FoundDebugEvent->Status = STATUS_SUCCESS;
		DbgkpWakeTarget(FoundDebugEvent);
	}
	else {
		Status = STATUS_INVALID_PARAMETER;
	}

	return Status;
}



NTSTATUS
__fastcall
proxyDbgkOpenProcessDebugPort(IN PEPROCESS_S Process,
	IN KPROCESSOR_MODE PreviousMode,
	OUT HANDLE* DebugHandle)
{
	struct _DMA_ADAPTER* v7 = 0;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	DbgProcess dbgmsg = { 0 };
	PAGED_CODE();
	/*
		dbgmsg.DebugProcess = Process;
		if (Debug_FindMyNeedData(&dbgmsg)==FALSE)
		{
			return ori_pslp4(Process, PreviousMode, DebugHandle);
		}
	*/

	//if (!Process->Pcb.newdbgport) return STATUS_PORT_NOT_SET;

	if (!Port_IsPort(Process)) return STATUS_PORT_NOT_SET;


	ExAcquireFastMutex(&DbgkFastMutex);

	//DebugObject = Process->Pcb.newdbgport;
	DebugObject = Port_GetPort(Process);
	if (DebugObject)
	{
		v7 = *(struct _DMA_ADAPTER**)DebugObject;
		if (v7)
		{
			ObReferenceObject(DebugObject);
		}
	}

	ExReleaseFastMutex(&DbgkFastMutex);


	if (!DebugObject) return STATUS_PORT_NOT_SET;


	Status = ObOpenObjectByPointer((PVOID)DebugObject,
		PreviousMode == KernelMode ? 0x200 : 0,
		0,
		MAXIMUM_ALLOWED,
		*NewDbgObject,
		PreviousMode,
		DebugHandle);

	if (!NT_SUCCESS(Status))
	{
		//HalPutDmaAdapter(v7);
		return Status;
	}

	ObDereferenceObject(DebugObject);


	return Status;
}

VOID
proxyDbgkCopyProcessDebugPort(
	IN PEPROCESS_S TargetProcess,
	IN PEPROCESS_S SourceProcess
	, IN ULONG64 unknow, IN ULONG64 unknow1
)

{
	PDEBUG_OBJECT DebugObject;
	p_save_handlentry Padd = NULL;

	PAGED_CODE();

	/*Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd == NULL)
	{
		return ori_pslp2(TargetProcess, SourceProcess, unknow, unknow1);

	}*/

	//TargetProcess->Pcb.newdbgport = NULL; // New process. Needs no locks.


	if (Port_IsPort(SourceProcess))

		//if (SourceProcess->Pcb.newdbgport != NULL) 
	{
		ExAcquireFastMutex(&DbgkFastMutex);
		//DebugObject = SourceProcess->Pcb.newdbgport;
		DebugObject = Port_GetPort(SourceProcess);
		if (DebugObject != NULL && (SourceProcess->Flags & PS_PROCESS_FLAGS_NO_DEBUG_INHERIT) == 0) {
			//
			// We must not propagate a debug port thats got no handles left.
			//
			ExAcquireFastMutex(&DebugObject->Mutex);

			//
			// If the object is delete pending then don't propagate this object.
			//
			if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
				ObReferenceObject(DebugObject);

				//TargetProcess->Pcb.newdbgport = DebugObject;
				Port_SetPort(TargetProcess, DebugObject);
			}

			ExReleaseFastMutex(&DebugObject->Mutex);
		}
		ExReleaseFastMutex(&DbgkFastMutex);
	}
}


VOID
__fastcall
proxyDbgkpDeleteObject(IN PVOID DebugObject)
{
	PAGED_CODE();

	DbgPrint("proxyDbgkpDeleteObject\n");

	ASSERT(IsListEmpty(&((PDEBUG_OBJECT)DebugObject)->EventList));
}

VOID
NTAPI
DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent)
{
	PHANDLE Handle = NULL;
	PAGED_CODE();


	switch (DebugEvent->ApiMsg.ApiNumber)
	{

	case DbgKmCreateProcessApi:


		Handle = &DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle;
		break;


	case DbgKmLoadDllApi:


		Handle = &DebugEvent->ApiMsg.u.LoadDll.FileHandle;

	default:
		break;
	}

	if ((Handle) && (*Handle)) ObCloseHandle(*Handle, KernelMode);


	ObDereferenceObject(DebugEvent->Process);
	ObDereferenceObject(DebugEvent->Thread);
	ExFreePoolWithTag(DebugEvent, 'EgbD');
}

VOID
NTAPI
DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent)
{
	PETHREAD_S Thread = DebugEvent->Thread;
	PAGED_CODE();


	if (DebugEvent->Flags & DEBUG_EVENT_SUSPEND) PsResumeThread(Thread, NULL);


	if (DebugEvent->Flags & DEBUG_EVENT_RELEASE)
	{

		ExReleaseRundownProtection(&Thread->RundownProtect);
	}


	if (DebugEvent->Flags & DEBUG_EVENT_NOWAIT)
	{

		DbgkpFreeDebugEvent(DebugEvent);
	}
	else
	{

		KeSetEvent(&DebugEvent->ContinueEvent, IO_NO_INCREMENT, FALSE);
	}
}

POBJECT_TYPE CreateNewObjectType(POBJECT_TYPE_S* OrigDebugObjectType)
{
	NTSTATUS					status;
	POBJECT_TYPE_S				NewObjectType;

	UNICODE_STRING				usObjectTypeName, usFuncName;
	OBCREATEOBJECTTYPE			ObCreateObjectType;
	OBJECT_TYPE_INITIALIZER_S	Object_Type_Init = { 0 };

	NewObjectType = NULL;

	if (OrigDebugObjectType == NULL || *OrigDebugObjectType == NULL || ObTypeIndexTable == NULL)
	{
		if (!OrigDebugObjectType)
		{
			DbgPrint("OrigDebugObjectType is null\n");
		}
		if (!ObTypeIndexTable)
		{
			DbgPrint("ObTypeIndexTable is null\n");
		}

		return NULL;
	}


	RtlInitUnicodeString(&usObjectTypeName, L"VV-DBG");
	RtlInitUnicodeString(&usFuncName, L"ObCreateObjectType");
	ObCreateObjectType = (OBCREATEOBJECTTYPE)MmGetSystemRoutineAddress(&usFuncName);
	if (ObCreateObjectType == NULL)
	{
		return NULL;
	}

	memset(&Object_Type_Init, 0x00, sizeof(OBJECT_TYPE_INITIALIZER_S));
	memcpy(&Object_Type_Init, &(*OrigDebugObjectType)->TypeInfo, sizeof(OBJECT_TYPE_INITIALIZER_S));
	Object_Type_Init.DeleteProcedure = &proxyDbgkpDeleteObject;
	Object_Type_Init.CloseProcedure = &proxyDbgkpCloseObject;
	Object_Type_Init.ValidAccessMask = 0x1f000f;
	status = ObCreateObjectType(&usObjectTypeName, &Object_Type_Init, NULL, &NewObjectType);
	if (status == STATUS_OBJECT_NAME_COLLISION)
	{
		ULONG Index = 2;
		while (ObTypeIndexTable[Index])
		{
			if (RtlCompareUnicodeString(&ObTypeIndexTable[Index]->Name, &usObjectTypeName, FALSE) == 0)
			{
				return (POBJECT_TYPE)ObTypeIndexTable[Index];
			}
			Index++;
		}
	}

	return (POBJECT_TYPE)NewObjectType;
}

#include "Log.h"
int initDbgk() {
	InitDbgPortList();
	PmainList = createlist();//创建记录DBG工具的链表

	ExSystemExceptionFilter = fc_DbgkGetAdrress(L"ExSystemExceptionFilter");
	//ObInsertObject = fc_DbgkGetAdrress(L"ObInsertObject");
	//ObCreateObject = fc_DbgkGetAdrress(L"ObCreateObject");
	//ObOpenObjectByPointer = fc_DbgkGetAdrress(L"ObOpenObjectByPointer");
	KiCheckForKernelApcDelivery12 = fc_DbgkGetAdrress(L"KiCheckForKernelApcDelivery");
	if (!ExSystemExceptionFilter)
	{
		DbgPrint("get ExSystemExceptionFilter failed\n");
		return -1;
	}
	if (!KiCheckForKernelApcDelivery12)
	{
		DbgPrint("get KiCheckForKernelApcDelivery12 failed\n");
		return -2;
	}
	if (!ExSystemExceptionFilter || !KiCheckForKernelApcDelivery12)
	{
		DbgPrint("initDbgk failed\n");
		return -3;
	}

	ExInitializeFastMutex(&DbgkFastMutex);
	DbgkFastMutex2 = (PFAST_MUTEX)DbgkpProcessDebugPortMutex;

	NewDbgObject = g_DbgkDebugObjectType;

	//NewDbgObject =*(ULONG64*)DbgkDebugObjectType; 

	//NewDbgObject = CreateNewObjectType(g_DbgkDebugObjectType);

	if (NewDbgObject == NULL) {

		DbgPrint("NewDbgObject is NULL");
		return -4;
	}
	return 0;

}

NTSTATUS __fastcall
DbgkpQueueMessage_2(
	IN PEPROCESS_S Process,
	IN PETHREAD_S Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject
)
{
	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT StaticDebugEvent;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	DbgProcess dbgmsg = { 0 };
	/*
		dbgmsg.DebugProcess = Process;
		if (Debug_FindMyNeedData(&dbgmsg)==FALSE)
		{
			return ori_pslp11(Process, Thread, ApiMsg, Flags, TargetDebugObject);
		}*/
	PAGED_CODE();

	if (Flags & DEBUG_EVENT_NOWAIT) {
		DbgPrint("DEBUG_EVENT_NOWAIT !!!!!!!!!!!!!!!!!!!!!!!\n");
		DebugEvent = ExAllocatePoolWithQuotaTag(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
			sizeof(*DebugEvent),
			'EgbD');
		if (DebugEvent == NULL) {
			DbgPrint("STATUS_INSUFFICIENT_RESOURCES\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;
		ObReferenceObject(Process);
		ObReferenceObject(Thread);
		DebugEvent->BackoutThread = PsGetCurrentThread();
		DebugObject = TargetDebugObject;
	}
	else {
		DbgPrint("DEBUG_EVENT_WAIT\n");
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;
		ExAcquireFastMutex(&DbgkFastMutex);

		//DebugObject = Process->Pcb.newdbgport;
		//DebugObject = Process->Pcb.newdbgport;
		DebugObject = Port_GetPort(Process);
		//
		// See if this create message has already been sent.
		//
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
			if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG) {
				//DebugObject = NULL;
				DbgPrint("DbgKmCreateThreadApi !!!!!!!!!!!!!!!!!!!!!!!\n");
			}
		}
		if (ApiMsg->ApiNumber == DbgKmLoadDllApi &&
			Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG &&
			Flags & 0x40) {
			//DebugObject = NULL;
			DbgPrint("DbgKmLoadDllApi !!!!!!!!!!!!!!!!!!!!!!!\n");
		}
		//
		// See if this exit message is for a thread that never had a create
		//
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
			if (Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG) {
				//DebugObject = NULL;
				DbgPrint("DbgKmExitThreadApi !!!!!!!!!!!!!!!!!!!!!!!\n");
			}
		}

		KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);

	}


	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId = Thread->Cid;

	if (DebugObject == NULL) {
		Status = STATUS_PORT_NOT_SET;
		DbgPrint("STATUS_PORT_NOT_SET !!!!!!!!!!!!!!!!!!!!!!!\n");
	}
	else {

		//
		// We must not use a debug port thats got no handles left.
		//
		ExAcquireFastMutex(&DebugObject->Mutex);
		DbgPrint("ExAcquireFastMutex !!!!!!!!!!!!!!!!!!!!!!!\n");
		//
		// If the object is delete pending then don't use this object.
		//
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);
			//
			// Set the event to say there is an unread event in the object
			//
			DbgPrint("DEBUG_OBJECT_DELETE_PENDING\n");
			if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
				DbgPrint("KeSetEvent DebugObject->EventsPresent\n");
			}
			Status = STATUS_SUCCESS;
		}
		else {
			DbgPrint("STATUS_DEBUGGER_INACTIVE !!!!!!!!!!!!!!!!!!!!!!!\n");
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);
	}


	if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
		ExReleaseFastMutex(&DbgkFastMutex);

		if (NT_SUCCESS(Status)) {
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			Status = DebugEvent->Status;
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else {
		if (!NT_SUCCESS(Status)) {
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}

	return Status;
}

NTSTATUS
__fastcall
DbgkpSendApiMessage_2(IN OUT PDBGKM_MSG ApiMsg,
	IN BOOLEAN SuspendProcess)
{
	NTSTATUS Status;
	BOOLEAN Suspended = FALSE;
	PAGED_CODE();

	PVOID  addr = 0; PVOID  caller = 0;
	RtlGetCallersAddress(&addr, &caller);
	DbgPrint("DbgkpSendApiMessage_2:callerAddr:%p caller:%s \n", addr, caller);
	/* Suspend process if required */
	if (SuspendProcess)
	{
		Suspended = proxyDbgkpSuspendProcess(NtCurrentProcess());
	}

	/* Set return status */
	ApiMsg->ReturnedStatus = STATUS_PENDING;

	/* Set create process reported state */
	PspSetProcessFlag(&((PEPROCESS_S)PsGetCurrentProcess())->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED);

	DbgPrint("DbgkpSendApiMessage_2:DbgkpQueueMessage_2 \n");
	/* Send the LPC command */
	Status = DbgkpQueueMessage_2(PsGetCurrentProcess(),
		PsGetCurrentThread(),
		ApiMsg,
		((SuspendProcess & 0x2) << 0x5),
		NULL);

	/* Flush the instruction cache */
	ZwFlushInstructionCache(NtCurrentProcess(), NULL, 0);

	DbgPrint("DbgkpSendApiMessage_2:DbgkpResumeProcess(PsGetCurrentProcess(), 0);\n");
	/* Resume the process if it was suspended */
	if (Suspended) DbgkpResumeProcess(PsGetCurrentProcess(), 0);
	return Status;
}

NTSTATUS
NTAPI
DbgkpSendApiMessageLpc(IN OUT PDBGKM_MSG Message,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess)
{
	NTSTATUS Status;
	UCHAR Buffer[PORT_MAXIMUM_MESSAGE_LENGTH];
	BOOLEAN Suspended = FALSE;
	PAGED_CODE();

	if (SuspendProcess) Suspended = proxyDbgkpSuspendProcess(NtCurrentProcess());


	Message->ReturnedStatus = STATUS_PENDING;


	PspSetProcessFlag(&((PEPROCESS_S)PsGetCurrentProcess())->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED);


	Status = LpcRequestWaitReplyPortEx(Port,
		(PPORT_MESSAGE)Message,
		(PPORT_MESSAGE)&Buffer[0]);


	ZwFlushInstructionCache(NtCurrentProcess(), NULL, 0);


	if (NT_SUCCESS(Status)) RtlCopyMemory(Message, Buffer, sizeof(DBGKM_MSG));

	DbgPrint("DbgkpSendApiMessageLpc:DbgkpResumeProcess \n");
	if (Suspended) DbgkpResumeProcess(NtCurrentProcess(), 0);
	return Status;
}

BOOLEAN
__fastcall
proxyDbgkForwardException(IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugPort,
	IN BOOLEAN SecondChance)
{
	DbgPrint("==================proxyDbgkForwardException start================== \n");
	DBGKM_MSG ApiMessage;
	PDBGKM_EXCEPTION DbgKmException = &ApiMessage.Exception;
	NTSTATUS Status = TRUE;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PVOID Port = NULL;
	DbgProcess dbgmsg = { 0 };
	BOOLEAN UseLpc = FALSE;
	PAGED_CODE();

	/*
		dbgmsg.DebugProcess = Process;
		if (Debug_FindMyNeedData(&dbgmsg) == NULL)
		{
			DbgPrint("proxyDbgkForwardException");
			ori_pslp3(ExceptionRecord, DebugPort, SecondChance);
		}
	*/

	/* Setup the API Message */
	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_EXCEPTION));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmExceptionApi;

	/* Check if this is to be sent on the debug port */
	if (DebugPort)
	{
		/* Use the debug port, unless the thread is being hidden */
	//	Port = Process->Pcb.newdbgport;
		Port = Port_GetPort(Process);
		// Process->Pcb.newdbgport;
		DbgPrint("proxyDbgkForwardException:pid:%d Port_GetPort:%p \n", PsGetCurrentProcessId(), DebugPort);
	}
	else
	{
		/* Otherwise, use the exception port */
		Port = Process->ExceptionPortData;
		ApiMessage.h.u2.ZeroInit = 0;
		ApiMessage.h.u2.s2.Type = LPC_EXCEPTION;
		UseLpc = TRUE;
		DbgPrint("proxyDbgkForwardException:DebugPort is null \n");
	}
	DbgPrint("异常\n");
	/* Break out if there's no port */
	if (!Port) return FALSE;
	MarkDbgProcess();
	/* Fill out the exception information */
	DbgKmException->ExceptionRecord = *ExceptionRecord;
	DbgKmException->FirstChance = !SecondChance;

	/* Check if we should use LPC */
	if (UseLpc)
	{
		DbgPrint("proxyDbgkForwardException:DbgkpSendApiMessageLpc \n");
		/* Send the message on the LPC Port */
		Status = DbgkpSendApiMessageLpc(&ApiMessage, Port, DebugPort);
	}
	else
	{
		DbgPrint("proxyDbgkForwardException:DbgkpSendApiMessage_2 \n");
		/* Use native debug object */
		Status = DbgkpSendApiMessage_2(&ApiMessage, DebugPort);
	}

	/* Check if we failed, and for a debug port, also check the return status */
	if (!(NT_SUCCESS(Status)) ||
		((DebugPort) &&
			(!(NT_SUCCESS(ApiMessage.ReturnedStatus)) ||
				(ApiMessage.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED))))
	{
		/* Fail */
		DbgPrint("==================proxyDbgkForwardException end with Fail================== \n");
		return FALSE;
	}

	/* Otherwise, we're ok */
	DbgPrint("==================proxyDbgkForwardException end with OK================== \n");
	return TRUE;
}

//NTSTATUS
//NTAPI
//DbgkpPostFakeThreadMessages_2(IN PEPROCESS_S Process,
//IN PDEBUG_OBJECT DebugObject,
//IN PETHREAD StartThread,
//OUT PETHREAD *FirstThread,
//OUT PETHREAD *LastThread)
//{
//	PETHREAD_S pFirstThread = NULL, ThisThread, OldThread = NULL, pLastThread;
//	NTSTATUS Status = STATUS_UNSUCCESSFUL;
//	BOOLEAN IsFirstThread;
//	ULONG Flags;
//	DBGKM_MSG ApiMessage;
//	PDBGKM_CREATE_THREAD CreateThread = &ApiMessage.CreateThread;
//	PDBGKM_CREATE_PROCESS CreateProcess = &ApiMessage.CreateProcess;
//	BOOLEAN First;
//	PIMAGE_NT_HEADERS NtHeader;
//	PAGED_CODE();
//
//
//
//	if (StartThread)
//	{
//
//		IsFirstThread = FALSE;
//		pFirstThread = StartThread;
//		ThisThread = StartThread;
//
//
//		ObReferenceObject(StartThread);
//	}
//	else
//	{
//
//		ThisThread = PsGetNextProcessThread(Process, NULL);
//		IsFirstThread = TRUE;
//	}
//
//
//	do
//	{
//
//		if (OldThread) ObDereferenceObject(OldThread);
//
//
//		pLastThread = ThisThread;
//		ObReferenceObject(ThisThread);
//		if (ExAcquireRundownProtection(&ThisThread->RundownProtect))
//		{
//
//			Flags = DEBUG_EVENT_RELEASE | DEBUG_EVENT_NOWAIT;
//
//
//			if (!ThisThread->SystemThread)
//			{
//
//				if (NT_SUCCESS(PsSuspendThread(ThisThread, NULL)))
//				{
//
//					Flags |= DEBUG_EVENT_SUSPEND;
//				}
//			}
//		}
//		else
//		{
//
//			Flags = DEBUG_EVENT_PROTECT_FAILED | DEBUG_EVENT_NOWAIT;
//		}
//
//
//		RtlZeroMemory(&ApiMessage, sizeof(ApiMessage));
//
//
//		if ((IsFirstThread) &&
//			!(Flags & DEBUG_EVENT_PROTECT_FAILED) &&
//			!(ThisThread->SystemThread))
//		{
//
//			First = TRUE;
//		}
//		else
//		{
//
//			First = FALSE;
//		}
//
//
//		if (First)
//		{
//
//			ApiMessage.ApiNumber = DbgKmCreateProcessApi;
//
//
//			if (Process->SectionObject)
//			{
//
//				CreateProcess->FileHandle =
//					DbgkpSectionToFileHandle(Process->SectionObject);
//			}
//			else
//			{
//
//				CreateProcess->FileHandle = NULL;
//			}
//
//
//			CreateProcess->BaseOfImage = Process->SectionBaseAddress;
//
//
//			NtHeader = RtlImageNtHeader(Process->SectionBaseAddress);
//			if (NtHeader)
//			{
//
//				CreateProcess->DebugInfoFileOffset = NtHeader->FileHeader.
//					PointerToSymbolTable;
//				CreateProcess->DebugInfoSize = NtHeader->FileHeader.
//					NumberOfSymbols;
//			}
//		}
//		else
//		{
//
//			ApiMessage.ApiNumber = DbgKmCreateThreadApi;
//			CreateThread->StartAddress = ThisThread->StartAddress;
//		}
//
//
//
//		Status = DbgkpQueueMessage_2(Process,
//			ThisThread,
//			&ApiMessage,
//			Flags,
//			DebugObject);
//		if (!NT_SUCCESS(Status))
//		{
//
//			if (Flags & DEBUG_EVENT_SUSPEND) PsResumeThread(ThisThread, NULL);
//
//
//			if (Flags & DEBUG_EVENT_RELEASE)
//			{
//
//				ExReleaseRundownProtection(&ThisThread->RundownProtect);
//			}
//
//
//			if ((ApiMessage.ApiNumber == DbgKmCreateProcessApi) &&
//				(CreateProcess->FileHandle))
//			{
//
//				ObCloseHandle(CreateProcess->FileHandle, KernelMode);
//			}
//
//
//			ObDereferenceObject(ThisThread);
//			break;
//		}
//
//
//		if (First)
//		{
//
//			IsFirstThread = FALSE;
//
//
//			ObReferenceObject(ThisThread);
//			pFirstThread = ThisThread;
//		}
//
//
//		ThisThread = PsGetNextProcessThread(Process, ThisThread);
//		OldThread = pLastThread;
//	} while (ThisThread);
//
//
//	if (!NT_SUCCESS(Status))
//	{
//
//		if (pFirstThread) ObDereferenceObject(pFirstThread);
//		if (pLastThread) ObDereferenceObject(pLastThread);
//		return Status;
//	}
//
//
//	if (!pFirstThread) return STATUS_UNSUCCESSFUL;
//
//
//	*FirstThread = pFirstThread;
//	*LastThread = pLastThread;
//	return Status;
//}
//NTSTATUS
//NTAPI
//DbgkpPostFakeModuleMessages(IN PEPROCESS_S Process,
//IN PETHREAD Thread,
//IN PDEBUG_OBJECT DebugObject)
//{
//	PPEB Peb = Process->Peb;
//	PPEB_LDR_DATA LdrData;
//	PLDR_DATA_TABLE_ENTRY LdrEntry;
//	PLIST_ENTRY ListHead, NextEntry;
//	DBGKM_MSG ApiMessage;
//	PDBGKM_LOAD_DLL LoadDll = &ApiMessage.LoadDll;
//	ULONG i;
//	PIMAGE_NT_HEADERS NtHeader;
//	UNICODE_STRING ModuleName;
//	OBJECT_ATTRIBUTES ObjectAttributes;
//	IO_STATUS_BLOCK IoStatusBlock;
//	NTSTATUS Status;
//	PAGED_CODE();
//
//
//
//	if (!Peb) return STATUS_SUCCESS;
//
//
//	LdrData = Peb->Ldr;
//	ListHead = &LdrData->InLoadOrderModuleList;
//	NextEntry = ListHead->Flink;
//
//	i = 0;
//	while ((NextEntry != ListHead) && (i < 500))
//	{
//
//		if (!i)
//		{
//
//			NextEntry = NextEntry->Flink;
//			i++;
//			continue;
//		}
//
//
//		LdrEntry = CONTAINING_RECORD(NextEntry,
//			LDR_DATA_TABLE_ENTRY,
//			InLoadOrderLinks);
//
//
//		RtlZeroMemory(&ApiMessage, sizeof(DBGKM_MSG));
//		ApiMessage.ApiNumber = DbgKmLoadDllApi;
//
//
//		LoadDll->BaseOfDll = LdrEntry->DllBase;
//		LoadDll->NamePointer = NULL;
//
//		NtHeader = RtlImageNtHeader(LoadDll->BaseOfDll);
//		if (NtHeader)
//		{
//
//			LoadDll->DebugInfoFileOffset = NtHeader->FileHeader.
//				PointerToSymbolTable;
//			LoadDll->DebugInfoSize = NtHeader->FileHeader.NumberOfSymbols;
//		}
//
//
//
//		Status = MmGetFileNameForAddress(NtHeader, &ModuleName);
//		if (NT_SUCCESS(Status))
//		{
//
//			InitializeObjectAttributes(&ObjectAttributes,
//				&ModuleName,
//				OBJ_FORCE_ACCESS_CHECK |
//				OBJ_KERNEL_HANDLE |
//				OBJ_CASE_INSENSITIVE,
//				NULL,
//				NULL);
//
//
//			Status = ZwOpenFile(&LoadDll->FileHandle,
//				GENERIC_READ | SYNCHRONIZE,
//				&ObjectAttributes,
//				&IoStatusBlock,
//				FILE_SHARE_READ |
//				FILE_SHARE_WRITE |
//				FILE_SHARE_DELETE,
//				FILE_SYNCHRONOUS_IO_NONALERT);
//			if (!NT_SUCCESS(Status)) LoadDll->FileHandle = NULL;
//
//
//			ExFreePool(ModuleName.Buffer);
//		}
//
//
//
//		if (DebugObject == NULL
//			)
//		{
//
//			DbgkpSendApiMessage_2(&ApiMessage, 0x3);
//		}
//
//		else{
//			Status = DbgkpQueueMessage_2(Process,
//				Thread,
//				&ApiMessage,
//				DEBUG_EVENT_NOWAIT,
//				DebugObject);
//
//		}
//		if (!NT_SUCCESS(Status))
//		{
//
//			if (LoadDll->FileHandle) ObCloseHandle(LoadDll->FileHandle,
//				KernelMode);
//		}
//
//
//		NextEntry = NextEntry->Flink;
//		i++;
//	}
//
//
//	return STATUS_SUCCESS;
//}


/*
PVOID PsQuerySystemDllInfo(
	ULONG index)
{
	PVOID64	DllInfo;

	DllInfo = (PVOID64)PspSystemDlls[index];
	if (DllInfo != NULL &&
		*(PVOID*)((char*)DllInfo + 0x28) != 0)
	{
		return (PVOID)((ULONG64)DllInfo + 0x10);
	}

	return NULL;
}
*/

VOID proxyDbgkSendSystemDllMessages_1(
	PETHREAD_S	Thread,
	PDEBUG_OBJECT	DebugObject,
	PDBGKM_MSG	ApiMsg
)
{
	NTSTATUS	status;

	HANDLE		FileHandle;

	ULONG		index;
	PTEB64		Teb;
	PEPROCESS_S	Process;
	PETHREAD_S	CurrentThread;
	PMODULE_INFO	DllInfo;
	BOOLEAN		bSource;
	KAPC_STATE ApcState;
	PIMAGE_NT_HEADERS NtHeaders;

	IO_STATUS_BLOCK	IoStackBlock;
	OBJECT_ATTRIBUTES	ObjectAttr;

	if (Thread)
	{
		Process = Thread->Tcb.Process;
	}
	else {
		Process = PsGetCurrentProcess();
	}

	CurrentThread = (PETHREAD)PsGetCurrentThread();
	index = 0;
	do
	{
		if (index >= 2)
		{
			break;
		}
		DllInfo = (PMODULE_INFO)PsQuerySystemDllInfo(index);
		if (DllInfo != NULL)
		{
			ApiMsg->LoadDll.DebugInfoFileOffset = 0;
			ApiMsg->LoadDll.DebugInfoSize = 0;
			ApiMsg->LoadDll.FileHandle = NULL;

			Teb = NULL;

			ApiMsg->LoadDll.BaseOfDll = DllInfo->BaseOfDll;

			if (Thread && index != 0)
			{
				bSource = TRUE;
				KeStackAttachProcess((PEPROCESS)Process, &ApcState);
			}
			else {
				bSource = FALSE;
			}

			NtHeaders = RtlImageNtHeader(DllInfo->BaseOfDll);
			if (NtHeaders != NULL)
			{
				ApiMsg->LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				ApiMsg->LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}

			if (Thread == 0)
			{
				if (!IS_SYSTEM_THREAD(CurrentThread) &&
					CurrentThread->Tcb.ApcStateIndex != 1)
				{
					Teb = (PTEB64)CurrentThread->Tcb.Teb;
				}

				if (Teb)
				{
					RtlStringCbCopyW(Teb->StaticUnicodeBuffer, 261 * sizeof(wchar_t), DllInfo->Buffer);
					Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
					ApiMsg->LoadDll.NamePointer = (PVOID)&Teb->NtTib.ArbitraryUserPointer;
				}
			}

			if (bSource == TRUE)
			{
				KeUnstackDetachProcess(&ApcState);
			}

			InitializeObjectAttributes(
				&ObjectAttr,
				&DllInfo->FileName,
				OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);

			status = ZwOpenFile(
				&FileHandle,
				GENERIC_READ | SYNCHRONIZE,
				&ObjectAttr,
				&IoStackBlock,
				FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_SYNCHRONOUS_IO_NONALERT);
			if (!NT_SUCCESS(status))
			{
				FileHandle = NULL;
			}


			ApiMsg->h.u1.Length = sizeof(DBGKM_MSG) << 16 |
				(8 + sizeof(DBGKM_LOAD_DLL));
			ApiMsg->h.u2.ZeroInit = 0;
			ApiMsg->h.u2.s2.Type = LPC_DEBUG_EVENT;
			ApiMsg->ApiNumber = DbgKmLoadDllApi;


			if (Thread == NULL)
			{
				DbgPrint("proxyDbgkSendSystemDllMessages_1:DbgkpSendApiMessage_2\n");
				DbgkpSendApiMessage_2(ApiMsg, 0x3);
				if (FileHandle != NULL)
				{
					ObCloseHandle(FileHandle, KernelMode);
				}
				if (Teb != NULL)
				{
					Teb->NtTib.ArbitraryUserPointer = NULL;

				}
			}
			else {
				status = DbgkpQueueMessage_2(
					Process,
					Thread,
					ApiMsg,
					DEBUG_EVENT_NOWAIT,
					DebugObject);
				if (!NT_SUCCESS(status))
				{
					if (FileHandle != NULL)
					{
						ObCloseHandle(FileHandle, KernelMode);
					}
				}
			}
		}
		index++;
	} while (TRUE);
}

VOID proxyDbgkSendSystemDllMessages(
	PETHREAD_S		Thread,
	PDEBUG_OBJECT	DebugObject,
	PDBGKM_MSG	ApiMsg
)
{
	NTSTATUS	status;
	HANDLE		FileHandle;
	ULONG		index;
	PTEB64		Teb;
	PEPROCESS_S	Process;
	PETHREAD_S	CurrentThread;
	PMODULE_INFO	DllInfo;
	BOOLEAN		bSource;
	KAPC_STATE ApcState;
	PIMAGE_NT_HEADERS NtHeaders;

	IO_STATUS_BLOCK	IoStackBlock;
	OBJECT_ATTRIBUTES	ObjectAttr;

	if (Thread)
	{
		Process = (PEPROCESS_S)Thread->Tcb.Process;
	}
	else {
		Process = (PEPROCESS_S)PsGetCurrentProcess();
	}
	CurrentThread = (PETHREAD_S)PsGetCurrentThread();
	index = 0;
	do
	{
		if (index >= 1)
		{
			break;
		}
		DllInfo = (PMODULE_INFO)PsQuerySystemDllInfo(index);
		if (DllInfo != NULL)
		{
			if (index == 1 && Process->WoW64Process == 0)
			{
				break;
			}

			//ApiMsg->LoadDll;
			Teb = NULL;

			ApiMsg->LoadDll.BaseOfDll = DllInfo->BaseOfDll;
			DbgPrint("ApiMsg->LoadDll.BaseOfDll:%p\n", ApiMsg->LoadDll.BaseOfDll);
			if (Thread && index != 0)
			{
				bSource = TRUE;
				KeStackAttachProcess((PRKPROCESS)Process, &ApcState);
				NtHeaders = RtlImageNtHeader(DllInfo->BaseOfDll);
				DbgPrint("NtHeaders:%p\n", NtHeaders);
				if (NtHeaders != NULL)
				{
					ApiMsg->LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg->LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}
			else
			{
				bSource = FALSE;
			}

			if (Thread == 0)
			{

				if (CurrentThread->Tcb.SystemThread != TRUE &&
					CurrentThread->Tcb.ApcStateIndex != 1)
				{
					Teb = (PTEB64)CurrentThread->Tcb.Teb;
				}

				if (Teb)
				{
					RtlStringCbCopyW(Teb->StaticUnicodeBuffer, 261 * sizeof(wchar_t), DllInfo->Buffer);
					Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
					ApiMsg->LoadDll.NamePointer = (PVOID)&Teb->NtTib.ArbitraryUserPointer;
				}
			}

			if (bSource == TRUE)
			{
				KeUnstackDetachProcess(&ApcState);
			}

			InitializeObjectAttributes(
				&ObjectAttr,
				&DllInfo->FileName,
				OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);

			status = ZwOpenFile(
				&FileHandle,
				GENERIC_READ | SYNCHRONIZE,
				&ObjectAttr,
				&IoStackBlock,
				FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_SYNCHRONOUS_IO_NONALERT);
			if (!NT_SUCCESS(status))
			{
				FileHandle = NULL;
			}
			ApiMsg->h.u1.Length = 0x500028;
			ApiMsg->h.u2.ZeroInit = 8;
			ApiMsg->ApiNumber = DbgKmLoadDllApi;
			if (Thread == NULL)
			{
				DbgPrint("proxyDbgkSendSystemDllMessages:DbgkpSendApiMessage_2\n");
				DbgkpSendApiMessage_2(ApiMsg, 0x3);
				if (FileHandle != NULL)
				{
					ObCloseHandle(FileHandle, KernelMode);
				}
				if (Teb != NULL)
				{
					Teb->NtTib.ArbitraryUserPointer = NULL;

				}
			}
			else {
				status = DbgkpQueueMessage_2(
					Process,
					Thread,
					ApiMsg,
					0x2,
					DebugObject);
				if (!NT_SUCCESS(status))
				{
					if (FileHandle != NULL)
					{
						ObCloseHandle(FileHandle, KernelMode);
					}
				}
			}
		}
		index++;
	} while (TRUE);
}

typedef BOOLEAN(*__stdcall pfExAcquireRundownProtection_0)(PEX_RUNDOWN_REF RunRef);
pfExAcquireRundownProtection_0 ExAcquireRundownProtection_0;

NTSTATUS DbgkpPostFakeThreadMessages_2(
	PEPROCESS_S	Process,
	PDEBUG_OBJECT	DebugObject,
	PETHREAD	StartThread,
	PETHREAD* pFirstThread,
	PETHREAD* pLastThread
)
{
	NTSTATUS status;
	PETHREAD_S Thread, FirstThread, LastThread, CurrentThread;
	DBGKM_MSG ApiMsg;	//上面分析的一个未知的结构体，应该就是DBGKM_APIMSG类型的结构
	BOOLEAN First = TRUE;
	BOOLEAN IsFirstThread;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG Flags;
	KAPC_STATE ApcState;

	status = STATUS_UNSUCCESSFUL;

	LastThread = FirstThread = NULL;

	CurrentThread = KeGetCurrentThread();

	if (StartThread == 0)
	{
		StartThread = PsGetNextProcessThread(Process, NULL);
		First = TRUE;
	}
	else {
		First = FALSE;
		FirstThread = StartThread;
		ObfReferenceObject(StartThread);
	}

	for (Thread = StartThread;
		Thread != NULL;
		Thread = PsGetNextProcessThread(Process, Thread))
	{
		Flags = DEBUG_EVENT_NOWAIT;

		if (LastThread != 0)
		{
			ObfDereferenceObject(LastThread);
		}

		LastThread = Thread;
		ObfReferenceObject(Thread);

		if (ExAcquireRundownProtection(&Thread->RundownProtect))
		{
			if (Thread->ThreadInserted == 0)
			{
				continue;
			}

			Flags |= DEBUG_EVENT_RELEASE;
			if (!IS_SYSTEM_THREAD(Thread))
			{
				status = PsSuspendThread((PETHREAD)Thread, 0);
				if (NT_SUCCESS(status))
				{
					Flags |= DEBUG_EVENT_SUSPEND;
				}
			}
		}
		else {
			Flags |= DEBUG_EVENT_PROTECT_FAILED;
		}

		//每次构造一个DBGKM_APIMSG结构
		memset(&ApiMsg, 0, sizeof(DBGKM_MSG));
		if (First && ((Flags & DEBUG_EVENT_PROTECT_FAILED) == 0))
		{
			//进程的第一个线程才会到这里
			IsFirstThread = TRUE;
			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
			if (Process->SectionObject)
			{
				//DbgkpSectionToFileHandle函数是返回一个模块的句柄
				ApiMsg.CreateProcess.FileHandle = DbgkpSectionToFileHandle(Process->SectionObject);
			}
			else {
				ApiMsg.CreateProcess.FileHandle = NULL;
			}
			ApiMsg.CreateProcess.BaseOfImage = Process->SectionBaseAddress;
			ApiMsg.CreateProcess.InitialThread.StartAddress = Thread->StartAddress;

			KeStackAttachProcess(Process, &ApcState);

			__try {				
				NtHeaders = RtlImageNtHeader(Process->Peb->ImageBaseAddress);
				if (NtHeaders)
				{
					ApiMsg.CreateProcess.BaseOfImage = NtHeaders->OptionalHeader.ImageBase;
					ApiMsg.CreateProcess.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					ApiMsg.CreateProcess.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}except(EXCEPTION_EXECUTE_HANDLER) {
				ApiMsg.CreateProcess.InitialThread.StartAddress = NULL;
				ApiMsg.CreateProcess.DebugInfoFileOffset = 0;
				ApiMsg.CreateProcess.DebugInfoSize = 0;
			}
			KeUnstackDetachProcess(&ApcState);
		}
		else {
			IsFirstThread = FALSE;
			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
			ApiMsg.CreateThread.StartAddress = Thread->StartAddress;
		}

		status = DbgkpQueueMessage_2(
			Process,
			Thread,
			&ApiMsg,
			Flags,
			DebugObject);

		if (!NT_SUCCESS(status))
		{
			if (Flags & DEBUG_EVENT_SUSPEND)
			{
				PsResumeThread(Thread, NULL);
			}

			if (Flags & DEBUG_EVENT_RELEASE)
			{
				ExReleaseRundownProtection(&Thread->RundownProtect);
			}

			if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.CreateProcess.FileHandle != NULL)
			{
				ObCloseHandle(ApiMsg.CreateProcess.FileHandle, KernelMode);
			}

			ObfDereferenceObject(Thread);
			break;

		}
		else if (IsFirstThread) {
			First = FALSE;
			ObfReferenceObject(Thread);
			FirstThread = Thread;
			proxyDbgkSendSystemDllMessages(Thread, DebugObject, &ApiMsg);
		}
	}

	if (!NT_SUCCESS(status)) {
		if (FirstThread)
		{
			ObfDereferenceObject(FirstThread);
		}
		if (LastThread != NULL)
		{
			ObfDereferenceObject(LastThread);
		}
	}
	else {
		if (FirstThread) {
			*pFirstThread = FirstThread;
			*pLastThread = LastThread;
		}
		else {

			if (LastThread != NULL)
			{
				ObfDereferenceObject(LastThread);
			}
			status = STATUS_UNSUCCESSFUL;
		}
	}
	return status;
}

typedef  UINT64  _QWORD;
typedef  UINT32  _DWORD;

__int64 DbgkpSetProcessDebugObject_asm(ULONG_PTR BugCheckParameter1, PRKEVENT Event, int a3, ...)
{
	struct _KTHREAD* v3; // r13
	int v4; // edi
	void* v7; // rbx
	__int64 v8; // r14
	struct _KEVENT* v9; // r14
	__int64 v10; // rbx
	int v11; // eax
	__int64 v12; // r13
	__int64 v13; // rcx
	_QWORD* v14; // rax
	struct _KEVENT** v15 = 0; // rax
	_QWORD* v16; // rax
	int v17; // eax
	PVOID v18; // rcx
	__int64 v19; // rax
	PVOID Object; // [rsp+30h] [rbp-30h] BYREF
	struct _KTHREAD* v22; // [rsp+38h] [rbp-28h]
	PKGUARDED_MUTEX Mutex; // [rsp+40h] [rbp-20h]
	PVOID P; // [rsp+48h] [rbp-18h] BYREF
	PVOID* v25; // [rsp+50h] [rbp-10h]
	char v26; // [rsp+A8h] [rbp+48h]
	char v27; // [rsp+B0h] [rbp+50h]
	void* v28; // [rsp+B8h] [rbp+58h] BYREF
	va_list va; // [rsp+B8h] [rbp+58h]
	va_list va1; // [rsp+C0h] [rbp+60h] BYREF

	va_start(va1, a3);
	va_start(va, a3);
	v28 = va_arg(va1, void*);
	v3 = KeGetCurrentThread();
	Object = 0i64;
	v25 = &P;
	P = &P;
	v4 = a3;
	v22 = v3;
	v26 = 1;
	v27 = 0;
	if (a3 >= 0)
	{
		v7 = v28;
		v4 = 0;
	}
	else
	{
		v7 = 0i64;
		v28 = 0i64;
	}
	if (v4 >= 0)
	{
		ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
		while (1)
		{
			if (*(_QWORD*)(BugCheckParameter1 + 1400))
			{
				v4 = -1073741752;
				v27 = 1;
				goto LABEL_11;
			}
			*(_QWORD*)(BugCheckParameter1 + 1400) = Event;
			ObfReferenceObjectWithTag(v7, 0x4F676244u);
			v27 = 1;
			v8 = PsGetNextProcessThread(BugCheckParameter1, v7);
			if (!v8)
				goto LABEL_11;
			*(_QWORD*)(BugCheckParameter1 + 1400) = 0i64;
			KeReleaseGuardedMutex(&DbgkpProcessDebugPortMutex);
			v27 = 0;
			ObfDereferenceObjectWithTag(v7, 0x4F676244u);
			DbgPrint("asm DbgkpPostFakeThreadMessages\n");
			v4 = DbgkpPostFakeThreadMessages(BugCheckParameter1, Event, v8, &Object, (void**)va);
			if (v4 < 0)
				break;
			ObfDereferenceObjectWithTag(Object, 0x4F676244u);
			ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
			v7 = v28;
		}
		v7 = 0i64;
		v28 = 0i64;
	}
LABEL_11:
	Mutex = (PKGUARDED_MUTEX)&Event[1];
	ExAcquireFastMutex((PFAST_MUTEX)&Event[1]);
	if (v4 >= 0)
	{
		if ((Event[4].Header.LockNV & 1) != 0)
		{
			*(_QWORD*)(BugCheckParameter1 + 1400) = 0i64;
			v4 = -1073740972;
		}
		else
		{
			_InterlockedOr((volatile signed __int32*)(BugCheckParameter1 + 1124), 3u);
			ObfReferenceObject(Event);
			v7 = v28;
		}
	}
	v9 = (struct _KEVENT*)Event[3].Header.WaitListHead.Flink;
	if (v9 == (struct _KEVENT*)&Event[3].Header.WaitListHead)
		goto LABEL_37;
	do
	{
		v10 = (__int64)v9;
		v9 = *(struct _KEVENT**)&v9->Header.Lock;
		v11 = *(_DWORD*)(v10 + 76);
		if ((v11 & 4) == 0 || *(struct _KTHREAD**)(v10 + 80) != v3)
			continue;
		v12 = *(_QWORD*)(v10 + 64);
		if (v4 < 0)
		{
			if (v9->Header.WaitListHead.Flink != (LIST_ENTRY*)v10
				|| (v15 = *(struct _KEVENT***)(v10 + 8), *v15 != (struct _KEVENT*)v10))
			{
			LABEL_45:
				__fastfail(3u);
			}
			*v15 = v9;
			v9->Header.WaitListHead.Flink = (LIST_ENTRY*)v15;
			goto LABEL_30;
		}
		if ((v11 & 0x10) != 0)
		{
			_InterlockedOr((volatile signed __int32*)(v12 + 1296), 0x80u);
			v13 = *(_QWORD*)v10;
			if (*(_QWORD*)(*(_QWORD*)v10 + 8i64) != v10)
				goto LABEL_45;
			v14 = *(_QWORD**)(v10 + 8);
			if (*v14 != v10)
				goto LABEL_45;
			*v14 = v13;
			*(_QWORD*)(v13 + 8) = v14;
		LABEL_30:
			v16 = v25;
			if (*v25 != &P)
				goto LABEL_45;
			*(_QWORD*)v10 = &P;
			*(_QWORD*)(v10 + 8) = v16;
			*v16 = v10;
			v25 = (PVOID*)v10;
			goto LABEL_32;
		}
		if (v26)
		{
			*(_DWORD*)(v10 + 76) = v11 & 0xFFFFFFFB;
			KeSetEvent(Event, 0, 0);
			v26 = 0;
		}
		*(_QWORD*)(v10 + 80) = 0i64;
		_InterlockedOr((volatile signed __int32*)(v12 + 1296), 0x40u);
	LABEL_32:
		v17 = *(_DWORD*)(v10 + 76);
		if ((v17 & 8) != 0)
		{
			*(_DWORD*)(v10 + 76) = v17 & 0xFFFFFFF7;
			ExReleaseRundownProtection((PEX_RUNDOWN_REF)(v12 + 1272));
		}
		v3 = v22;
	} while (v9 != (struct _KEVENT*)&Event[3].Header.WaitListHead);
	v7 = v28;
LABEL_37:
	KeReleaseGuardedMutex(Mutex);
	if (v27)
		KeReleaseGuardedMutex(&DbgkpProcessDebugPortMutex);
	if (v7)
		ObfDereferenceObjectWithTag(v7, 0x4F676244u);
	while (1)
	{
		v18 = P;
		if (P == &P)
			break;
		if (*((PVOID**)P + 1) != &P)
			goto LABEL_45;
		v19 = *(_QWORD*)P;
		if (*(PVOID*)(*(_QWORD*)P + 8i64) != P)
			goto LABEL_45;
		P = *(PVOID*)P;
		*(_QWORD*)(v19 + 8) = &P;
		DbgkpWakeTarget(v18);
	}
	if (v4 >= 0)
		originalDbgkpMarkProcessPeb(BugCheckParameter1);
	return (unsigned int)v4;
}



NTSTATUS __fastcall
DbgkpSetProcessDebugObject_2(//反汇编OK
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN NTSTATUS MsgStatus,
	IN PETHREAD LastThread
)
{
	DbgPrint("================================DbgkpSetProcessDebugObject_2============================================\n");
	PEPROCESS ps;
	NTSTATUS status1 = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &ps);
	if (NT_SUCCESS(status1))
	{
		UCHAR* Name = PsGetProcessImageFileName(ps);
		DbgPrint("DbgkpSetProcessDebugObject_2:currentProcess:%s\n", Name);
		ObDereferenceObject(ps);
		Name = PsGetProcessImageFileName(Process);
		DbgPrint("DbgkpSetProcessDebugObject_2:targetProcess:%s\n", Name);
	}
	DbgPrint("DbgkpSetProcessDebugObject_2:DebugObject:%p \n", DebugObject);

	NTSTATUS Status;
	PETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PETHREAD_S Thread;
	BOOLEAN GlobalHeld;
	PETHREAD FirstThread;

	PAGED_CODE();

	ThisThread = PsGetCurrentThread();

	InitializeListHead(&TempList);

	First = TRUE;
	GlobalHeld = FALSE;

	if (!NT_SUCCESS(MsgStatus))
	{
		DbgPrint("DbgkpSetProcessDebugObject_2:MsgStatus:%p \n", MsgStatus);
		LastThread = NULL;
		Status = MsgStatus;
	}
	else
	{
		Status = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(Status))
	{
		while (1)
		{
			GlobalHeld = TRUE;
			ExAcquireFastMutex(&DbgkFastMutex);
			/*if (Process->Pcb.newdbgport!= NULL)
			 {
				 Status = STATUS_PORT_ALREADY_SET;
				 break;
			 }*/
			if (Port_IsPort(Process))
			{
				DbgPrint("DbgkpSetProcessDebugObject_2:STATUS_PORT_ALREADY_SET \n");
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}
			if (Port_SetPort(Process, DebugObject))
			{
				DbgPrint("DbgkpSetProcessDebugObject_2:Port_SetPort ok: Process:%p DebugObject:%p \n", Process, DebugObject);
				//Process->DebugPort = DebugObject;
				//g_pdebugObj = DebugObject;
			}
			//	Port_FindProcessList:FFFFE00C904D3080


			//DbgkpSetProcessDebugObject_2:Port_GetPort:Process:FFFFE00C904D3080 DebugObject : FFFFE00C8C834B20

			if (Port_GetPort(Process))
			{
				DbgPrint("DbgkpSetProcessDebugObject_2:Port_GetPort:Process:%p DebugObject:%p \n", Process, Port_GetPort(Process));
			}

			//Process->Pcb.newdbgport = DebugObject;
			//DbgPrint("DbgkpSetProcessDebugObject_2:Process->DebugPort:%p\n", Process->DebugPort);
			DbgPrint("DbgkpSetProcessDebugObject_2:LastThread:%p \n", LastThread);
			ObReferenceObject(LastThread);
			Thread = PsGetNextProcessThread(Process, LastThread);
			if (Thread != NULL)
			{
				//Process->DebugPort = NULL; /*------ DebugPort -----------*/
				//Process->Pcb.newdbgport = NULL;
				//DbgPrint("DbgkpSetProcessDebugObject_2:Port_RemoveDbgItem Process:%p \n", Process); 
				//Port_RemoveDbgItem(Process, NULL);
				KeReleaseGuardedMutex(&DbgkFastMutex);
				GlobalHeld = FALSE;
				ObDereferenceObject(LastThread);
				Status = DbgkpPostFakeThreadMessages_2(
					Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status))
				{
					LastThread = NULL;
					break;
				}
				ObDereferenceObject(FirstThread);
				//ExAcquireFastMutex(&DbgkFastMutex);
			}
			else
			{
				DbgPrint("DbgkpSetProcessDebugObject_2:break \n");
				break;
			}
		}
	}

	ExAcquireFastMutex(&DebugObject->Mutex);
	if (NT_SUCCESS(Status))
	{
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
			PspSetProcessFlag(&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObReferenceObject(DebugObject);//Process->NoDebugInherit 为1就表示有调试了。
		}
		else
		{
			//	Process->Pcb.newdbgport = NULL; /*------ DebugPort -----------*/
			DbgPrint("DbgkpSetProcessDebugObject_2:Port_RemoveDbgItem STATUS_DEBUGGER_INACTIVE \n");
			Port_RemoveDbgItem(Process, NULL);
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		)
	{
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;

		if ((DebugEvent->Flags & DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {
			Thread = DebugEvent->Thread;

			if (NT_SUCCESS(Status) && !IS_SYSTEM_THREAD(Thread))
			{
				if ((DebugEvent->Flags & DEBUG_EVENT_PROTECT_FAILED) != 0) {
					PspSetProcessFlag(&Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {

					if (First) {
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}

					DebugEvent->BackoutThread = NULL;
					PspSetProcessFlag(&Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);

				}
			}
			else
			{
				DbgPrint("DbgkpSetProcessDebugObject_2:RemoveEntryList:%p \n", &DebugEvent->EventList);
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				ExReleaseRundownProtection(&Thread->RundownProtect);
			}

		}
	}

	KeReleaseGuardedMutex(&DebugObject->Mutex);

	if (GlobalHeld) {
		KeReleaseGuardedMutex(&DbgkFastMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject(LastThread);
	}

	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget(DebugEvent);
	}

	if (NT_SUCCESS(Status)) {
		//originalDbgkpMarkProcessPeb(Process);
		MarkDbgProcess();
	}

	return STATUS_SUCCESS;
}

NTSTATUS DbgkpPostFakeProcessCreateMessages_2(
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT DebugObject,
	IN PETHREAD* pLastThread
)
{
	NTSTATUS	status;
	KAPC_STATE	ApcState;
	PETHREAD	StartThread, Thread;
	PETHREAD	LastThread;

	//收集所有线程创建的消息
	StartThread = 0;
	status = DbgkpPostFakeThreadMessages_2(
		Process,
		DebugObject,
		NULL,
		&Thread,
		&LastThread);
	if (NT_SUCCESS(status))
	{
		DbgPrint("DbgkpPostFakeProcessCreateMessages_2:DbgkpPostFakeThreadMessages_2 ok DbgkpPostModuleMessages \n");
		KeStackAttachProcess(Process, &ApcState);
		//收集模块创建的消息
		DbgkpPostModuleMessages(Process, Thread, DebugObject);
		KeUnstackDetachProcess(&ApcState);
		ObfDereferenceObject(Thread);
	}
	else {
		LastThread = 0;
		DbgPrint("DbgkpPostFakeProcessCreateMessages_2:DbgkpPostFakeThreadMessages_2 failed \n");
	}
	*pLastThread = LastThread;

	return	status;
}

VOID
NTAPI
DbgkpConvertKernelToUserStateChange(IN PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	IN PDEBUG_EVENT DebugEvent)
{
	WaitStateChange->AppClientId = DebugEvent->ClientId;

	switch (DebugEvent->ApiMsg.ApiNumber)
	{
	case DbgKmCreateProcessApi:
	{
		DbgPrint("DbgKmCreateProcessApi\n");
		//WaitStateChange->StateInfo.CreateThread.NewThread.StartAddress =
		//	DebugEvent->ApiMsg.u.CreateThread.StartAddress;
		//WaitStateChange->StateInfo.CreateThread.NewThread.SubSystemKey =
		//	DebugEvent->ApiMsg.u.CreateThread.SubSystemKey;

		WaitStateChange->NewState = DbgCreateProcessStateChange;
		WaitStateChange->StateInfo.CreateProcessInfo.NewProcess =
			DebugEvent->ApiMsg.u.CreateProcessInfo;

		DbgPrint("DebugEvent->ApiMsg.u.CreateProcessInfo.BaseOfImage:%p \n", DebugEvent->ApiMsg.u.CreateProcessInfo.BaseOfImage);
		DbgPrint("DebugEvent->ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress:%p \n", DebugEvent->ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress);


		WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess = DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle;

		DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
		break;
	}

	case DbgKmCreateThreadApi:
	{
		DbgPrint("DbgKmCreateThreadApi\n");
		WaitStateChange->NewState = DbgCreateThreadStateChange;

		WaitStateChange->StateInfo.CreateThread.NewThread.StartAddress =
			DebugEvent->ApiMsg.u.CreateThread.StartAddress;
		WaitStateChange->StateInfo.CreateThread.NewThread.SubSystemKey =
			DebugEvent->ApiMsg.u.CreateThread.SubSystemKey;
		break;
	}

	case DbgKmExceptionApi:
	{
		DbgPrint("DbgKmExceptionApi\n");
		if ((NTSTATUS)DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode ==
			STATUS_BREAKPOINT)
		{
			WaitStateChange->NewState = DbgBreakpointStateChange;
		}
		else if ((NTSTATUS)DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode ==
			STATUS_SINGLE_STEP)
		{
			WaitStateChange->NewState = DbgSingleStepStateChange;
		}
		else
		{
			WaitStateChange->NewState = DbgExceptionStateChange;
		}

		WaitStateChange->StateInfo.Exception.ExceptionRecord =
			DebugEvent->ApiMsg.u.Exception.ExceptionRecord;

		WaitStateChange->StateInfo.Exception.FirstChance =
			DebugEvent->ApiMsg.u.Exception.FirstChance;
		break;
	}

	case DbgKmExitProcessApi:
	{
		DbgPrint("DbgKmExitProcessApi\n");
		WaitStateChange->NewState = DbgExitProcessStateChange;
		WaitStateChange->StateInfo.ExitProcess.ExitStatus =
			DebugEvent->ApiMsg.u.ExitProcess.ExitStatus;
		break;
	}

	case DbgKmExitThreadApi:
	{
		DbgPrint("DbgKmExitThreadApi\n");
		WaitStateChange->NewState = DbgExitThreadStateChange;
		WaitStateChange->StateInfo.ExitThread.ExitStatus =
			DebugEvent->ApiMsg.u.ExitThread.ExitStatus;
		break;
	}

	case DbgKmLoadDllApi:
	{
		DbgPrint("DbgKmLoadDllApi\n");
		WaitStateChange->NewState = DbgLoadDllStateChange;
		WaitStateChange->StateInfo.LoadDll = DebugEvent->ApiMsg.u.LoadDll;
		if (DebugEvent->ApiMsg.u.LoadDll.NamePointer)
		{
			DbgPrint("WaitStateChange->StateInfo.LoadDll.NamePointer:%s \n", WaitStateChange->StateInfo.LoadDll.NamePointer);
		}

		DebugEvent->ApiMsg.u.LoadDll.FileHandle = NULL;
		break;
	}

	case DbgKmUnloadDllApi:
	{
		DbgPrint("DbgKmUnloadDllApi\n");
		WaitStateChange->NewState = DbgUnloadDllStateChange;
		WaitStateChange->StateInfo.UnloadDll.BaseAddress =
			DebugEvent->ApiMsg.u.UnloadDll.BaseAddress;
		break;
	}

	default:

		ASSERT(FALSE);
	}
}

VOID
NTAPI
DbgkpOpenHandles(IN PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	IN PEPROCESS Process,
	IN PETHREAD Thread)
{
	NTSTATUS Status;
	HANDLE Handle;
	PHANDLE DupHandle;
	PAGED_CODE();

	switch (WaitStateChange->NewState)
	{
	case DbgCreateThreadStateChange:
	{
		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{
			WaitStateChange->
				StateInfo.CreateThread.HandleToThread = Handle;
		}
		return;
	}

	case DbgCreateProcessStateChange:
	{
		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{

			WaitStateChange->
				StateInfo.CreateProcessInfo.HandleToThread = Handle;
		}

		Status = ObOpenObjectByPointer(Process,
			0,
			NULL,
			PROCESS_ALL_ACCESS,
			*PsProcessType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{
			WaitStateChange->
				StateInfo.CreateProcessInfo.HandleToProcess = Handle;
		}

		DupHandle = &WaitStateChange->
			StateInfo.CreateProcessInfo.NewProcess.FileHandle;
		break;
	}

	case DbgLoadDllStateChange:
	{
		DupHandle = &WaitStateChange->StateInfo.LoadDll.FileHandle;
		break;
	}

	default:
		return;
	}


	Handle = *DupHandle;
	if (Handle)
	{

		Status = ObDuplicateObject(PsGetCurrentProcess(),
			Handle,
			PsGetCurrentProcess(),
			DupHandle,
			0,
			0,
			DUPLICATE_SAME_ACCESS,
			KernelMode);
		if (!NT_SUCCESS(Status)) *DupHandle = NULL;


		ObCloseHandle(Handle, KernelMode);
	}
}



NTSTATUS
NTAPI
DbgkClearProcessDebugObject(IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT SourceDebugObject OPTIONAL)
{
	PDEBUG_OBJECT DebugObject = NULL;
	PDEBUG_EVENT DebugEvent;
	LIST_ENTRY TempList;
	PLIST_ENTRY NextEntry;
	PAGED_CODE();

	DbgPrint("=====================DbgkClearProcessDebugObject====================\n");

	ExAcquireFastMutex(&DbgkFastMutex);


	//DebugObject = Process->Pcb.newdbgport;

	DebugObject = Port_GetPort(Process);
	if ((DebugObject) &&
		((DebugObject == SourceDebugObject) ||
			(SourceDebugObject == NULL)))
	{

		//	Process->Pcb.newdbgport = NULL;
		Port_RemoveDbgItem(Process, NULL);
		ExReleaseFastMutex(&DbgkFastMutex);
		originalDbgkpMarkProcessPeb(Process);
		DbgPrint("DbgkClearProcessDebugObject:Port_RemoveDbgItem \n");
	}
	else
	{
		ExReleaseFastMutex(&DbgkFastMutex);
		DbgPrint("DbgkClearProcessDebugObject:STATUS_PORT_NOT_SET \n");
		return STATUS_PORT_NOT_SET;
	}

	InitializeListHead(&TempList);


	ExAcquireFastMutex(&DebugObject->Mutex);

	NextEntry = DebugObject->EventList.Flink;
	while (NextEntry != &DebugObject->EventList)
	{

		DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);
		NextEntry = NextEntry->Flink;


		if (DebugEvent->Process == Process)
		{

			RemoveEntryList(&DebugEvent->EventList);
			InsertTailList(&TempList, &DebugEvent->EventList);
		}
	}


	ExReleaseFastMutex(&DebugObject->Mutex);


	ObDereferenceObject(DebugObject);

	while (!IsListEmpty(&TempList))
	{

		NextEntry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);


		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}


	return STATUS_SUCCESS;
}


#define MK_FP( seg,ofs )( (void _seg * )( seg ) +( void near * )( ofs ))





typedef NTSTATUS(*OriginalNtWaitForDebugEvent)(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
	);
OriginalNtWaitForDebugEvent originalNtWaitForDebugEvent;

FORCEINLINE PKTRAP_FRAME PspGetThreadTrapFrame(PETHREAD_S Thread)
{
#define KERNEL_STACK_CONTROL_LENGTH sizeof(KERNEL_STACK_CONTROL)  
#define KTRAP_FRAME_LENGTH sizeof(KTRAP_FRAME)  

	ULONG64 InitialStack;
	PKERNEL_STACK_CONTROL StackControl;
	__try {
		InitialStack = (ULONG64)Thread->Tcb.InitialStack;
		StackControl = (PKERNEL_STACK_CONTROL)InitialStack;
		if (StackControl == NULL)
		{
			DbgPrint("StackControl Thread:%p Is NULL!", Thread);
			return NULL;
		}
		if (MmIsAddressValid(&StackControl->Previous.StackBase) == FALSE)
		{
			return NULL;
		}
		while (StackControl->Previous.StackBase != 0)
		{
			InitialStack = StackControl->Previous.InitialStack;
			StackControl = (PKERNEL_STACK_CONTROL)InitialStack;
		}

	}except(EXCEPTION_EXECUTE_HANDLER) {
		return NULL;

	}



	return (PKTRAP_FRAME)(InitialStack - KTRAP_FRAME_LENGTH);
}
NTSTATUS AddAllThreadContextToList(PEPROCESS_S Process) {
	PETHREAD CurrentThread = KeGetCurrentThread();

	PKTRAP_FRAME pframe = NULL;
	PETHREAD_S Thread = NULL;

	THREAD_dr_List t = { 0 };
	PPROCESS_List PList = NULL;
	if (Process != NULL)
	{
		PList = Dr_AddProcessToList(Process);
	}
	else
	{
		return FALSE;
	}

	Thread = PsGetNextProcessThread(Process, NULL);
	DbgPrint("Process : %p\n", Process);
	while (Thread != NULL) {
		DbgPrint("Thread : %p\n", Thread);

		if (Thread != NULL) {
			if (ExAcquireRundownProtection(&Thread->RundownProtect))
			{
				pframe = PspGetThreadTrapFrame(Thread);

				//Thread->Tcb.TrapFrame;

				DbgPrint("Thread Frame: %p\n", pframe);

				if (MmIsAddressValid(pframe) == TRUE)
				{
					/*t.Dr0 = ((PLARGE_INTEGER)(pframe->Dr0))->LowPart;
					t.Dr1 = HIDWORD(pframe->Dr1);
					t.Dr2 = HIDWORD(pframe->Dr2);
					t.Dr3 = HIDWORD(pframe->Dr3);
					t.Dr6 = HIDWORD(pframe->Dr6);
					t.Dr7 = HIDWORD(pframe->Dr7);*/
					t.Dr0 = ((PLARGE_INTEGER)(&pframe->Dr0))->LowPart;
					t.Dr1 = ((PLARGE_INTEGER)(&pframe->Dr1))->LowPart;
					t.Dr2 = ((PLARGE_INTEGER)(&pframe->Dr2))->LowPart;
					t.Dr3 = ((PLARGE_INTEGER)(&pframe->Dr3))->LowPart;
					t.Dr6 = ((PLARGE_INTEGER)(&pframe->Dr6))->LowPart;
					t.Dr7 = ((PLARGE_INTEGER)(&pframe->Dr7))->LowPart;
					t.eflag = pframe->EFlags;
					//	pframe->EFlags |= 0x100;;

					//Clear Thread Context
					pframe->Dr0 = 0;
					pframe->Dr1 = 0;
					pframe->Dr2 = 0;
					pframe->Dr3 = 0;
					pframe->Dr6 = 0;
					pframe->Dr7 = 0;

					t.Thread = Thread;
					Dr_AddThreadStructToList(PList, &t);
					DbgPrint("thread: %p dr0: %d dr1 :%d dr2 :%d dr3 :%d dr6:%d dr7:%d\n", Thread, t.Dr0, t.Dr1, t.Dr2, t.Dr3, t.Dr6, t.Dr7);
				}
				else {
					/////////FIXME
				}

				ExReleaseRundownProtection(&Thread->RundownProtect);
			}
		}

		Thread = PsGetNextProcessThread(Process, Thread);
	}

	return STATUS_SUCCESS;
}

VOID GetCloseDbgtoolMsg(
	IN HANDLE hParentId,
	IN HANDLE hProcessId,
	IN BOOLEAN bCreate)
{
	p_save_handlentry Padd = NULL;
	if (!bCreate) {

		Padd = querylist(PmainList, hProcessId, NULL);
		if (Padd != NULL) {

			deletelist(Padd);//删除节点
		}

	}

}
VOID RemoveDbgtoolMsg(BOOLEAN  isload) {
	if (isload)
	{
		PsSetCreateProcessNotifyRoutine(GetCloseDbgtoolMsg, FALSE);

	}
	else
	{
		PsSetCreateProcessNotifyRoutine(GetCloseDbgtoolMsg, TRUE);

	}

}
VOID
MsgCreateUnThreadMsg(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
) {

	PEPROCESS_S Process = NULL;
	PETHREAD_S Thread = NULL;
	NTSTATUS st, st2 = NULL;

	if (PsGetCurrentProcess() != PsInitialSystemProcess)
	{
		st = PsLookupProcessByProcessId(ProcessId, &Process);


		if (NT_SUCCESS(st)) { ObDereferenceObject(Process); }
		else {
			return;
		}
		st2 = PsLookupThreadByThreadId(ThreadId, &Thread);
		if (NT_SUCCESS(st2)) { ObDereferenceObject(Thread); }
		else
		{
			return;
		}

		if (Create)
		{
			if (Port_IsPort(Process))
			{



				DBGKM_MSG ApiMessage = { 0 };
				PDBGKM_CREATE_THREAD CreateThreadArgs = &ApiMessage.CreateThread;


				ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
					(8 + sizeof(DBGKM_CREATE_THREAD));
				ApiMessage.h.u2.ZeroInit = 0;
				ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
				ApiMessage.ApiNumber = DbgKmCreateThreadApi;

				CreateThreadArgs->StartAddress = Thread->Win32StartAddress;
				CreateThreadArgs->SubSystemKey = 0;
				DbgPrint("MsgCreateUnThreadMsg:DbgkpSendApiMessage_2\n");
				DbgkpSendApiMessage_2(&ApiMessage, FALSE);
			}



		}
	}





}
VOID SetDbgMsgNotify(BOOLEAN IsLoad) {
	if (IsLoad)
	{
		PsSetCreateThreadNotifyRoutine(MsgCreateUnThreadMsg);

	}
	else {
		PsRemoveCreateThreadNotifyRoutine(MsgCreateUnThreadMsg);

	}


}

PETHREAD
PsGetNextProcessThread_wrk(
	IN PEPROCESS Process,
	IN PETHREAD_S Thread
)
/*++

Routine Description:

	This function is used to enumerate the threads in a process.


Arguments:

	Process - Process to enumerate
	Thread  - Thread to start enumeration from. This must have been obtained from previous call to
			  PsGetNextProcessThread. If NULL enumeration starts at the first non-terminating thread in the process.

Return Value:

	PETHREAD - Pointer to a non-terminated process thread or a NULL if there are non. This thread must be passed
			   either to another call to PsGetNextProcessThread or PsQuitNextProcessThread.

--*/
{
	PLIST_ENTRY ListEntry;
	PETHREAD NewThread, CurrentThread;

	PAGED_CODE();

	CurrentThread = PsGetCurrentThread();

	//PspLockProcessShared(Process, CurrentThread);

	for (ListEntry = (Thread == NULL) ? Process->ThreadListHead.Flink : Thread->ThreadListEntry.Flink;
		;
		ListEntry = ListEntry->Flink) {
		if (ListEntry != &Process->ThreadListHead) {
			NewThread = CONTAINING_RECORD(ListEntry, ETHREAD_S, ThreadListEntry);
			//
			// Don't reference a thread thats in its delete routine
			//
			if (ObReferenceObject(NewThread)) {
				break;
			}
		}
		else {
			NewThread = NULL;
			break;
		}
	}
	//PspUnlockProcessShared(Process, CurrentThread);

	if (Thread != NULL) {
		ObDereferenceObject(Thread);
	}
	return NewThread;
}

typedef USHORT _WORD;

//NTSTATUS __fastcall NtDebugActiveProcess(IN HANDLE ProcessHandle, IN HANDLE DebugHandle)
//{
//	char previousMode; // bp
//	NTSTATUS result; // eax
//	__int64 v5; // rcx
//	struct _KTHREAD_S* currentThread; // rax
//	struct _EX_RUNDOWN_REF* v7; // rdi
//	KPROCESS* v8; // rsi
//	NTSTATUS status; // ebx
//	unsigned __int64 v10; // rax
//	__int16 v11; // cx
//	unsigned __int64 v12; // rax
//	__int16 v13; // cx
//	BOOLEAN v14; // al
//	struct _KEVENT* v15; // rsi
//	PEPROCESS_S process; // [rsp+80h] [rbp+18h] BYREF
//	PDEBUG_OBJECT Object; // [rsp+88h] [rbp+20h] BYREF
//	PETHREAD lastThread;
//
//	process = 0i64;
//	previousMode = ((PKTHREAD_S)KeGetCurrentThread())->PreviousMode;
//	result = ObReferenceObjectByHandleWithTag(ProcessHandle, 0x800u, (POBJECT_TYPE)*PsProcessType, previousMode, 0x4F676244u, &process, 0i64);
//	if (result >= 0)
//	{
//		currentThread = KeGetCurrentThread();
//		v7 = (struct _EX_RUNDOWN_REF*)process;
//		v8 = currentThread->ApcState.Process;
//		if (process == v8 || process == PsInitialSystemProcess)
//		{
//			status = -1073741790;
//		}
//		else
//		{
//			LOBYTE(v5) = previousMode;
//			if ((unsigned __int8)PsTestProtectedProcessIncompatibility(v5, currentThread->ApcState.Process, process))
//			{
//				status = -1073740014;
//			}
//			else if ((v7[124].Count & 1) == 0 || (status = PsRequestDebugSecureProcess(v7), status >= 0))
//			{
//				v10 = v8[1].AffinityPadding[10];
//				if (!v10
//					|| (v11 = *(_WORD*)(v10 + 8), v11 != 332) && v11 != 452
//					|| (v12 = v7[176].Count) != 0 && ((v13 = *(_WORD*)(v12 + 8), v13 == 332) || v13 == 452))
//				{
//					Object = 0i64;
//					status = ObReferenceObjectByHandle(DebugHandle, 2u, DbgkDebugObjectType, previousMode, &Object, 0i64);
//					if (status >= 0)
//					{
//						v14 = ExAcquireRundownProtection_0(v7 + 139);
//						v15 = (struct _KEVENT*)Object;
//						if (v14)
//						{
//							result = DbgkpPostFakeProcessCreateMessages((ULONG_PTR)v7, Object, lastThread);
//							status = DbgkpSetProcessDebugObject((ULONG_PTR)v7, v15, result, 0i64);
//							ExReleaseRundownProtection(v7 + 139);
//						}
//						else
//						{
//							status = -1073741558;
//						}
//						HalPutDmaAdapter((PADAPTER_OBJECT)v15);
//					}
//				}
//				else
//				{
//					status = -1073741637;
//				}
//			}
//		}
//		ObfDereferenceObjectWithTag(v7, 0x4F676244u);
//		result = status;
//	}
//	return result;
//}


ULONG64 fc_DbgkGetAdrress(PUNICODE_STRING64 funcstr) {
	UNICODE_STRING64 usFuncName;
	RtlInitUnicodeString(&usFuncName, funcstr);
	return MmGetSystemRoutineAddress(&usFuncName);

}
