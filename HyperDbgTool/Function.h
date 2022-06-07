#pragma once

typedef struct _SYMBOLS_DATA
{
	PVOID  DbgkExitThread;
	PVOID  DbgkClearProcessDebugObject;
	PVOID  DbgkSendSystemDllMessages;
	PVOID  PspExitThread;
	PVOID  PspTerminateAllThreads;
	PVOID  PspProcessDelete;
	PULONG PspNotifyEnableMask;
	PVOID  DbgkExitProcess;
	PVOID  DbgkpPostFakeThreadMessages;
	PVOID  DbgkpPostFakeProcessCreateMessages;
	PVOID  PsCallImageNotifyRoutines;
	PVOID  ObFastReferenceObjectLocked;
	PVOID  ObFastReferenceObject;
	PVOID  ObFastDereferenceObject;
	PVOID  DbgkpSendApiMessageLpc;
	PVOID  DbgkpSendErrorMessage;
	PVOID  DbgkpQueueMessage;
	PVOID  DbgkpSuspendProcess;
	PVOID  KiDispatchException;
	PVOID  DbgkForwardException;
	PVOID  DbgkMapViewOfSection;
	PVOID  DbgkCreateThread;
	PVOID  DbgkUnMapViewOfSection;
	PVOID  DbgkCopyProcessDebugPort;
	PVOID  DbgkOpenProcessDebugPort;
	PVOID  DbgkpSetProcessDebugObject;
	PVOID  DbgkpMarkProcessPeb;
	PVOID  PsSuspendThread;
	PVOID  PsResumeThread;
	PVOID  KeResumeThread;
	PVOID  PsSynchronizeWithThreadInsertion;
	PVOID  DbgkpPostModuleMessages;
	PVOID  DbgkpFreeDebugEvent;
	PVOID  DbgkpWakeTarget;
	PVOID  ObDuplicateObject;
	PVOID  KiCheckForKernelApcDelivery;
	PVOID  PsQuerySystemDllInfo;
	//PVOID  ExAcquireRundownProtection_0;
	PVOID  PsGetNextProcessThread;
	//PVOID  KeFreezeAllThreads;
	//PVOID  KeThawAllThreads;
	PVOID PsThawProcess;
	PVOID PsFreezeProcess;
	PVOID  ZwFlushInstructionCache;



	//////
	PVOID  PspActiveProcessLock;
	PVOID  ExfAcquirePushLockExclusive;
	PVOID  ExfTryToWakePushLock;
	PVOID  PspRemoveProcessFromJob;
	PVOID  PspDeleteLdt;
	PVOID  PsReturnProcessNonPagedPoolQuota;
	PVOID  AlpcpCleanupProcessViews;
	PVOID  ObDereferenceDeviceMap;
	PVOID  PspDereferenceQuotaBlock;
	PVOID  PsReturnProcessPagedPoolQuota;
	PVOID  ExDestroyHandle;
	PVOID  MmCleanProcessAddressSpace;
	PVOID  MmDeleteProcessAddressSpace;
	PVOID  MmGetFileNameForSection;
	PVOID  PspCidTable;
	PVOID  ObFastReplaceObject;
	PVOID  LpcRequestWaitReplyPortEx;
	PVOID  PsTestProtectedProcessIncompatibility;
	PVOID  PsRequestDebugSecureProcess;

}SYMBOLS_DATA,*PSYMBOLS_DATA;

bool LoadSymbols(const char* symbolPath);