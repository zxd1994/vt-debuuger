#include"Log.h"
#include "CKernelDbg.h"
#include "KernelDbgStruct.h"
#include "dbgk1to2.h"

FAST_MUTEX g_DbgkpProcessDebugPortMutex;
extern "C"  POBJECT_TYPE * g_DbgkDebugObjectType;

POBJECT_TYPE_S g_DbgkDebugObjectType_1 = 0;
PULONG PspNotifyEnableMask;
PVOID* PspSystemDlls;
SYMBOLS_DATA g_SymbolsData;

#define PROCESS_HOOKPORT_OFFSET 0x170
#define PROCESS_PORT_OFFSET 0x1F0
//函数指针
typedef VOID(*PSCALLIMAGENOTIFYROUTINES)(
	IN PUNICODE_STRING ImageName,
	IN HANDLE ProcessId,
	OUT PIMAGE_INFO_EX ImageInfoEx,
	IN PVOID FileObject); PSCALLIMAGENOTIFYROUTINES PsCallImageNotifyRoutines = 0;

typedef PVOID(*OBFASTREFERENCEOBJECTLOCKED)(
	IN PEX_FAST_REF FastRef); OBFASTREFERENCEOBJECTLOCKED ObFastReferenceObjectLocked = 0;
typedef PVOID(*OBFASTREFERENCEOBJECT)(
	IN PEX_FAST_REF FastRef); OBFASTREFERENCEOBJECT ObFastReferenceObject = 0;

typedef VOID(*OBFASTDEREFERENCEOBJECT)(
	IN PEX_FAST_REF FastRef,
	IN PVOID Object); OBFASTDEREFERENCEOBJECT ObFastDereferenceObject = 0;
typedef NTSTATUS(*DBGKPSENDAPIMESSAGELPC)(
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN PVOID Port,
	IN BOOLEAN SuspendProcess); DBGKPSENDAPIMESSAGELPC  DbgkpSendApiMessageLpc = 0;
typedef NTSTATUS(*DBGKPSENDERRORMESSAGE)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN ULONG Falge,
	IN PDBGKM_APIMSG	DbgApiMsg); DBGKPSENDERRORMESSAGE DbgkpSendErrorMessage = 0;


typedef NTSTATUS(*KERESUMETHREAD)(
	__inout PETHREAD Thread); KERESUMETHREAD KeResumeThread = 0;


//typedef	NTSTATUS(*DBGKPPOSTMODULEMESSAGES)(
//	IN PEPROCESS Process,
//	IN PETHREAD Thread,
//	IN PVOID DebugObject); DBGKPPOSTMODULEMESSAGES DbgkpPostModuleMessages = 0;


typedef NTSTATUS(*OBDUPLICATEOBJECT)(
	IN PEPROCESS SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode);
//OBDUPLICATEOBJECT ObDuplicateObject = 0;

//typedef NTSTATUS(*PSSUSPENDTHREAD)(
//	IN PETHREAD Thread,
//	OUT PULONG PreviousSuspendCount OPTIONAL); PSSUSPENDTHREAD PsSuspendThread = 0;


typedef VOID(*KEFREEZEALLTHREADS)(
	VOID
	); KEFREEZEALLTHREADS KeFreezeAllThreads = 0;
typedef VOID(*KETHAWALLTHREADS)(
	VOID
	); KETHAWALLTHREADS KeThawAllThreads = 0;
typedef void (*KICHECKFORKERNELAPCDELIVERY)(); KICHECKFORKERNELAPCDELIVERY KiCheckForKernelApcDelivery = 0;
typedef NTSTATUS(*ZWFLUSHINSTRUCTIONCACHE)(
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in SIZE_T Length
	); ZWFLUSHINSTRUCTIONCACHE ZwFlushInstructionCache = 0;

//函数实现
BOOLEAN HookDbgkDebugObjectType()
{
	//如果是不以原始DbgkDebugObjectType指针来操作，以启动方式时则需要替换PspInsertProcess中的DbgkDebugObjectType
	UNICODE_STRING ObjectTypeName;
	//获取原始DbgkDebugObjectType
	CKernelTable Ssdt;
	PVOID NtCreateDebugObject = Ssdt.GetAddressFromName("NtCreateDebugObject");

	if (!NtCreateDebugObject)
	{
		return FALSE;
	}

	ULONG templong = 0;
	UCHAR tzm[] = { 0x48, 0x8B, 0x15, 0xEC, 0x85, 0x47, 0x00 };

	ULONG64 addr = 0;

	for (PUCHAR i = (PUCHAR)NtCreateDebugObject; i < (PUCHAR)NtCreateDebugObject + 0x100; i++)
	{
		if (*i == 0x48 && *(i + 1) == 0x8B &&
			*(i + 2) == 0x15
			)
		{
			memcpy(&templong, i + 3, 4);
			addr = (ULONG64)((ULONG)templong + (ULONG64)i + 7);
			break;
		}
	}

	g_DbgkDebugObjectType = (POBJECT_TYPE*)addr;
	if (g_DbgkDebugObjectType == 0)
	{
		return FALSE;
	}
	DbgPrint("g_DbgkDebugObjectType:%p\n", g_DbgkDebugObjectType);
	RtlInitUnicodeString(&ObjectTypeName, L"styone");

	OBJECT_TYPE_INITIALIZER_WIN10 ObjectTypeInitializer;
	POBJECT_TYPE* DbgkDebugObjectType = g_DbgkDebugObjectType;

	//参数构造
	//memcpy(&ObjectTypeInitializer, &DbgkDebugObjectType->TypeInfo, sizeof(ObjectTypeInitializer));
	memcpy(&ObjectTypeInitializer, &(*DbgkDebugObjectType)->TypeInfo, sizeof(OBJECT_TYPE_INITIALIZER_WIN10));

	//这里恢复调试权限
	//ObjectTypeInitializer.DeleteProcedure = &DbgkpDeleteObject;
	//ObjectTypeInitializer.CloseProcedure = &DbgkpCloseObject;
	//ObjectTypeInitializer.DeleteProcedure = &proxyDbgkpDeleteObject;
	//ObjectTypeInitializer.CloseProcedure = &proxyDbgkpCloseObject;
	ObjectTypeInitializer.DeleteProcedure = NULL;
	ObjectTypeInitializer.CloseProcedure = NULL;
	ObjectTypeInitializer.GenericMapping.GenericRead = 0x00020001;
	ObjectTypeInitializer.GenericMapping.GenericWrite = 0x00020002;
	ObjectTypeInitializer.GenericMapping.GenericExecute = 0x00120000;
	ObjectTypeInitializer.GenericMapping.GenericAll = 0x001f000f;
	ObjectTypeInitializer.ValidAccessMask = 0x001f000f;

	//创建调试对象类型
	NTSTATUS status = ObCreateObjectType(&ObjectTypeName, &ObjectTypeInitializer, NULL, (PVOID*)g_DbgkDebugObjectType);
	//return FALSE;
	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_OBJECT_NAME_COLLISION)
		{
			DbgPrint("ObCreateObjectType STATUS_OBJECT_NAME_COLLISION\n");
			//对象名已经存在
			PUCHAR j_ObGetObjectType = (PUCHAR)GetKernelAddress("ObGetObjectType");

			if (!j_ObGetObjectType)
			{
				DbgPrint("ObGetObjectType failed\n");
				return FALSE;
			}
			//ULONG uloffset = (ULONG)(*(PUINT32)(j_ObGetObjectType + 31));
			//DbgPrint("uloffset:%x\n", uloffset);
			//ULONG64 baseAddr = (ULONG64)j_ObGetObjectType + 35;
			//DbgPrint("baseAddr:%p\n", baseAddr);
			//POBJECT_TYPE* ObTypeIndexTable = (POBJECT_TYPE*)(baseAddr + uloffset);
			POBJECT_TYPE* ObTypeIndexTable = (POBJECT_TYPE*)(*(PUINT32)(j_ObGetObjectType + 31) + (ULONG64)j_ObGetObjectType + 35);
			if (!ObTypeIndexTable)
			{
				DbgPrint("ObGetObjectType get failed\n");
				return FALSE;
			}
			DbgPrint("ObTypeIndexTable:%p\n", ObTypeIndexTable);
			//DbgPrint("sizeof(_OBJECT_TYPE):%x\n", sizeof(_OBJECT_TYPE));
			DbgPrint("ObTypeIndexTable[2]:%p\n", ObTypeIndexTable[2]);

			ULONG Index = 2;
			while (ObTypeIndexTable[Index])
			{
				DbgPrint("ObTypeIndexTable[Index]:%p\n", ObTypeIndexTable[Index]);
				if (&ObTypeIndexTable[Index]->Name)
				{
					if (ObTypeIndexTable[Index]->Name.Buffer)
					{
						DbgPrint("RtlCompareUnicodeString:%ws %ws\n", ObTypeIndexTable[Index]->Name.Buffer, ObjectTypeName.Buffer);
						if (RtlCompareUnicodeString(&ObTypeIndexTable[Index]->Name, &ObjectTypeName, FALSE) == 0)
						{
							*g_DbgkDebugObjectType = ObTypeIndexTable[Index];
							DbgPrint("ObCreateObjectType already exist *g_DbgkDebugObjectType:%p\n", *g_DbgkDebugObjectType);
							return TRUE;
						}
					}
				}

				Index++;
			}
		}
		else
		{
			DbgPrint("ObCreateObjectType eeor!\n");
			return FALSE;
		}
	}
	DbgPrint("ObCreateObjectType ok g_DbgkDebugObjectType:%p\n", g_DbgkDebugObjectType);
	return TRUE;
}

NTSTATUS(*OriginalDbgkpQueueMessage)(
	IN PEPROCESS_S Process,
	IN  PETHREAD_S Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject);
NTSTATUS DbgkpQueueMessage(
	IN PEPROCESS_S Process,
	IN  PETHREAD_S Thread,
	IN OUT PDBGKM_APIMSG ApiMsg,
	IN ULONG Flags,
	IN PDEBUG_OBJECT TargetDebugObject)
{

	// DbgPrint("DbgkpQueueMessage !\n");

	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT StaticDebugEvent;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;

	if (Flags & 2)
	{
		DebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithQuotaTag((POOL_TYPE)(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE), sizeof(DEBUG_EVENT), 'EgbD');//sizeof (DEBUG_EVENT)=0x168
		if (!DebugEvent)
		{
			return  STATUS_INSUFFICIENT_RESOURCES;
		}

		DebugEvent->Flags = Flags | 4;//offset: 0x13
		ObReferenceObject(Thread);
		ObReferenceObject(Process);
		DebugObject = TargetDebugObject;
		DebugEvent->BackoutThread = PsGetCurrentThread();

	}
	else
	{
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;


		ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);

		DebugObject = (PDEBUG_OBJECT)Process->DebugPort;

		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi ||
			ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
			if (*(PULONG)((PUCHAR)Thread + 0x448) & 0x80) {
				DebugObject = NULL;
			}
		}

		//这里Flags&0x40为真可能是表示跳过LoadDll的消息
		if (ApiMsg->ApiNumber == DbgKmLoadDllApi &&
			*(PULONG)((PUCHAR)Thread + 0x448) & 0x80 &&
			Flags & 0x40) {
			DebugObject = NULL;
		}

		//跳过线程或者进程退出的消息
		if (ApiMsg->ApiNumber == DbgKmExitThreadApi ||
			ApiMsg->ApiNumber == DbgKmExitProcessApi) {
			if (*(PULONG)((PUCHAR)Thread + 0x448) & 0x100) {
				DebugObject = NULL;
			}
		}
		KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
	}

	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId = Thread->Cid;

	if (DebugObject == NULL)
	{
		Status = STATUS_PORT_NOT_SET;
	}
	else
	{
		ExAcquireFastMutex(&DebugObject->Mutex);



		if ((DebugObject->Flags & 0x1) == 0) {
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);

			if ((Flags & 0x2) == 0) {
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);
	}

	if ((Flags & 0x2) == 0) {
		//这时候释放消息同步，因为这个等待需要耗时，所以我们要在KeWaitForSingleObject函数前调用它
		//而且消息已经顺利的插入调试对象了，所以不存在不安去的因素了
		ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);

		if (NT_SUCCESS(Status)) {
			KeWaitForSingleObject(
				&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			//消息完成的话，这里放入了消息完成的状态值，并且作为返回值使用
			Status = DebugEvent->Status;
			//ApiMsg是输出参数
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else {
		if (!NT_SUCCESS(Status)) {
			ObfDereferenceObject(Process);
			ObfDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}

	return Status;
}

PVOID PsCaptureExceptionPort(
	IN PEPROCESS_S Process)
{
	PKTHREAD_S	Thread;
	PVOID		ExceptionPort;

	ExceptionPort = Process->ExceptionPortData;
	if (ExceptionPort != NULL)
	{
		KeEnterCriticalRegion();
		ExfAcquirePushLockShared((ULONG_PTR)&Process->ProcessLock);
		ExceptionPort = (PVOID)((ULONG_PTR)ExceptionPort & ~0x7);
		ObfReferenceObject(ExceptionPort);
		ExfReleasePushLockShared((ULONG_PTR)&Process->ProcessLock);
		KeLeaveCriticalRegion();
		//这段可能有问题
		PKTHREAD_S CurrentThread = (PKTHREAD_S)KeGetCurrentThread();
		//判断APC链表是否为空
		if (&CurrentThread->ApcState.ApcListHead[0] != CurrentThread->ApcState.ApcListHead[0].Flink)
		{
			//判断APC是否禁用
			if (CurrentThread->SpecialApcDisable != 0)
			{
				//大概看了下是分发APC
				KiCheckForKernelApcDelivery();
			}
		}
	}

	return ExceptionPort;
}

BOOLEAN myDbgkpSuspendProcess(
	VOID
) {
	if ((((PEPROCESS_S)PsGetCurrentProcess())->Flags & 0x8) == 0)
	{
		KeFreezeAllThreads();
		return TRUE;
	}
	return FALSE;
}

NTSTATUS DbgkpSendApiMessage(
	ULONG	Flag,
	PDBGKM_APIMSG ApiMsg) {
	NTSTATUS status;
	BOOLEAN	bIsSuspend;
	PEPROCESS_S	Process = (PEPROCESS_S)PsGetCurrentProcess();
	PETHREAD_S	Thread;

	bIsSuspend = FALSE;

	if (Flag & 0x1)
	{
		bIsSuspend = DbgkpSuspendProcess(Process);
	}

	Thread = (PETHREAD_S)PsGetCurrentThread();
	Process = (PEPROCESS_S)PsGetCurrentProcess();

	ApiMsg->ReturnedStatus = STATUS_PENDING;
	status = DbgkpQueueMessage(
		Process,
		Thread,
		ApiMsg,
		((Flag & 0x2) << 0x5),
		NULL);

	ZwFlushInstructionCache(NtCurrentProcess(), 0, 0);
	if (bIsSuspend)
	{
		KeThawAllThreads();
	}

	return status;
}

//PVOID PsQuerySystemDllInfo(
//	ULONG index)			//这里的index不会大于1
//{
//	PVOID	DllInfo;
//
//	DllInfo = (PVOID)PspSystemDlls[index];	//[DllInfo+0x14]是模块的基地址
//	if (DllInfo != NULL &&
//		*(PVOID*)((char*)DllInfo + 0x28) != 0)
//	{
//		return (PVOID)((ULONG_PTR)DllInfo + 0x10);
//	}
//
//	return NULL;
//}

VOID myDbgkSendSystemDllMessages(
	PETHREAD_S		Thread,
	PDEBUG_OBJECT	DebugObject,
	PDBGKM_APIMSG	ApiMsg
)
{

	NTSTATUS	status;
	HANDLE		FileHandle;
	ULONG		index;
	PTEB		Teb;
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
		if (index >= 2)
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

			ApiMsg->u.LoadDll = { 0 };
			Teb = NULL;

			ApiMsg->u.LoadDll.BaseOfDll = DllInfo->BaseOfDll;

			if (Thread && index != 0)
			{
				bSource = TRUE;
				KeStackAttachProcess((PRKPROCESS)Process, &ApcState);
			}
			else
			{
				bSource = FALSE;
			}

			NtHeaders = RtlImageNtHeader(DllInfo->BaseOfDll);
			if (NtHeaders != NULL)
			{
				ApiMsg->u.LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				ApiMsg->u.LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}

			if (Thread == 0)
			{

				if (CurrentThread->Tcb.SystemThread != TRUE &&
					CurrentThread->Tcb.ApcStateIndex != 1)
				{
					Teb = (PTEB)CurrentThread->Tcb.Teb;
				}

				if (Teb)
				{
					RtlStringCbCopyW(Teb->StaticUnicodeBuffer, 261 * sizeof(wchar_t), DllInfo->Buffer);
					Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
					ApiMsg->u.LoadDll.NamePointer = (PVOID)&Teb->NtTib.ArbitraryUserPointer;
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
				DbgkpSendApiMessage(0x3, ApiMsg);
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
				status = DbgkpQueueMessage(
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


EX_PUSH_LOCK MiChangeControlAreaFileLock;
PFILE_OBJECT MiReferenceControlAreaFile(
	PCONTROL_AREA CtrlArea)
{

	PKTHREAD_S	CurrentThread;
	PFILE_OBJECT FileObject;

	CurrentThread = (PKTHREAD_S)PsGetCurrentThread();
	KeEnterCriticalRegion();

	ExfAcquirePushLockShared((ULONG_PTR)&MiChangeControlAreaFileLock);

	//((PETHREAD_S)CurrentThread)->OwnsChangeControlAreaShared = TRUE;
	FileObject = (PFILE_OBJECT)ObFastReferenceObjectLocked(&CtrlArea->FilePointer);
	//((PETHREAD_S)CurrentThread)->OwnsChangeControlAreaShared = FALSE;

	ExfReleasePushLockShared((ULONG_PTR)&MiChangeControlAreaFileLock);

	KeLeaveCriticalRegion();

	return FileObject;
}
NTSTATUS myMmGetFileNameForSection(
	IN PSEGMENT_OBJECT SectionObject,
	OUT POBJECT_NAME_INFORMATION* FileNameInfo
)
{

	ULONG NumberOfBytes;
	ULONG AdditionalLengthNeeded;
	NTSTATUS Status;
	PFILE_OBJECT FileObject;

	NumberOfBytes = 1024;

	*FileNameInfo = NULL;



	if ((((ULONG_PTR)SectionObject->MmSubSectionFlags) & 0x20) == FALSE)
	{
		return STATUS_SECTION_NOT_IMAGE;
	}

	*FileNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, NumberOfBytes, '  mM');

	if (*FileNameInfo == NULL) {
		return STATUS_NO_MEMORY;
	}

	FileObject = (PFILE_OBJECT)ObFastReferenceObject(&SectionObject->Subsection->ControlArea->FilePointer);
	if (FileObject == 0)
	{
		FileObject = MiReferenceControlAreaFile(SectionObject->Subsection->ControlArea);
	}


	Status = ObQueryNameString(FileObject,
		*FileNameInfo,
		NumberOfBytes,
		&AdditionalLengthNeeded);

	if (!NT_SUCCESS(Status)) {

		if (Status == STATUS_INFO_LENGTH_MISMATCH) {

			//
			// Our buffer was not large enough, retry just once with a larger
			// one (as specified by ObQuery).  Don't try more than once to
			// prevent broken parse procedures which give back wrong
			// AdditionalLengthNeeded values from causing problems.
			//

			ExFreePool(*FileNameInfo);

			NumberOfBytes += AdditionalLengthNeeded;

			*FileNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool,
				NumberOfBytes,
				'  mM');

			if (*FileNameInfo == NULL)
			{
				ObDereferenceObjectDeferDelete(FileObject);
				return STATUS_NO_MEMORY;
			}

			Status = ObQueryNameString(FileObject,
				*FileNameInfo,
				NumberOfBytes,
				&AdditionalLengthNeeded);

			if (NT_SUCCESS(Status))
			{
				ObDereferenceObjectDeferDelete(FileObject);
				return STATUS_SUCCESS;
			}
		}

		ObDereferenceObjectDeferDelete(FileObject);
		ExFreePool(*FileNameInfo);
		*FileNameInfo = NULL;
		return Status;
	}
	ObDereferenceObjectDeferDelete(FileObject);
	return STATUS_SUCCESS;
}
HANDLE DbgkpSectionToFileHandle(
	IN PVOID SectionObject) {
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE Handle;
	POBJECT_NAME_INFORMATION FileNameInfo;

	Status = MmGetFileNameForSection((PSEGMENT_OBJECT)SectionObject, &FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}

	InitializeObjectAttributes(
		&Obja,
		&FileNameInfo->Name,
		OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);

	Status = ZwOpenFile(
		&Handle,
		(ACCESS_MASK)(GENERIC_READ | SYNCHRONIZE),
		&Obja,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT
	);
	ExFreePool(FileNameInfo);
	if (!NT_SUCCESS(Status)) {
		return NULL;
	}
	else {
		return Handle;
	}
}

//NTSTATUS myDbgkpPostFakeThreadMessages(
//	PEPROCESS_S	Process,
//	PDEBUG_OBJECT	DebugObject,
//	PETHREAD_S	StartThread,
//	PETHREAD_S* pFirstThread,
//	PETHREAD_S* pLastThread)
//{
//
//	NTSTATUS status;
//	PETHREAD_S Thread, FirstThread, LastThread, CurrentThread;
//	DBGKM_APIMSG ApiMsg;
//	BOOLEAN First = TRUE;
//	BOOLEAN IsFirstThread;
//	PIMAGE_NT_HEADERS NtHeaders;
//	ULONG Flags;
//	KAPC_STATE ApcState;
//
//	status = STATUS_UNSUCCESSFUL;
//
//	LastThread = FirstThread = NULL;
//
//	CurrentThread = (PETHREAD_S)PsGetCurrentThread();
//
//	if (StartThread == 0)
//	{
//		StartThread = (PETHREAD_S)PsGetNextProcessThread((PEPROCESS)Process, 0);
//		First = TRUE;
//	}
//	else {
//		First = FALSE;
//		FirstThread = StartThread;
//		ObReferenceObject(StartThread);
//	}
//
//	for (Thread = StartThread;
//		Thread != NULL;
//		Thread = (PETHREAD_S)PsGetNextProcessThread((PEPROCESS)Process, (PETHREAD)Thread))
//	{
//
//		Flags = 0x2;
//
//		if (LastThread != 0)
//		{
//			ObDereferenceObject(LastThread);
//		}
//
//		LastThread = Thread;
//		ObReferenceObject(LastThread);
//		if (Thread->Tcb.SystemThread != 0)
//		{
//			continue;
//		}
//
//
//		if (Thread->ThreadInserted == 0)//这里要注意下位操作
//		{
//			//这个涉及的内容也比较多，而且一般也不会进入这里，所以为了简单注释掉好了
//			//PsSynchronizeWithThreadInsertion(Thread,CurrentThread);
//			if (Thread->ThreadInserted == 0)
//			{
//				continue;
//			}
//		}
//
//		if (ExAcquireRundownProtection(&Thread->RundownProtect))
//		{
//			Flags |= 0x8;
//			status = PsSuspendThread((PETHREAD)Thread, 0);
//			if (NT_SUCCESS(status))
//			{
//				Flags |= 0x20;
//			}
//		}
//		else {
//			Flags |= 0x10;
//		}
//
//		//每次构造一个DBGKM_APIMSG结构
//		memset(&ApiMsg, 0, sizeof(DBGKM_APIMSG));
//
//		if (First && (Flags & 0x10) == 0)
//		{
//			//进程的第一个线程才会到这里
//			IsFirstThread = TRUE;
//			ApiMsg.ApiNumber = DbgKmCreateProcessApi;
//			if (Process->SectionObject)
//			{
//				//DbgkpSectionToFileHandle函数是返回一个模块的句柄
//				ApiMsg.u.CreateProcessInfo.FileHandle = DbgkpSectionToFileHandle(Process->SectionObject);
//			}
//			else {
//				ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
//			}
//			ApiMsg.u.CreateProcessInfo.BaseOfImage = Process->SectionBaseAddress;
//
//			KeStackAttachProcess((PRKPROCESS)Process, &ApcState);
//
//			__try {
//				NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
//				if (NtHeaders)
//				{
//					ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
//					ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
//					ApiMsg.u.CreateProcessInfo.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
//				}
//			}_except(EXCEPTION_EXECUTE_HANDLER) {
//				ApiMsg.u.CreateProcessInfo.InitialThread.StartAddress = NULL;
//				ApiMsg.u.CreateProcessInfo.DebugInfoFileOffset = 0;
//				ApiMsg.u.CreateProcessInfo.DebugInfoSize = 0;
//			}
//
//			KeUnstackDetachProcess(&ApcState);
//		}
//		else {
//			IsFirstThread = FALSE;
//			ApiMsg.ApiNumber = DbgKmCreateThreadApi;
//			ApiMsg.u.CreateThread.StartAddress = Thread->StartAddress;//注意偏移
//		}
//
//		status = DbgkpQueueMessage(
//			Process,
//			Thread,
//			&ApiMsg,
//			Flags,
//			DebugObject);
//
//		if (!NT_SUCCESS(status))
//		{
//			if (Flags & 0x20)
//			{
//				KeResumeThread((PETHREAD)Thread);
//			}
//
//			if (Flags & 0x08)
//			{
//				ExReleaseRundownProtection(&Thread->RundownProtect);
//			}
//
//			if (ApiMsg.ApiNumber == DbgKmCreateProcessApi && ApiMsg.u.CreateProcessInfo.FileHandle != NULL)
//			{
//				ObCloseHandle(ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
//			}
//
//			ObDereferenceObject(Thread);
//			break;
//
//		}
//		else if (IsFirstThread) {
//			First = FALSE;
//			ObReferenceObject(Thread);
//			FirstThread = Thread;
//
//			DbgkSendSystemDllMessages(Thread, DebugObject, &ApiMsg);
//		}
//	}
//
//	if (!NT_SUCCESS(status)) {
//		if (FirstThread)
//		{
//			ObDereferenceObject(FirstThread);
//		}
//		if (LastThread != NULL)
//		{
//			ObDereferenceObject(LastThread);
//		}
//	}
//	else {
//		if (FirstThread) {
//			*pFirstThread = FirstThread;
//			*pLastThread = LastThread;
//		}
//		else {
//
//			if (LastThread != NULL)
//			{
//				ObDereferenceObject(LastThread);
//			}
//			status = STATUS_UNSUCCESSFUL;
//		}
//	}
//	return status;
//}

//NTSTATUS DbgkpPostFakeProcessCreateMessages(
//	IN PEPROCESS_S Process,
//	IN PDEBUG_OBJECT DebugObject,
//	IN PETHREAD_S* pLastThread)
//{
//
//	NTSTATUS	status;
//	KAPC_STATE	ApcState;
//	PETHREAD_S	StartThread, Thread;
//	PETHREAD_S	LastThread = 0;
//
//	//收集所有线程创建的消息
//	StartThread = 0;
//	//_DbgkpPostFakeThreadMessages DbgkpPostFakeThreadMessages = (_DbgkpPostFakeThreadMessages)0xfffff8000432b360;
//	status = DbgkpPostFakeThreadMessages(Process, DebugObject, StartThread, &Thread, &LastThread);
//
//	if (NT_SUCCESS(status))
//	{
//		KeStackAttachProcess((PRKPROCESS)Process, &ApcState);
//
//		//收集模块创建的消息
//
//
//		DbgkpPostModuleMessages((PEPROCESS)Process, (PETHREAD)Thread, DebugObject);
//
//		KeUnstackDetachProcess(&ApcState);
//
//		ObDereferenceObject(Thread);
//	}
//	else {
//		LastThread = 0;
//	}
//
//	*pLastThread = LastThread;
//	return	status;
//}

VOID DbgkpFreeDebugEvent(
	IN PDEBUG_EVENT DebugEvent)
{
	NTSTATUS Status;

	switch (DebugEvent->ApiMsg.ApiNumber) {
	case DbgKmCreateProcessApi:
		if (DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle != NULL) {
			Status = ObCloseHandle(DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle, KernelMode);
		}
		break;

	case DbgKmLoadDllApi:
		if (DebugEvent->ApiMsg.u.LoadDll.FileHandle != NULL) {
			Status = ObCloseHandle(DebugEvent->ApiMsg.u.LoadDll.FileHandle, KernelMode);
		}
		break;

	}
	ObfDereferenceObject(DebugEvent->Process);
	ObfDereferenceObject(DebugEvent->Thread);
	ExFreePoolWithTag(DebugEvent, 0);
}

VOID DbgkpWakeTarget(
	IN PDEBUG_EVENT DebugEvent)
{
	PETHREAD_S Thread;

	Thread = DebugEvent->Thread;

	if ((DebugEvent->Flags & 0x20) != 0) {
		KeResumeThread((PETHREAD)DebugEvent->Thread);
	}

	if (DebugEvent->Flags & 0x8) {
		ExReleaseRundownProtection(&Thread->RundownProtect);
	}

	if ((DebugEvent->Flags & 0x2) == 0) {
		KeSetEvent(&DebugEvent->ContinueEvent, 0, FALSE);
	}
	else {
		DbgkpFreeDebugEvent(DebugEvent);
	}
}

/**/
VOID DbgkpMarkProcessPeb(PEPROCESS_S Process)
{
	KAPC_STATE ApcState;

	if (ExAcquireRundownProtection(&Process->RundownProtect)) {

		if (Process->Peb != NULL) {
			KeStackAttachProcess((PRKPROCESS)&Process->Pcb, &ApcState);

			ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);

			_try{
				//Process->Peb->BeingDebugged = FALSE;
			(BOOLEAN)(Process->DebugPort != NULL ? TRUE : FALSE);
			} _except(EXCEPTION_EXECUTE_HANDLER) {
			}
			ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);

			KeUnstackDetachProcess(&ApcState);
		}

		ExReleaseRundownProtection(&Process->RundownProtect);
	}
}

//NTSTATUS DbgkpSetProcessDebugObject(
//	IN PEPROCESS_S Process,
//	IN PDEBUG_OBJECT DebugObject,
//	IN NTSTATUS MsgStatus,
//	IN PETHREAD_S LastThread)
//{
//	NTSTATUS Status;
//	PETHREAD_S ThisThread;
//	LIST_ENTRY TempList;
//	PLIST_ENTRY Entry;
//	PDEBUG_EVENT DebugEvent;
//	BOOLEAN First;
//	PETHREAD_S Thread;
//	BOOLEAN GlobalHeld;
//	PETHREAD_S FirstThread;
//
//	PAGED_CODE();
//
//	ThisThread = (PETHREAD_S)PsGetCurrentThread();
//
//	//初始化链表，这个之后储存消息
//	InitializeListHead(&TempList);
//
//	First = TRUE;
//	GlobalHeld = FALSE;
//
//	if (!NT_SUCCESS(MsgStatus)) {
//		LastThread = NULL;
//		Status = MsgStatus;
//	}
//	else {
//		Status = STATUS_SUCCESS;
//	}
//
//
//	if (NT_SUCCESS(Status)) {
//
//		while (1) {
//
//			GlobalHeld = TRUE;
//
//			ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);
//
//			//如果被调试进程的debugport已经设置，那么跳出循环
//			if (Process->DebugPort != NULL) {
//				Status = STATUS_PORT_ALREADY_SET;
//				break;
//			}
//
//			//没有设置debugport，在这里设置
//			Process->DebugPort = DebugObject;
//
//			//增加被调试进程最后一个线程的引用
//			ObfReferenceObject(LastThread);
//
//			//这里如果返回有值，说明在这之间还有线程被创建了，这里也要加入调试消息链表
//			Thread = (PETHREAD_S)PsGetNextProcessThread((PEPROCESS)Process, (PETHREAD)LastThread);
//			if (Thread != NULL) {
//
//				Process->DebugPort = NULL;
//
//				ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);
//
//				GlobalHeld = FALSE;
//
//				ObfDereferenceObject(LastThread);
//				//通知线程创建消息
//				Status = DbgkpPostFakeThreadMessages(
//					Process,
//					DebugObject,
//					Thread,
//					&FirstThread,
//					&LastThread);
//				if (!NT_SUCCESS(Status)) {
//					LastThread = NULL;
//					break;
//				}
//				ObfDereferenceObject(FirstThread);
//			}
//			else {
//				break;
//			}
//		}
//	}
//
//	ExAcquireFastMutex(&DebugObject->Mutex);
//
//	if (NT_SUCCESS(Status)) {
//		//看看调试对象是否要求删除
//		if ((DebugObject->Flags & 0x1) == 0) {
//			RtlInterlockedSetBitsDiscardReturn(&Process->Flags, 0x2 | 0x1);
//			ObfReferenceObject(DebugObject);
//		}
//		else {
//			Process->DebugPort = NULL;
//			Status = STATUS_DEBUGGER_INACTIVE;
//		}
//	}
//
//	//通过上面的操作，调试对象的消息链表装满了线程创建的消息(同时也包含模块加载的消息)
//	//
//	for (Entry = DebugObject->EventList.Flink;
//		Entry != &DebugObject->EventList;
//		) {
//		//取出调试事件
//		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
//		Entry = Entry->Flink;
//
//		//看看调试事件是否急于处理，如果不是急于处理的，说明在DbgkpQueueMessage函数里面没有得到处理，
//		//那么我们就在这里想办法处理吧(急于处理的已经在DbgkpQueueMessage函数中处理过了，所以这里无需担心)。
//		//并且看看是否是本线程负责通知完成此消息
//		if ((DebugEvent->Flags & 0x4) != 0 && DebugEvent->BackoutThread == (PETHREAD)ThisThread) {
//			Thread = DebugEvent->Thread;
//
//			if (NT_SUCCESS(Status)) {
//				//这里判断之前对线程申请的停止保护是否失败
//				if ((DebugEvent->Flags & 0x10) != 0) {
//					RtlInterlockedSetBitsDiscardReturn(&Thread->CrossThreadFlags,
//						0x100);
//					RemoveEntryList(&DebugEvent->EventList);
//					InsertTailList(&TempList, &DebugEvent->EventList);
//				}
//				else {
//					//这里极有可能是判断是否主线程的创建消息，是主线程的话完成消息
//					if (First) {
//						DebugEvent->Flags &= ~0x4;
//						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
//						First = FALSE;
//					}
//					//到这里设置跳过线程创建消息
//					DebugEvent->BackoutThread = NULL;
//					RtlInterlockedSetBitsDiscardReturn(&Thread->CrossThreadFlags,
//						0x80);
//
//				}
//			}
//			else {
//				//很移除消息，并且加入临时链表中
//				RemoveEntryList(&DebugEvent->EventList);
//				InsertTailList(&TempList, &DebugEvent->EventList);
//			}
//			//这里看看是够请求过线程停止保护，是的话释放请求
//			if (DebugEvent->Flags & 0x8) {
//				DebugEvent->Flags &= ~0x8;
//				ExReleaseRundownProtection(&Thread->RundownProtect);
//			}
//
//		}
//	}
//
//	ExReleaseFastMutex(&DebugObject->Mutex);
//
//	if (GlobalHeld) {
//		ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);
//	}
//
//	if (LastThread != NULL) {
//		ObDereferenceObject(LastThread);
//	}
//
//	//这里读取临时链表，并且处理里面的每个消息
//	while (!IsListEmpty(&TempList)) {
//		Entry = RemoveHeadList(&TempList);
//		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
//		DbgkpWakeTarget(DebugEvent);
//	}
//
//	if (NT_SUCCESS(Status)) {
//		DbgkpMarkProcessPeb(Process);
//	}
//
//	return Status;
//}


NTSTATUS(*OriginalDbgkClearProcessDebugObject)(
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT SourceDebugObject);
NTSTATUS  DbgkClearProcessDebugObject(
	IN PEPROCESS_S Process,
	IN PDEBUG_OBJECT SourceDebugObject) {
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;

	ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);

	DebugObject = (PDEBUG_OBJECT)Process->DebugPort;
	if (DebugObject == NULL || (DebugObject != SourceDebugObject && SourceDebugObject != NULL)) {
		DebugObject = NULL;
		Status = STATUS_PORT_NOT_SET;
	}
	else {
		Process->DebugPort = NULL;
		Status = STATUS_SUCCESS;
	}
	ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);

	if (NT_SUCCESS(Status)) {
		DbgkpMarkProcessPeb(Process);
	}

	if (DebugObject) {
		InitializeListHead(&TempList);

		ExAcquireFastMutex(&DebugObject->Mutex);
		for (Entry = DebugObject->EventList.Flink;
			Entry != &DebugObject->EventList;
			) {

			DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
			Entry = Entry->Flink;
			if (DebugEvent->Process == Process) {
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}
		}
		ExReleaseFastMutex(&DebugObject->Mutex);

		ObfDereferenceObject(DebugObject);

		while (!IsListEmpty(&TempList)) {
			Entry = RemoveHeadList(&TempList);
			DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
			DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
			DbgkpWakeTarget(DebugEvent);
		}
	}

	return Status;
}
VOID DbgkpConvertKernelToUserStateChange(
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	PDEBUG_EVENT DebugEvent)
{
	WaitStateChange->AppClientId = DebugEvent->ClientId;
	switch (DebugEvent->ApiMsg.ApiNumber) {
	case DbgKmExceptionApi:
		switch (DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode) {
		case STATUS_BREAKPOINT:
			WaitStateChange->NewState = DbgBreakpointStateChange;
			break;

		case STATUS_SINGLE_STEP:
			WaitStateChange->NewState = DbgSingleStepStateChange;
			break;

		default:
			WaitStateChange->NewState = DbgExceptionStateChange;
			break;
		}
		WaitStateChange->StateInfo.Exception = DebugEvent->ApiMsg.u.Exception;
		break;

	case DbgKmCreateThreadApi:
		WaitStateChange->NewState = DbgCreateThreadStateChange;
		WaitStateChange->StateInfo.CreateThread.NewThread = DebugEvent->ApiMsg.u.CreateThread;
		break;

	case DbgKmCreateProcessApi:
		WaitStateChange->NewState = DbgCreateProcessStateChange;
		WaitStateChange->StateInfo.CreateProcessInfo.NewProcess = DebugEvent->ApiMsg.u.CreateProcessInfo;
		DebugEvent->ApiMsg.u.CreateProcessInfo.FileHandle = NULL;
		break;

	case DbgKmExitThreadApi:
		WaitStateChange->NewState = DbgExitThreadStateChange;
		WaitStateChange->StateInfo.ExitThread = DebugEvent->ApiMsg.u.ExitThread;
		break;

	case DbgKmExitProcessApi:
		WaitStateChange->NewState = DbgExitProcessStateChange;
		WaitStateChange->StateInfo.ExitProcess = DebugEvent->ApiMsg.u.ExitProcess;
		break;

	case DbgKmLoadDllApi:
		WaitStateChange->NewState = DbgLoadDllStateChange;
		WaitStateChange->StateInfo.LoadDll = DebugEvent->ApiMsg.u.LoadDll;
		DebugEvent->ApiMsg.u.LoadDll.FileHandle = NULL;
		break;

	case DbgKmUnloadDllApi:
		WaitStateChange->NewState = DbgUnloadDllStateChange;
		WaitStateChange->StateInfo.UnloadDll = DebugEvent->ApiMsg.u.UnloadDll;
		break;

	default:
		ASSERT(FALSE);
	}
}

VOID DbgkpOpenHandles(
	PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
	PEPROCESS_S Process,
	PETHREAD_S Thread)
{
	NTSTATUS Status;
	PEPROCESS_S CurrentProcess;
	HANDLE OldHandle;

	switch (WaitStateChange->NewState) {
	case DbgCreateThreadStateChange:
		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
			THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsThreadType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateThread.HandleToThread);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateThread.HandleToThread = NULL;
		}
		break;

	case DbgCreateProcessStateChange:

		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | \
			THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsThreadType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateProcessInfo.HandleToThread = NULL;
		}
		Status = ObOpenObjectByPointer(Process,
			0,
			NULL,
			PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
			PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION |
			PROCESS_CREATE_THREAD | PROCESS_TERMINATE |
			READ_CONTROL | SYNCHRONIZE,
			*PsProcessType,
			KernelMode,
			&WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess);
		if (!NT_SUCCESS(Status)) {
			WaitStateChange->StateInfo.CreateProcessInfo.HandleToProcess = NULL;
		}

		OldHandle = WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle;
		if (OldHandle != NULL) {
			CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
			Status = ObDuplicateObject(CurrentProcess,
				OldHandle,
				CurrentProcess,
				&WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle,
				0,
				0,
				DUPLICATE_SAME_ACCESS,
				KernelMode);
			if (!NT_SUCCESS(Status)) {
				WaitStateChange->StateInfo.CreateProcessInfo.NewProcess.FileHandle = NULL;
			}
			ObCloseHandle(OldHandle, KernelMode);
		}
		break;

	case DbgLoadDllStateChange:

		OldHandle = WaitStateChange->StateInfo.LoadDll.FileHandle;
		if (OldHandle != NULL) {
			CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
			Status = ObDuplicateObject(CurrentProcess,
				OldHandle,
				CurrentProcess,
				&WaitStateChange->StateInfo.LoadDll.FileHandle,
				0,
				0,
				DUPLICATE_SAME_ACCESS,
				KernelMode);
			if (!NT_SUCCESS(Status)) {
				WaitStateChange->StateInfo.LoadDll.FileHandle = NULL;
			}
			ObCloseHandle(OldHandle, KernelMode);
		}

		break;

	default:
		break;
	}
}

NTSTATUS(*OriginalNtCreateDebugObject)(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags);
NTSTATUS  NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags)
{
	NTSTATUS status;
	HANDLE Handle;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE	PreviousMode;

	PreviousMode = ExGetPreviousMode();

	//判断用户层句柄地址是否合法
	_try{
		if (PreviousMode != KernelMode) {
			ProbeForWrite(DebugObjectHandle,sizeof(HANDLE),sizeof(UCHAR));
		}
		*DebugObjectHandle = NULL;

	} _except(ExSystemExceptionFilter()) {
		return GetExceptionCode();
	}

	if (Flags & ~0x1) {
		return STATUS_INVALID_PARAMETER;
	}

	//创建调试对象
	status = ObCreateObject(
		PreviousMode,
		*g_DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);

	if (!NT_SUCCESS(status)) {
		return status;
	}
	//初始化调试对象
	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & 0x1) {
		DebugObject->Flags = 0x2;
	}
	else {
		DebugObject->Flags = 0;
	}

	//调试对象插入句柄表
	status = ObInsertObject(
		DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	_try{
		*DebugObjectHandle = Handle;
	} _except(ExSystemExceptionFilter()) {
		status = GetExceptionCode();
	}

	return status;
}

NTSTATUS(*OriginalNtDebugActiveProcess)(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle);
//NTSTATUS  NtDebugActiveProcess(
//	HANDLE ProcessHandle,
//	HANDLE DebugObjectHandle)
//{
//
//	NTSTATUS status;
//	KAPC_STATE	ApcState;
//	KPROCESSOR_MODE PreviousMode;
//	PDEBUG_OBJECT DebugObject;
//	PEPROCESS_S Process, CurrentProcess;
//	PETHREAD LastThread;
//	PreviousMode = ExGetPreviousMode();
//	//得到被调试进程的eprocess
//	status = ObReferenceObjectByHandle(
//		ProcessHandle,
//		0x800,
//		*PsProcessType,
//		PreviousMode,
//		(PVOID*)&Process,
//		NULL);
//	if (!NT_SUCCESS(status)) {
//		return status;
//	}
//	//判断被调试进程是否自己或者被调试进程是否PsInitialSystemProcess进程，是的话退出
//	if (Process == (PEPROCESS_S)PsGetCurrentProcess() || Process == (PEPROCESS_S)PsInitialSystemProcess) {
//		ObfDereferenceObject(Process);
//		return STATUS_ACCESS_DENIED;
//	}
//
//	CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
//
//
//	////判断下模式、当前进程的ProtectedProcess和被调试进程的ProtectedProcess
//	//if (PreviousMode == UserMode &&
//	//	CurrentProcess->ProtectedProcess == 0 &&
//	//	Process->ProtectedProcess)
//	//{
//	//	//这里很奇怪，如果当前进程被保护的那么就到不了这里了。
//	//	//那说明当前进程是受保护的就可以忽视目标进程是否受保护了。
//	//	ObfDereferenceObject_S(Process);
//	//	return STATUS_PROCESS_IS_PROTECTED;
//	//}
//
//	status = ObReferenceObjectByHandle(
//		DebugObjectHandle,
//		0x2,
//		*g_DbgkDebugObjectType,
//		PreviousMode,
//		(PVOID*)&DebugObject,
//		NULL);
//
//	if (NT_SUCCESS(status)) {
//		//进程退出可不好办了，所以在这里还是先调用ExAcquireRundownProtection吧，安全一点儿
//		if (ExAcquireRundownProtection(&Process->RundownProtect))
//		{
//			//发送一个虚拟的进程创建消息....从字面理解是这样的，实际它要达到的效果也是如此
//			status = DbgkpPostFakeProcessCreateMessages(Process, DebugObject, (PETHREAD_S*)&LastThread);
//
//			//注意，DbgkpSetProcessDebugObject函数有个参数是寄存器传参，不分析还很难看出来，
//			//其中一个参数是DbgkpPostFakeProcessCreateMessages函数的返回值，而此参数是通过
//			//eax传递进去的，为了保持和windows的代码一致，我也写成wrk一样的吧。
//			//设置调试对象给被调试的进程
//
//			status = DbgkpSetProcessDebugObject((PEPROCESS_S)Process, DebugObject, status, (PETHREAD_S)LastThread);
//
//			ExReleaseRundownProtection(&Process->RundownProtect);
//		}
//		else {
//			status = STATUS_PROCESS_IS_TERMINATING;
//		}
//
//		ObfDereferenceObject(DebugObject);
//	}
//	ObfDereferenceObject(Process);
//
//	//KdPrint(("NtDebugActiveProcess:%X", status));
//
//	return status;
//}


typedef NTSTATUS(*OriginalNtDebugContinue)(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus);
EXTERN_C OriginalNtDebugContinue originalNtDebugContinue;
NTSTATUS  NtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus)
{
	NTSTATUS Status;
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent, FoundDebugEvent;
	KPROCESSOR_MODE PreviousMode;
	CLIENT_ID Clid;
	PLIST_ENTRY Entry;
	BOOLEAN GotEvent;

	PreviousMode = ExGetPreviousMode();

	_try{
		if (PreviousMode != KernelMode) {
			ProbeForRead(ClientId, sizeof(*ClientId), sizeof(UCHAR));
		}
		Clid = *ClientId;

	} _except(ExSystemExceptionFilter()) {
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
		DebugObjectHandle,
		0x1,
		*g_DbgkDebugObjectType,
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


typedef NTSTATUS(*OriginalNtWaitForDebugEvent)(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
	);
extern "C" OriginalNtWaitForDebugEvent originalNtWaitForDebugEvent;
NTSTATUS  NtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PDBGUI_WAIT_STATE_CHANGE WaitStateChange
)
{


	NTSTATUS Status;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	LARGE_INTEGER Tmo = { 0 };
	LARGE_INTEGER StartTime = { 0 };
	DBGUI_WAIT_STATE_CHANGE tWaitStateChange = {};
	PEPROCESS_S Process;
	PETHREAD_S Thread;
	PLIST_ENTRY Entry, Entry2;
	PDEBUG_EVENT DebugEvent, DebugEvent2;
	BOOLEAN GotEvent;

	PreviousMode = ExGetPreviousMode();

	_try{
		if (ARGUMENT_PRESENT(Timeout)) {
			if (PreviousMode != KernelMode) {
				ProbeForRead(Timeout, sizeof(*Timeout), sizeof(UCHAR));
			}
			Tmo = *Timeout;
			Timeout = &Tmo;
			KeQuerySystemTime(&StartTime);
		}
		if (PreviousMode != KernelMode) {
			ProbeForWrite(WaitStateChange, sizeof(*WaitStateChange), sizeof(UCHAR));
		}

	} _except(ExSystemExceptionFilter()) {
		return GetExceptionCode();
	}

	//首先通过句柄获取调试对象
	Status = ObReferenceObjectByHandle(DebugObjectHandle,
		0x1,
		*g_DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Process = NULL;
	Thread = NULL;

	while (1) {
		//在调试对象有事件产生
		Status = KeWaitForSingleObject(&DebugObject->EventsPresent,
			Executive,
			PreviousMode,
			Alertable,
			Timeout);
		if (!NT_SUCCESS(Status) || Status == STATUS_TIMEOUT || Status == STATUS_ALERTED || Status == STATUS_USER_APC) {
			break;
		}

		GotEvent = FALSE;

		DebugEvent = NULL;

		ExAcquireFastMutex(&DebugObject->Mutex);

		//等到有信号后判断是否此调试对象无效了，没有无效那么就进一步处理
		if ((DebugObject->Flags & 0x1) == 0) {

			//在这里遍历调试事件链表
			for (Entry = DebugObject->EventList.Flink;
				Entry != &DebugObject->EventList;
				Entry = Entry->Flink) {

				DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
				//判断消息是否已经读取过或者是否还不需要处理，否则处理
				if ((DebugEvent->Flags & (0x1 | 0x4)) == 0) {
					GotEvent = TRUE;

					//这里进行第二次遍历事件链表
					for (Entry2 = DebugObject->EventList.Flink;
						Entry2 != Entry;
						Entry2 = Entry2->Flink) {

						DebugEvent2 = CONTAINING_RECORD(Entry2, DEBUG_EVENT, EventList);
						//能进入这个遍历的说明有找到比DebugEvent还早的未处理事件，那么就重新设置下
						//DebugEvent事件标记为待处理状态。实际一般情况是进入不到这个循环里的，因为
						//目前我还能看到处理一个调试事件时，还有比这个调试事件更早的没被处理。或许
						//后面的研究会发现这个问题，那时咱们再详谈。通过这里也可以看出，调试事件是
						//严格按照队列形式来处理的，也就是先来的先处理。
						//
						if (DebugEvent->ClientId.UniqueProcess == DebugEvent2->ClientId.UniqueProcess) {

							DebugEvent->Flags |= 0x4;
							DebugEvent->BackoutThread = NULL;
							GotEvent = FALSE;
							break;
						}
					}
					//找到一个满足条件的事件的话，就退出循环了
					if (GotEvent) {
						break;
					}
				}
			}

			//找到的话，把事件相关的信息转换成用户层可识别的信息，然后设置此事件已读
			if (GotEvent) {
				Process = DebugEvent->Process;
				Thread = DebugEvent->Thread;
				ObfReferenceObject(Thread);
				ObfReferenceObject(Process);
				DbgkpConvertKernelToUserStateChange(&tWaitStateChange, DebugEvent);
				DebugEvent->Flags |= 0x1;
			}
			else {
				//没找到的话设置调试对象没有信号了.....
				KeClearEvent(&DebugObject->EventsPresent);
			}
			Status = STATUS_SUCCESS;

		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		ExReleaseFastMutex(&DebugObject->Mutex);

		if (NT_SUCCESS(Status)) {
			if (GotEvent == FALSE) {

				if (Tmo.QuadPart < 0) {
					LARGE_INTEGER NewTime;
					KeQuerySystemTime(&NewTime);
					Tmo.QuadPart = Tmo.QuadPart + (NewTime.QuadPart - StartTime.QuadPart);
					StartTime = NewTime;
					if (Tmo.QuadPart >= 0) {
						Status = STATUS_TIMEOUT;
						break;
					}
				}
			}
			else {

				DbgkpOpenHandles(&tWaitStateChange, Process, Thread);
				ObfDereferenceObject(Thread);
				ObfDereferenceObject(Process);
				break;
			}
		}
		else {
			break;
		}
	}

	ObfDereferenceObject(DebugObject);

	_try{
		*WaitStateChange = tWaitStateChange;
	} _except(ExSystemExceptionFilter()) {
		Status = GetExceptionCode();
	}
	return Status;
}


NTSTATUS(*OriginalNtRemoveProcessDebug)(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);
NTSTATUS  NtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	NTSTATUS	status;
	PEPROCESS_S	Process, CurrentProcess;
	KPROCESSOR_MODE	PreviousMode;
	PDEBUG_OBJECT	DebugObject;
	//可能不会走到这个函数
	DbgPrint("NtRemoveProcessDebug Entry!\n");

	PreviousMode = ExGetPreviousMode();

	status = ObReferenceObjectByHandle(
		ProcessHandle,
		0x800,
		*PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//如果当前进程没有受保护且被调试进程受保护，这里直接返回失败！
	//if (PreviousMode == UserMode)
	//{
	//	CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
	//	if (CurrentProcess->ProtectedProcess == FALSE &&
	//		Process->ProtectedProcess == TRUE)
	//	{
	//		ObfDereferenceObject(Process);
	//		return STATUS_PROCESS_IS_PROTECTED;
	//	}
	//}

	status = ObReferenceObjectByHandle(
		DebugObjectHandle,
		0x2,
		*g_DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
	if (!NT_SUCCESS(status))
	{
		ObfDereferenceObject(Process);
		return status;
	}

	status = DbgkClearProcessDebugObject(
		Process,
		DebugObject);

	ObfDereferenceObject(DebugObject);
	ObfDereferenceObject(Process);
	return status;
}


VOID(*OriginalDbgkCreateThread)(PETHREAD_S Thread);
//VOID  DbgkCreateThread(PETHREAD_S Thread)
//{
//
//	DBGKM_APIMSG m;
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
//	PKTHREAD_S	CurrentThread;
//
//	Process = (PEPROCESS_S)Thread->Tcb.ApcState.Process;
//
//	OldFlags = RtlInterlockedSetBits(&Process->Flags, 0x400001);
//
//	if ((OldFlags & 0x00400000) == 0 &&
//		(*PspNotifyEnableMask & 0x1))
//	{
//
//		IMAGE_INFO_EX ImageInfoEx;
//		PUNICODE_STRING ImageName;
//		POBJECT_NAME_INFORMATION FileNameInfo;
//
//
//
//		ImageInfoEx.ImageInfo.Properties = 0;
//		ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
//		ImageInfoEx.ImageInfo.ImageBase = Process->SectionBaseAddress;
//		ImageInfoEx.ImageInfo.ImageSize = 0;
//
//		_try{
//			NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
//
//			if (NtHeaders)
//			{
//				ImageInfoEx.ImageInfo.ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
//			}
//		} _except(EXCEPTION_EXECUTE_HANDLER) {
//			ImageInfoEx.ImageInfo.ImageSize = 0;
//		}
//		ImageInfoEx.ImageInfo.ImageSelector = 0;
//		ImageInfoEx.ImageInfo.ImageSectionNumber = 0;
//
//		PsReferenceProcessFilePointer((PEPROCESS)Process, (PVOID*)&FileObject);
//		status = SeLocateProcessImageName((PEPROCESS)Process, &ImageName);
//		if (!NT_SUCCESS(status))
//		{
//			ImageName = NULL;
//		}
//
//		PsCallImageNotifyRoutines(
//			ImageName,
//			Process->UniqueProcessId,
//			&ImageInfoEx,
//			FileObject);
//
//		if (ImageName)
//		{
//			//因为在SeLocateProcessImageName中为ImageName申请了内存，所以要在此处释放掉
//			ExFreePoolWithTag(ImageName, 0);
//		}
//		//PsReferenceProcessFilePointer增加了引用计数
//		ObfDereferenceObject(FileObject);
//
//		index = 0;
//		while (index < 2)
//		{
//			ModuleInfo = (PMODULE_INFO)PsQuerySystemDllInfo(index);
//			if (ModuleInfo != NULL)
//			{
//
//				ImageInfoEx.ImageInfo.Properties = 0;
//				ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
//				ImageInfoEx.ImageInfo.ImageBase = ModuleInfo->BaseOfDll;
//				ImageInfoEx.ImageInfo.ImageSize = 0;
//
//				_try{
//					NtHeaders = RtlImageNtHeader(ModuleInfo->BaseOfDll);
//					if (NtHeaders)
//					{
//						ImageInfoEx.ImageInfo.ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
//					}
//				}_except(EXCEPTION_EXECUTE_HANDLER) {
//					ImageInfoEx.ImageInfo.ImageSize = 0;
//				}
//
//				ImageInfoEx.ImageInfo.ImageSelector = 0;
//				ImageInfoEx.ImageInfo.ImageSectionNumber = 0;
//
//				//实际就是PspSystemDlls
//				SystemDll = (PSYSTEM_DLL)((ULONG_PTR)ModuleInfo - 0x10);
//				Object = ObFastReferenceObject(&SystemDll->FastRef);
//				if (Object == NULL)
//				{
//					KeEnterCriticalRegion();
//
//					ExfAcquirePushLockShared((ULONG_PTR)&SystemDll->Lock);
//
//					Object = ObFastReferenceObjectLocked(&SystemDll->FastRef);
//
//					ExfReleasePushLockShared((ULONG_PTR)&SystemDll->Lock);
//
//					KeLeaveCriticalRegion();
//
//				}
//				//这段可能有问题
//				CurrentThread = (PKTHREAD_S)KeGetCurrentThread();
//				//判断APC链表是否为空
//				if (&CurrentThread->ApcState.ApcListHead[0] != CurrentThread->ApcState.ApcListHead[0].Flink)
//				{
//					//判断APC是否禁用
//					if (CurrentThread->SpecialApcDisable != 0)
//					{
//						KiCheckForKernelApcDelivery();
//					}
//				}
//				//获取文件对象
//				FileObject = (PFILE_OBJECT)ObFastReferenceObject(&((PSEGMENT_OBJECT)Object)->Subsection->ControlArea->FilePointer);
//				if (FileObject == 0)
//				{
//					FileObject = MiReferenceControlAreaFile(((PSEGMENT_OBJECT)Object)->Subsection->ControlArea);
//				}
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
//					&ImageInfoEx,
//					FileObject);
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
//	if ((OldFlags & 0x1) == 0)
//	{
//
//		CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
//		CreateThreadArgs->SubSystemKey = 0;
//
//		CreateProcessArgs = &m.u.CreateProcessInfo;
//		CreateProcessArgs->SubSystemKey = 0;
//		CreateProcessArgs->FileHandle = DbgkpSectionToFileHandle(
//			Process->SectionObject
//		);
//		CreateProcessArgs->BaseOfImage = Process->SectionBaseAddress;
//		CreateThreadArgs->StartAddress = NULL;
//		CreateProcessArgs->DebugInfoFileOffset = 0;
//		CreateProcessArgs->DebugInfoSize = 0;
//
//		_try{
//
//			NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);
//
//			if (NtHeaders) {
//
//
//				CreateThreadArgs->StartAddress = (PVOID)(NtHeaders->OptionalHeader.ImageBase + NtHeaders->OptionalHeader.AddressOfEntryPoint);
//
//				CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
//				CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
//			}
//		} _except(EXCEPTION_EXECUTE_HANDLER) {
//			CreateThreadArgs->StartAddress = NULL;
//			CreateProcessArgs->DebugInfoFileOffset = 0;
//			CreateProcessArgs->DebugInfoSize = 0;
//		}
//		m.h.u1.Length = 0x600038;
//		m.h.u2.ZeroInit = 8;
//		m.ApiNumber = DbgKmCreateProcessApi;
//
//		DbgkpSendApiMessage(FALSE, &m);
//
//		if (CreateProcessArgs->FileHandle != NULL) {
//			ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
//		}
//
//		DbgkSendSystemDllMessages
//		(
//			NULL,
//			NULL,
//			&m);
//	}
//	else {
//
//		CreateThreadArgs = &m.u.CreateThread;
//		CreateThreadArgs->SubSystemKey = 0;
//		CreateThreadArgs->StartAddress = Thread->Win32StartAddress;
//		m.h.u1.Length = 0x400018;
//		m.h.u2.ZeroInit = 8;
//		m.ApiNumber = DbgKmCreateThreadApi;
//		DbgkpSendApiMessage(TRUE, &m);
//	}
//
//	if (Thread->ClonedThread == TRUE)
//	{
//		DbgkpPostModuleMessages(
//			(PEPROCESS)Process,
//			(PETHREAD)Thread,
//			NULL);
//	}
//}

VOID(*OriginalDbgkExitThread)(
	NTSTATUS ExitStatus
	);
VOID  DbgkExitThread(
	NTSTATUS ExitStatus
)
{
	DBGKM_APIMSG ApiMsg;
	PEPROCESS_S	Process = (PEPROCESS_S)PsGetCurrentProcess();
	PETHREAD_S	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if (Process->DebugPort != NULL && CurrentThread->ThreadInserted == TRUE)
	{
		ApiMsg.u.ExitThread.ExitStatus = ExitStatus;
		ApiMsg.h.u1.Length = 0x34000C;
		ApiMsg.h.u2.ZeroInit = 8;
		ApiMsg.ApiNumber = DbgKmExitThreadApi;
		DbgkpSendApiMessage(0x1, &ApiMsg);
	}
}


VOID(*OriginalDbgkExitProcess)(
	NTSTATUS ExitStatus
	);
VOID  DbgkExitProcess(
	NTSTATUS ExitStatus
)
{
	DBGKM_APIMSG ApiMsg;
	PEPROCESS_S	Process = (PEPROCESS_S)PsGetCurrentProcess();
	PETHREAD_S	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if (Process->DebugPort != NULL && CurrentThread->ThreadInserted == TRUE)
	{
		KeQuerySystemTime(&Process->ExitTime);
		ApiMsg.u.ExitProcess.ExitStatus = ExitStatus;
		ApiMsg.h.u1.Length = 0x34000C;
		ApiMsg.h.u2.ZeroInit = 8;
		ApiMsg.ApiNumber = DbgKmExitProcessApi;
		DbgkpSendApiMessage(FALSE, &ApiMsg);
	}
}


NTSTATUS(*OriginalDbgkCopyProcessDebugPort)(
	IN PEPROCESS_S TargetProcess,
	IN PEPROCESS_S SourceProcess,
	IN PDEBUG_OBJECT DebugObject,
	OUT PBOOLEAN bFlag);
NTSTATUS  DbgkCopyProcessDebugPort(
	IN PEPROCESS_S TargetProcess,
	IN PEPROCESS_S SourceProcess,
	IN PDEBUG_OBJECT DebugObject,
	OUT PBOOLEAN bFlag)
{
	TargetProcess->DebugPort = 0;
	if (DebugObject == NULL)
	{
		if (SourceProcess->DebugPort == NULL)
		{
			*bFlag = FALSE;
			return STATUS_SUCCESS;
		}
		else {
			ExAcquireFastMutex(&g_DbgkpProcessDebugPortMutex);
			DebugObject = (PDEBUG_OBJECT)SourceProcess->DebugPort;
			if (DebugObject)
			{
				if (SourceProcess->Flags & 0x2)
				{
					DebugObject = NULL;
				}
				else {
					ObfReferenceObject(DebugObject);
				}
			}
			ExReleaseFastMutex(&g_DbgkpProcessDebugPortMutex);
		}

	}
	else {
		ObfReferenceObject(DebugObject);
	}

	if (DebugObject == NULL)
	{
		*bFlag = FALSE;
		return STATUS_SUCCESS;
	}

	ExAcquireFastMutex(&DebugObject->Mutex);
	if (DebugObject->Flags & 0x1)	//?
	{
		SourceProcess->Pcb.Header.DebugActive = TRUE;
	}
	else {
		TargetProcess->DebugPort = DebugObject;
	}
	ExReleaseFastMutex(&DebugObject->Mutex);

	if (SourceProcess->Pcb.Header.DebugActive == TRUE)
	{
		ObfDereferenceObject(DebugObject);
		DebugObject = NULL;
	}

	if (DebugObject == NULL)
	{
		*bFlag = FALSE;
	}
	else {
		DbgkpMarkProcessPeb(TargetProcess);
		*bFlag = TRUE;
	}

	return STATUS_SUCCESS;
}

//PVOID PsCaptureExceptionPort(
//	IN PEPROCESS_S Process){
//	PKTHREAD_S	Thread;
//	PVOID		ExceptionPort;
//
//	ExceptionPort = Process->ExceptionPortData;
//	if (ExceptionPort != NULL)
//	{
//		KeEnterCriticalRegion();
//		ExAcquirePushLockShared(&Process->ProcessLock,0);
//		ExceptionPort = (PVOID)((ULONG_PTR)ExceptionPort & ~0x7);
//		ObfReferenceObject(ExceptionPort);
//		ExReleasePushLockShared(&Process->ProcessLock,0);
//		KeLeaveCriticalRegion();
//	}
//
//	return ExceptionPort;
//}



BOOLEAN(*OriginalDbgkForwardException)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance);
BOOLEAN  DbgkForwardException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance)
{
	NTSTATUS		st;
	PEPROCESS_S		Process;
	PVOID			ExceptionPort;
	PDEBUG_OBJECT	DebugObject;
	BOOLEAN			bLpcPort;

	DBGKM_APIMSG m;
	PDBGKM_EXCEPTION args;

	DebugObject = NULL;
	ExceptionPort = NULL;
	bLpcPort = FALSE;

	args = &m.u.Exception;
	m.h.u1.Length = 0xD000A8;
	m.h.u2.ZeroInit = 8;
	m.ApiNumber = DbgKmExceptionApi;

	Process = (PEPROCESS_S)PsGetCurrentProcess();

	if (DebugException == TRUE)
	{
		DebugObject = (PDEBUG_OBJECT)Process->DebugPort;
	}
	else
	{
		ExceptionPort = PsCaptureExceptionPort(Process);
		m.h.u2.ZeroInit = 0x7;
		bLpcPort = TRUE;
	}

	if ((ExceptionPort == NULL && DebugObject == NULL) &&
		DebugException == TRUE)
	{
		return FALSE;
	}

	args->ExceptionRecord = *ExceptionRecord;
	args->FirstChance = !SecondChance;

	if (bLpcPort == FALSE)
	{
		st = DbgkpSendApiMessage(DebugException, &m);
	}
	else if (ExceptionPort) {

		st = DbgkpSendApiMessageLpc(&m, ExceptionPort, DebugException);
		ObfDereferenceObject(ExceptionPort);
	}
	else {
		m.ReturnedStatus = DBG_EXCEPTION_NOT_HANDLED;
		st = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(st))
	{

		st = m.ReturnedStatus;

		if (m.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED)
		{
			if (DebugException == TRUE)
			{
				return FALSE;
			}

			st = DbgkpSendErrorMessage(ExceptionRecord, 0, &m);
		}


	}

	return NT_SUCCESS(st);
}

BOOLEAN DbgkpSuppressDbgMsg(
	IN PTEB Teb)
{
	BOOLEAN bSuppress;
	_try{
		bSuppress = Teb->SuppressDebugMsg;
	}_except(EXCEPTION_EXECUTE_HANDLER) {
		bSuppress = FALSE;
	}
	return bSuppress;
};


VOID(*OriginalDbgkMapViewOfSection)(
	IN PEPROCESS_S	Process,
	IN PVOID SectionObject,
	IN PVOID BaseAddress

	);
VOID DbgkMapViewOfSection(
	IN PEPROCESS_S	Process,
	IN PVOID SectionObject,
	IN PVOID BaseAddress

)
{

	PTEB	Teb;
	HANDLE	hFile;
	DBGKM_APIMSG ApiMsg;
	PEPROCESS_S	CurrentProcess;
	PETHREAD_S	CurrentThread;
	PIMAGE_NT_HEADERS	pImageHeader;

	hFile = NULL;
	CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if (ExGetPreviousMode() == KernelMode || Process->DebugPort == NULL)
	{
		return;
	}
	if (CurrentThread->Tcb.SystemThread != TRUE && CurrentThread->Tcb.ApcStateIndex != 0x1)
	{
		Teb = (PTEB)CurrentThread->Tcb.Teb;
	}
	else
	{
		Teb = NULL;
	}

	if (Teb != NULL && Process == CurrentProcess)
	{
		if (!DbgkpSuppressDbgMsg(Teb))
		{
			ApiMsg.u.LoadDll.NamePointer = Teb->NtTib.ArbitraryUserPointer;
		}
		else {
			//暂停调试消息的话就退出
			return;
		}
	}
	else {
		ApiMsg.u.LoadDll.NamePointer = NULL;
	}

	hFile = DbgkpSectionToFileHandle(SectionObject);
	ApiMsg.u.LoadDll.FileHandle = hFile;
	ApiMsg.u.LoadDll.BaseOfDll = BaseAddress;
	ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
	ApiMsg.u.LoadDll.DebugInfoSize = 0;

	_try{
		pImageHeader = RtlImageNtHeader(BaseAddress);
		if (pImageHeader != NULL)
		{
			ApiMsg.u.LoadDll.DebugInfoFileOffset = pImageHeader->FileHeader.PointerToSymbolTable;
			ApiMsg.u.LoadDll.DebugInfoSize = pImageHeader->FileHeader.NumberOfSymbols;
		}
	}_except(EXCEPTION_EXECUTE_HANDLER) {
		ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
		ApiMsg.u.LoadDll.DebugInfoSize = 0;
		ApiMsg.u.LoadDll.NamePointer = NULL;
	}
	ApiMsg.h.u1.Length = 0x500028;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmLoadDllApi;

	DbgkpSendApiMessage(0x1, &ApiMsg);

	if (ApiMsg.u.LoadDll.FileHandle != NULL)
	{
		ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
	}
}


VOID(*OriginalDbgkUnMapViewOfSection)(
	IN PEPROCESS_S	Process,
	IN PVOID	BaseAddress);
VOID DbgkUnMapViewOfSection(
	IN PEPROCESS_S	Process,
	IN PVOID	BaseAddress)
{
	PTEB	Teb;
	DBGKM_APIMSG ApiMsg;
	PEPROCESS_S	CurrentProcess;
	PETHREAD_S	CurrentThread;

	CurrentProcess = (PEPROCESS_S)PsGetCurrentProcess();
	CurrentThread = (PETHREAD_S)PsGetCurrentThread();

	if (ExGetPreviousMode() == KernelMode || Process->DebugPort == NULL)
	{
		return;
	}
	if (CurrentThread->Tcb.SystemThread != TRUE && CurrentThread->Tcb.ApcStateIndex != 0x1)
	{
		Teb = (PTEB)CurrentThread->Tcb.Teb;
	}
	else
	{
		Teb = NULL;
	}

	if (Teb != NULL && Process == CurrentProcess)
	{
		if (DbgkpSuppressDbgMsg(Teb))
		{
			return;
		}
	}
	ApiMsg.u.UnloadDll.BaseAddress = BaseAddress;
	ApiMsg.h.u1.Length = 0x380010;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmUnloadDllApi;
	DbgkpSendApiMessage(0x1, &ApiMsg);
}

#include "DRRWE.h"
#include "Txoo.h"

//初始化数据
BOOLEAN CKernelDbg::IniteKernelDbg()
{
	//初始化自建变量
	ExInitializeFastMutex(&g_DbgkpProcessDebugPortMutex);
	ExInitializePushLock((PULONG_PTR)&MiChangeControlAreaFileLock);

	InitListAndLock();
	InitialzeDbgprocessList();

	//获取函数地址
	DbgkpSendApiMessageLpc = (DBGKPSENDAPIMESSAGELPC)g_SymbolsData.DbgkpSendApiMessageLpc;
	DbgkpSendErrorMessage = (DBGKPSENDERRORMESSAGE)g_SymbolsData.DbgkpSendErrorMessage;
	DbgkSendSystemDllMessages = (pfDbgkSendSystemDllMessages)g_SymbolsData.DbgkSendSystemDllMessages;
	DbgkpPostFakeThreadMessages = (DbgkpPostFakeThreadMessagesx)g_SymbolsData.DbgkpPostFakeThreadMessages;
	DbgkpPostFakeProcessCreateMessages = (pfDbgkpPostFakeProcessCreateMessages)g_SymbolsData.DbgkpPostFakeProcessCreateMessages;
	DbgkpSetProcessDebugObject = (pfDbgkpSetProcessDebugObject)g_SymbolsData.DbgkpSetProcessDebugObject;
	originalDbgkpMarkProcessPeb = (pfnDbgkpMarkProcessPeb)g_SymbolsData.DbgkpMarkProcessPeb;
	KeResumeThread = (KERESUMETHREAD)g_SymbolsData.KeResumeThread;
	DbgkpPostModuleMessages = (DbgkpPostModuleMessagesx)g_SymbolsData.DbgkpPostModuleMessages;////
	PsGetNextProcessThread = (PsGetNextProcessThreadx)g_SymbolsData.PsGetNextProcessThread;
	PsQuerySystemDllInfo = (pfPsQuerySystemDllInfo)g_SymbolsData.PsQuerySystemDllInfo;
	//ExAcquireRundownProtection_0 = (pfExAcquireRundownProtection_0)g_SymbolsData.ExAcquireRundownProtection_0;
	//DbgkpWakeTarget_2 = (PfDbgkpFreeDebugEvent)g_SymbolsData.DbgkpFreeDebugEvent;
	DbgkpWakeTarget_2 = (pfDbgkpWakeTarget)g_SymbolsData.DbgkpWakeTarget;
	ObDuplicateObject = (ObDuplicateObject1)g_SymbolsData.ObDuplicateObject;
	PsSuspendThread = (PsSuspendThreadx)g_SymbolsData.PsSuspendThread;
	PsResumeThread = (PsResumeThreadx)g_SymbolsData.PsResumeThread;
	PsSynchronizeWithThreadInsertion = (pfnPsSynchronizeWithThreadInsertion)g_SymbolsData.PsSynchronizeWithThreadInsertion;
	PsCallImageNotifyRoutines = (PSCALLIMAGENOTIFYROUTINES)g_SymbolsData.PsCallImageNotifyRoutines;
	ObFastReferenceObject = (OBFASTREFERENCEOBJECT)g_SymbolsData.ObFastReferenceObject;
	ObFastReferenceObjectLocked = (OBFASTREFERENCEOBJECTLOCKED)g_SymbolsData.ObFastReferenceObjectLocked;
	ObFastDereferenceObject = (OBFASTDEREFERENCEOBJECT)g_SymbolsData.ObFastDereferenceObject;
	KiCheckForKernelApcDelivery = (KICHECKFORKERNELAPCDELIVERY)g_SymbolsData.KiCheckForKernelApcDelivery;
	KeFreezeAllThreads = (KEFREEZEALLTHREADS)g_SymbolsData.KeFreezeAllThreads;
	KeThawAllThreads = (KETHAWALLTHREADS)g_SymbolsData.KeThawAllThreads;
	PsThawProcess = (pfPsThawProcess)g_SymbolsData.PsThawProcess;
	PsFreezeProcess = (pfPsFreezeProcess)g_SymbolsData.PsFreezeProcess;
	ZwFlushInstructionCache = (ZWFLUSHINSTRUCTIONCACHE)g_SymbolsData.ZwFlushInstructionCache;
	MmGetFileNameForSection = (MmGetFileNameForSectionx)g_SymbolsData.MmGetFileNameForSection;

	PsTestProtectedProcessIncompatibility = (pfPsTestProtectedProcessIncompatibility)g_SymbolsData.PsTestProtectedProcessIncompatibility;
	PsRequestDebugSecureProcess = (pfPsRequestDebugSecureProcess)g_SymbolsData.PsRequestDebugSecureProcess;
	LpcRequestWaitReplyPortEx = (pfLpcRequestWaitReplyPortEx)g_SymbolsData.LpcRequestWaitReplyPortEx;
	DbgkpSuspendProcess = (pfDbgkpSuspendProcess)g_SymbolsData.DdbgkpSuspendProcess;

	if (!DbgkpSendApiMessageLpc)
	{
		LogError("get DbgkpSendApiMessageLpc failed");
	}
	if (!DbgkpSendErrorMessage)
	{
		LogError("get DbgkpSendErrorMessage failed");
	}
	if (!DbgkpSendApiMessageLpc || !DbgkpSendErrorMessage ||
		!KeResumeThread || !DbgkpPostModuleMessages || !ObDuplicateObject || !PsSuspendThread ||
		!PsCallImageNotifyRoutines || !ObFastReferenceObject || !ObFastReferenceObjectLocked ||
		!ObFastDereferenceObject || !KiCheckForKernelApcDelivery || !KeFreezeAllThreads ||
		!KeThawAllThreads || !ZwFlushInstructionCache)
	{
		LogError("get unexport function failed");
		return FALSE;
	}

	//获取系统全局变量
	PspNotifyEnableMask = g_SymbolsData.PspNotifyEnableMask;
	if (!HookDbgkDebugObjectType())
	{
		LogError("HookDbgkDebugObjectType failed");
		return FALSE;
	}

	int iret = initDbgk();
	if (iret != 0)//初始化dbgkrnl系统数据
	{
		LogError("initDbgk failed:%d", iret);
		return FALSE;
	}

	return TRUE;
}

//Hook
BOOLEAN SetDebugPort(ULONG DebugPortOffset, BOOLEAN IsHook)
{
	if (IsHook)
	{
		KIRQL Irql = WPOFFx64();
		__try
		{
			//KiDispatchException
			*(PULONG)((ULONG_PTR)g_SymbolsData.KiDispatchException + 0x23C) = DebugPortOffset;
			//PspExitThread
			*(PULONG)((ULONG_PTR)g_SymbolsData.PspExitThread + 0x15A) = DebugPortOffset;
			//PspTerminateAllThreads
			*(PULONG)((ULONG_PTR)g_SymbolsData.PspTerminateAllThreads + 0x13B) = DebugPortOffset;
			//PspProcessDelete
			*(PULONG)((ULONG_PTR)g_SymbolsData.PspProcessDelete + 0xE3) = DebugPortOffset;
			//PspExitThread先设置ExitTime，导致ExitTime有值，使得PspProcessDelete判断有值然后释放debugport计数导致蓝屏,所以把PspExitThread里设置ExitTime改为设置CreateTime的偏移
			*(PULONG)((ULONG_PTR)g_SymbolsData.PspExitThread + 0x4DA) = 0x168;

		}_except(1)
		{
			return FALSE;
		}
		WPONx64(Irql);
	}
	else
	{
		KIRQL Irql = WPOFFx64();
		__try
		{
			//KiDispatchException
			*(PULONG)((ULONG_PTR)g_SymbolsData.KiDispatchException + 0x23C) = DebugPortOffset;
			//PspExitThread
			*(PULONG)((ULONG_PTR)g_SymbolsData.PspExitThread + 0x15A) = DebugPortOffset;
			//PspTerminateAllThreads
			*(PULONG)((ULONG_PTR)g_SymbolsData.PspTerminateAllThreads + 0x13B) = DebugPortOffset;
			//PspProcessDelete
			*(PULONG)((ULONG_PTR)g_SymbolsData.PspProcessDelete + 0xE3) = DebugPortOffset;
			//PspExitThread 恢复设置ExitTime的到CreateTime地方
			*(PULONG)((ULONG_PTR)g_SymbolsData.PspExitThread + 0x4DA) = 0x170;

		}_except(1)
		{
			return FALSE;
		}
		WPONx64(Irql);
	}

	return TRUE;
}

NTSTATUS
(*OriginalDbgkOpenProcessDebugPort)(IN PEPROCESS_S Process,
	IN KPROCESSOR_MODE PreviousMode,
	OUT HANDLE* DebugHandle);

#include "Log.h"
#include "Ssdt.h"
#include "HookHelper.h"
#include "HypervisorGateway.h"
BOOLEAN CKernelDbg::StartKernelDbg()
{
    BOOLEAN boole = TRUE;
	//初始化调试相关数据、函数地址
	if (!IniteKernelDbg())
	{
		LogError("IniteKernelDbg failed");
		return FALSE;
	}
	LogInfo("IniteKernelDbg ok");

	NT_SYSCALL_NUMBERS SyscallNumbers;
	GetNtSyscallNumbers(SyscallNumbers);

	if (SSDT::HookNtSyscall(SyscallNumbers.NtCreateDebugObject, proxyNtCreateDebugObject, (PVOID*)&OriginalNtCreateDebugObject) == FALSE)
	{
		LogError("NtCreateDebugObject hook failed");
		return FALSE;
	}

	if (SSDT::HookNtSyscall(SyscallNumbers.NtDebugContinue, proxyNtDebugContinue, (PVOID*)&originalNtDebugContinue) == FALSE)
	{
		LogError("NtDebugContinue hook failed");
		return FALSE;
	}
	if (SSDT::HookNtSyscall(SyscallNumbers.NtRemoveProcessDebug, proxyNtRemoveProcessDebug, (PVOID*)&OriginalNtRemoveProcessDebug) == FALSE)
	{
		LogError("NtRemoveProcessDebug hook failed");
		return FALSE;
	}
	
	if (!hv::hook_function(g_SymbolsData.DbgkOpenProcessDebugPort, proxyDbgkOpenProcessDebugPort, (PVOID*)&OriginalDbgkOpenProcessDebugPort))//不能退出调试
	{
		LogError("DbgkExitProcess hook failed");
		return FALSE;
	}
	if (!hv::hook_function(g_SymbolsData.DbgkCopyProcessDebugPort, proxyDbgkCopyProcessDebugPort, (PVOID*)&OriginalDbgkCopyProcessDebugPort))//不能退出调试
	{
		LogError("DbgkCopyProcessDebugPort hook failed");
		return FALSE;
	}
	if (!hv::hook_function(g_SymbolsData.DbgkMapViewOfSection, proxyDbgkMapViewOfSection, (PVOID*)&OriginalDbgkMapViewOfSection))//FIX
	{
		LogError("DbgkMapViewOfSection hook failed");
		return FALSE;
	}
	if (!hv::hook_function(g_SymbolsData.DbgkUnMapViewOfSection, proxyDbgkUnMapViewOfSection, (PVOID*)&OriginalDbgkUnMapViewOfSection))//FIX
	{
		LogError("DbgkMapViewOfSection hook failed");
		return FALSE;
	}
	if (!hv::hook_function(g_SymbolsData.DbgkExitProcess, proxyDbgkExitProcess, (PVOID*)&originalproxyDbgkExitProcess))
	{
		LogError("DbgkExitProcess hook failed");
		return FALSE;
	}
	if (!hv::hook_function(g_SymbolsData.DbgkExitThread, &proxyDbgkExitThread, (PVOID*)&OriginalDbgkExitThread))
	{
		boole = FALSE;
		return FALSE;
	}
	//if (!hv::hook_function(g_SymbolsData.PspExitThread, &proxyPspExitThread, (PVOID*)&originalproxyPspExitThread))
	//{
	//	boole = FALSE;
	//	return FALSE;
	//}
	if (!hv::hook_function(g_SymbolsData.DbgkForwardException, proxyDbgkForwardException, (PVOID*)&OriginalDbgkForwardException))
	{
		LogError("DbgkForwardException hook failed");
		return FALSE;
	}


	if (!hv::hook_function(g_SymbolsData.DbgkpSetProcessDebugObject, DbgkpSetProcessDebugObject_2, (PVOID*)&originalDbgkpSetProcessDebugObject))
	{
		LogError("DbgkExitProcess hook failed");
		return FALSE;
	}
	if (!hv::hook_function(g_SymbolsData.DbgkpPostFakeThreadMessages, DbgkpPostFakeThreadMessages_2, (PVOID*)&originalDbgkpPostFakeThreadMessages))
	{
		LogError("DbgkMapViewOfSection hook failed");
		return FALSE;
	}

	if (!hv::hook_function(g_SymbolsData.DbgkpQueueMessage, DbgkpQueueMessage_2, (PVOID*)&OriginalDbgkpQueueMessage))
	{
		LogError("DbgkExitProcess hook failed");
		return FALSE;
	}

	return boole;
}

/**/
void CKernelDbg::StopKernelDbg()
{
	NT_SYSCALL_NUMBERS SyscallNumbers;
	GetNtSyscallNumbers(SyscallNumbers);

	hv::unhook_function((unsigned long long)SyscallNumbers.NtDebugActiveProcess);
	hv::unhook_function((unsigned long long)SyscallNumbers.NtCreateDebugObject);
	hv::unhook_function((unsigned long long)SyscallNumbers.NtRemoveProcessDebug);
	hv::unhook_function((unsigned long long)SyscallNumbers.NtWaitForDebugEvent);
	hv::unhook_function((unsigned long long)SyscallNumbers.NtDebugContinue);


	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkExitProcess);
	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkExitThread);
	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkCopyProcessDebugPort);
	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkForwardException);
	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkMapViewOfSection);
	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkUnMapViewOfSection);
	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkClearProcessDebugObject);
	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkpQueueMessage);
	hv::unhook_function((unsigned long long)g_SymbolsData.DbgkCreateThread);

	return;
}


