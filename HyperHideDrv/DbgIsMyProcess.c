#include "ntddk.h"

typedef struct _DbgProcess
{
	LIST_ENTRY64 DbgProcessList;
	PEPROCESS DebugProcess;
	PEPROCESS Process;
	POBJECT_TYPE DebugObject;
	HANDLE DbgHanle;
}DbgProcess, *PDbgProcess;

static LIST_ENTRY64 DbgList;
static KSPIN_LOCK d_lock;

VOID InitialzeDbgprocessList(){

	KeInitializeSpinLock(&d_lock);
	InitializeListHead(&DbgList);
}


PDbgProcess Debug_AddStructToList(PDbgProcess DbgStruct){
	PDbgProcess pstruct = NULL;
	if (MmIsAddressValid(DbgStruct)==TRUE)
	{
		pstruct = (PDbgProcess)ExAllocatePoolWithTag(NonPagedPool, sizeof(DbgProcess), "dbx");

		if (!pstruct)
		{
			return FALSE;
		}
		RtlZeroMemory(pstruct, sizeof(DbgProcess));

		pstruct->DbgHanle = DbgStruct->DbgHanle;
		pstruct->DebugObject = DbgStruct->DebugObject;
		pstruct->DebugProcess = DbgStruct->DebugProcess;
		pstruct->Process = DbgStruct->Process;
		ExInterlockedInsertTailList(&DbgList, &pstruct->DbgProcessList, &d_lock);
		return pstruct;
	}
	return FALSE;


}

VOID NTAPI Debug_ExFreeItem(PDbgProcess Item)
{
	KIRQL OldIrql;
	KeAcquireSpinLock(&d_lock, &OldIrql);
	RemoveEntryList(&Item->DbgProcessList);
	KeReleaseSpinLock(&d_lock, OldIrql);
	ExFreePool(Item);
	return;


}

PDbgProcess Debug_FindMyNeedData(PDbgProcess DbgStruct){
	DbgProcess*Temp = NULL;
	DbgProcess*RetFind = NULL;
	KIRQL irql;
	PLIST_ENTRY64 Entry = NULL;
if (MmIsAddressValid(DbgStruct)==TRUE)
{
	KeAcquireSpinLock(&d_lock, &irql);
	Entry = DbgList.Flink;
	while (Entry != &DbgList){
		Temp = CONTAINING_RECORD(Entry, DbgProcess, DbgProcessList);
		Entry= Entry->Flink;
		if (Temp->DbgHanle==DbgStruct->DbgHanle)
		{
			RetFind = Temp;
			break;
		}
		if (Temp->DebugObject == DbgStruct->DebugObject)
		{
			RetFind = Temp;
			break;
		}
		if (Temp->DebugProcess == DbgStruct->DebugProcess)
		{
			RetFind = Temp;
			break;
		}
		if (Temp->Process == DbgStruct->Process)
		{
			RetFind = Temp;
			break;
		}
		
	}


	KeReleaseSpinLock(&d_lock, irql);
}
return RetFind;

}