#include "ntddk.h"
typedef struct _DbgPortList{
	LIST_ENTRY PortList;
	ULONG64 DbgPort;
	UINT8 markdbg;
	PEPROCESS Process;
}DbgPortList, *PDbgPortList;
static LIST_ENTRY PortList ;
static KSPIN_LOCK Port_lock = NULL;
VOID InitDbgPortList(){

	InitializeListHead(&PortList);
	KeInitializeSpinLock(&Port_lock);

}
PDbgPortList Port_FindProcessList(PEPROCESS Process ,ULONG64 DbgPort){
	KIRQL OldIrql;
	PLIST_ENTRY Entry;
	DbgPortList *TempItem = NULL;
	DbgPortList* DFind = NULL;
	KeAcquireSpinLock(&Port_lock, &OldIrql);
	Entry = PortList.Flink;
	while (Entry != &PortList)
	{
		TempItem = CONTAINING_RECORD(Entry, DbgPortList, PortList);
		Entry = Entry->Flink;
		if (Process!=NULL)
		{
			//DbgPrint("Port_FindProcessList TempItem->Process:%p Process:%p\n", TempItem->Process, Process);
			if (TempItem->Process == Process)
			{
				//DbgPrint("Port_FindProcessList ok\n");
				DFind = TempItem;
				break;
			}
		}
		
		if (DbgPort != NULL)
		{
			if (TempItem->DbgPort == DbgPort)
			{
				DFind = TempItem;
				break;
			}
		}
	}
	KeReleaseSpinLock(&Port_lock, OldIrql);
	return DFind;
}

PDbgPortList Port_AddProcessToList(PEPROCESS Process,ULONG64 DbgPort){
	PDbgPortList TempItem;
	TempItem = (PDbgPortList)ExAllocatePoolWithTag(NonPagedPool, sizeof(DbgPortList), 'prrp');
	if (!TempItem)
	{
		return FALSE;
	}

	RtlZeroMemory(TempItem, sizeof(DbgPortList));
	TempItem->Process = Process;
	TempItem->DbgPort = DbgPort;
	TempItem->markdbg = FALSE;
	ExInterlockedInsertTailList(&PortList, &TempItem->PortList, &Port_lock);
	if (TempItem != NULL)
	{

		return TempItem;
	}

	return FALSE;
}
BOOLEAN Port_SetPort(PEPROCESS Process, ULONG64 DbgPort){
	PDbgPortList Temp = NULL;
	Temp=Port_AddProcessToList(Process, DbgPort);
	if (Temp != NULL){


		return TRUE;
	}
	return FALSE;
}
BOOLEAN Port_IsPort(PEPROCESS Process){
	PDbgPortList Temp = NULL;
	Temp=Port_FindProcessList(Process, NULL);
	if (Temp!=NULL)
	{
		if (Temp->DbgPort != NULL && Temp->Process == Process){

			return TRUE;
		}
	}
	return FALSE;
}
ULONG64 Port_GetPort(PEPROCESS Process){
	PDbgPortList Temp = NULL;
	Temp = Port_FindProcessList(Process, NULL);
	if (Temp != NULL)
	{
		DbgPrint("Port_GetPort:Temp != NULL\n");
		if (Temp->DbgPort != NULL && Temp->Process == Process){

			DbgPrint("Port_GetPort:%p ok\n", Temp->DbgPort);
			return Temp->DbgPort;
		}
	}
	return FALSE;
}
VOID NTAPI Port_ExFreeItem(PDbgPortList Item)
{
	DbgPrint("Port_ExFreeItem:%p\n", Item);
	KIRQL OldIrql;
	KeAcquireSpinLock(&Port_lock, &OldIrql);
	RemoveEntryList(&Item->PortList);
	KeReleaseSpinLock(&Port_lock, OldIrql);
	ExFreePool(Item);
	return;
}

BOOLEAN Port_RemoveDbgItem(PEPROCESS Process, ULONG64 DbgPort){
	
	PDbgPortList Temp = NULL;
	Temp = Port_FindProcessList(Process, DbgPort);
	if (Temp != NULL)
	{
		if (Process!=NULL)
		{
			if (Temp->Process == Process){
				Port_ExFreeItem(Temp);
				return TRUE;
			}
		}

		if (DbgPort != NULL)
		{
			if (Temp->DbgPort == DbgPort){
				Port_ExFreeItem(Temp);
				return TRUE;
			}
		}
	}
	return FALSE;

}
