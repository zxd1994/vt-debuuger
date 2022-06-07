#include "ntddk.h"
typedef  LONG DWORD;
typedef struct _THREAD_dr_List{
	LIST_ENTRY TList;
	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;
	DWORD  eflag;
	PETHREAD Thread;

}THREAD_dr_List, *PTHREAD_dr_List;


typedef struct _PROCESS_List{
	LIST_ENTRY PorcessList;
	PEPROCESS Process;
	KSPIN_LOCK loacl_lock;
	LIST_ENTRY ThreadList;
}PROCESS_List, *PPROCESS_List;

static KSPIN_LOCK g_lock;
static LIST_ENTRY DrRwList;
VOID InitListAndLock(){
	InitializeListHead(&DrRwList);
	KeInitializeSpinLock(&g_lock);
}

PPROCESS_List Dr_FindProcessList(PEPROCESS Process){
	KIRQL OldIrql;
	PLIST_ENTRY Entry;
	PROCESS_List *TempItem = NULL;
	PROCESS_List* DFind = NULL;
	KeAcquireSpinLock(&g_lock, &OldIrql);
	Entry = DrRwList.Flink;
	while (Entry!=&DrRwList)
	{
		TempItem = CONTAINING_RECORD(Entry, PROCESS_List, PorcessList);
	
		Entry = Entry->Flink;
		if (TempItem->Process==Process)
		{
			DFind = TempItem;
			break;
		}
	}
	KeReleaseSpinLock(&g_lock, OldIrql);
	return DFind;
}

PPROCESS_List Dr_AddProcessToList(PEPROCESS Process){
	PPROCESS_List TempItem;
	TempItem = (PPROCESS_List)ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_List), 'drrp');
	if (!TempItem)
	{
		return FALSE;
	}

	RtlZeroMemory(TempItem, sizeof(PROCESS_List));
	TempItem->Process = Process;
	InitializeListHead(&TempItem->ThreadList);
	KeInitializeSpinLock(&TempItem->loacl_lock);
	ExInterlockedInsertTailList(&DrRwList,&TempItem->PorcessList,&g_lock);
	if (TempItem != NULL)
	{

		return TempItem;
	}

	return FALSE;
}

VOID NTAPI Dr_ExFreeItem(PPROCESS_List Item)
{
	KIRQL OldIrql;
	KeAcquireSpinLock(&g_lock, &OldIrql);
	RemoveEntryList(&Item->PorcessList);
	KeReleaseSpinLock(&g_lock, OldIrql);
	ExFreePool(Item);
	return;


}

PTHREAD_dr_List Dr_AddThreadStructToList(PPROCESS_List DrRwListItem, PTHREAD_dr_List Struct){

	PTHREAD_dr_List TempItem;
	TempItem = (PTHREAD_dr_List)ExAllocatePoolWithTag(NonPagedPool, sizeof(THREAD_dr_List), 'drrt');
	if (!TempItem)
	{
		return FALSE;
	}
	RtlZeroMemory(TempItem, sizeof(THREAD_dr_List));


	TempItem->Dr0 = Struct->Dr0;
	TempItem->Dr1 = Struct->Dr1;
	TempItem->Dr2 = Struct->Dr2;
	TempItem->Dr3 = Struct->Dr3;
	TempItem->Dr6 = Struct->Dr6;
	TempItem->Dr7 = Struct->Dr7;
	TempItem->eflag = Struct->eflag;

	TempItem->Thread = Struct->Thread;


	
	ExInterlockedInsertTailList(&DrRwListItem->ThreadList, &TempItem->TList, &DrRwListItem->loacl_lock);
	if (TempItem != NULL)
	{

		return TempItem;
	}
}

PTHREAD_dr_List Dr_FindThreadContextByThreadList(PPROCESS_List DrRwListItem, PETHREAD Thread){
	KIRQL OldIrql;
	PLIST_ENTRY Entry;
	THREAD_dr_List *TempItem = NULL;
	THREAD_dr_List* DFind = NULL;
	KeAcquireSpinLock(&DrRwListItem->loacl_lock, &OldIrql);
	Entry = DrRwListItem->ThreadList.Flink;
	while (Entry != &DrRwListItem->ThreadList)
	{
		TempItem = CONTAINING_RECORD(Entry, THREAD_dr_List, TList);
		
		Entry = Entry->Flink;
		if (TempItem->Thread == Thread)
		{
			DFind = TempItem;
			break;
		}
	}

	KeReleaseSpinLock(&DrRwListItem->loacl_lock, OldIrql);

	return DFind;

}


PTHREAD_dr_List Dr_UpdataThreadContextByThreadList(PPROCESS_List DrRwListItem, PETHREAD Thread, PTHREAD_dr_List UpData){
	KIRQL OldIrql;
	PLIST_ENTRY Entry;
	THREAD_dr_List *TempItem = NULL;
	THREAD_dr_List* DFind = NULL;
	KeAcquireSpinLock(&DrRwListItem->loacl_lock, &OldIrql);
	Entry = DrRwListItem->ThreadList.Flink;
	while (Entry != &DrRwListItem->ThreadList)
	{
		TempItem = CONTAINING_RECORD(Entry, THREAD_dr_List, TList);
	
		Entry = Entry->Flink;
		if (TempItem->Thread == Thread)
		{
			
			DFind = TempItem;
			DFind->Dr0 = UpData->Dr0;
			DFind->Dr1 = UpData->Dr1;
			DFind->Dr2 = UpData->Dr2;
			DFind->Dr3 = UpData->Dr3;
			DFind->Dr6 = UpData->Dr6;
			DFind->Dr7 = UpData->Dr7;
			DFind->eflag = UpData->eflag;
			

			break;
		}
	}

	KeReleaseSpinLock(&DrRwListItem->loacl_lock, OldIrql);

	return DFind;

}


VOID NTAPI Dr_ExFreeTheadListItem(PPROCESS_List DrRwListItem, PTHREAD_dr_List Struct)
{
	KIRQL OldIrql;
	KeAcquireSpinLock(&DrRwListItem->loacl_lock, &OldIrql);

	RemoveEntryList(&Struct->TList);
	KeReleaseSpinLock(&DrRwListItem->loacl_lock, OldIrql);
	ExFreePool(Struct);
	return;


}
