#include <ntifs.h>

//typedef  LONG DWORD;
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

#define HIDWORD(a) ((DWORD)((UINT64)(a) >> 32))
#define LODWORD(a) ((DWORD)((UINT64)(a)& 0x0000ffff))
typedef struct _PROCESS_List{
	LIST_ENTRY PorcessList;
	PEPROCESS Process;
	KSPIN_LOCK loacl_lock;
	LIST_ENTRY ThreadList;
}PROCESS_List, *PPROCESS_List;
EXTERN_C VOID InitListAndLock();
PPROCESS_List Dr_FindProcessList(PEPROCESS Process);
PPROCESS_List Dr_AddProcessToList(PEPROCESS Process);
VOID NTAPI Dr_ExFreeItem(PPROCESS_List Item);
PTHREAD_dr_List Dr_AddThreadStructToList(PPROCESS_List DrRwListItem, PTHREAD_dr_List Struct);
VOID NTAPI Dr_ExFreeTheadListItem(PPROCESS_List DrRwListItem, PTHREAD_dr_List Struct);
PTHREAD_dr_List Dr_FindThreadContextByThreadList(PPROCESS_List DrRwListItem, PETHREAD Thread);
PTHREAD_dr_List Dr_UpdataThreadContextByThreadList(PPROCESS_List DrRwListItem, PETHREAD Thread, PTHREAD_dr_List UpData);
