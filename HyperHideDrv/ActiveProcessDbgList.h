#include <ntifs.h>

typedef struct _DbgPortList{
	LIST_ENTRY PortList;
	ULONG64 DbgPort;
	UINT8 markdbg;
	PEPROCESS Process;
}DbgPortList, *PDbgPortList;
VOID InitDbgPortList();
PDbgPortList Port_FindProcessList(PEPROCESS Process, ULONG64 DbgPort);
PDbgPortList Port_AddProcessToList(PEPROCESS Process, ULONG64 DbgPort);
VOID NTAPI Port_ExFreeItem(PDbgPortList Item);
BOOLEAN Port_SetPort(PEPROCESS Process, ULONG64 DbgPort);
BOOLEAN Port_IsPort(PEPROCESS Process);
ULONG64 Port_GetPort(PEPROCESS Process);
BOOLEAN Port_RemoveDbgItem(PEPROCESS Process, ULONG64 DbgPort);