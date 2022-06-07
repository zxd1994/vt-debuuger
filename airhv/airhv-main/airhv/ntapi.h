#pragma once
#include <ntddk.h>

struct __nt_kprocess
{
    DISPATCHER_HEADER Header;                                       //0x0
    LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;
};

extern "C"
{
    void NTAPI KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, PVOID Context);
    void NTAPI KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
    BOOLEAN NTAPI KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);
}