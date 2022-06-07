#pragma once
#include <Windows.h>
#include <ImageHlp.h>
#include "CSymbols.h"


typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)
(
    IN ULONG	SystemInformationClass,
    OUT PVOID	SystemInformation,
    IN ULONG	Length,
    OUT PULONG	ReturnLength
    );

typedef unsigned long DWORD;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    ULONG Unknow1;
    ULONG Unknow2;
    ULONG Unknow3;
    ULONG Unknow4;
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;//内核中以加载的模块的个数
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
