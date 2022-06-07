#pragma once
#include <ntddk.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemExtendedProcessInformation = 6,
    SystemProcessorPerformanceInformation = 8,
    SystemModuleInformation = 11,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemKernelDebuggerInformation = 35,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemFullProcessInformation = 148
} SYSTEM_INFORMATION_CLASS;

extern "C" 
{
    NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation
    (
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
}

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE {
    PVOID 	Reserved1;
    PVOID 	Reserved2;
    PVOID 	ImageBaseAddress;
    ULONG 	ImageSize;
    ULONG 	Flags;
    unsigned short 	Id;
    unsigned short 	Rank;
    unsigned short 	Unknown;
    unsigned short 	NameOffset;
    unsigned char 	Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG                       ModulesCount;
    SYSTEM_MODULE_ENTRY         Modules[1];
    ULONG                       Count;
    SYSTEM_MODULE 	            Sys_Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;