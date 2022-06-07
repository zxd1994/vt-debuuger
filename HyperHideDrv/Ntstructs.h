#pragma once
#ifndef _NTSTRUCT_H
#define _NTSTRUCT_H

#ifndef _NTIFS_H
#define _NTIFS_H
#include <ntifs.h>
#endif // !_NTIFS_H

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;                                         //0x0
    VOID* Handle;                                                           //0x10
}CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;                                                           //0x0
    USHORT Length;                                                          //0x2
    ULONG TimeStamp;                                                        //0x4
    STRING DosPath;                                                 //0x8
}RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                                                    //0x0
    ULONG Length;                                                           //0x4
    ULONG Flags;                                                            //0x8
    ULONG DebugFlags;                                                       //0xc
    VOID* ConsoleHandle;                                                    //0x10
    ULONG ConsoleFlags;                                                     //0x18
    VOID* StandardInput;                                                    //0x20
    VOID* StandardOutput;                                                   //0x28
    VOID* StandardError;                                                    //0x30
    CURDIR CurrentDirectory;                                        //0x38
    UNICODE_STRING DllPath;                                         //0x50
    UNICODE_STRING ImagePathName;                                   //0x60
    UNICODE_STRING CommandLine;                                     //0x70
    VOID* Environment;                                                      //0x80
    ULONG StartingX;                                                        //0x88
    ULONG StartingY;                                                        //0x8c
    ULONG CountX;                                                           //0x90
    ULONG CountY;                                                           //0x94
    ULONG CountCharsX;                                                      //0x98
    ULONG CountCharsY;                                                      //0x9c
    ULONG FillAttribute;                                                    //0xa0
    ULONG WindowFlags;                                                      //0xa4
    ULONG ShowWindowFlags;                                                  //0xa8
    UNICODE_STRING WindowTitle;                                     //0xb0
    UNICODE_STRING DesktopInfo;                                     //0xc0
    UNICODE_STRING ShellInfo;                                       //0xd0
    UNICODE_STRING RuntimeData;                                     //0xe0
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
    ULONGLONG EnvironmentSize;                                              //0x3f0
    ULONGLONG EnvironmentVersion;                                           //0x3f8
    VOID* PackageDependencyData;                                            //0x400
    ULONG ProcessGroupId;                                                   //0x408
    ULONG LoaderThreads;                                                    //0x40c
    UNICODE_STRING RedirectionDllName;                              //0x410
    UNICODE_STRING HeapPartitionName;                               //0x420
    ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
    ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _OBJECT_HANDLE_ATTRIBUTE_INFORMATION
{
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
}OBJECT_HANDLE_ATTRIBUTE_INFORMATION, * POBJECT_HANDLE_ATTRIBUTE_INFORMATION;

typedef struct _JOBOBJECT_BASIC_PROCESS_ID_LIST {
    ULONG NumberOfAssignedProcesses;
    ULONG NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[1];
} JOBOBJECT_BASIC_PROCESS_ID_LIST, * PJOBOBJECT_BASIC_PROCESS_ID_LIST;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG Reserved[40];
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
}SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
{
    BOOLEAN DebuggerAllowed;
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerPresent;
}SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
}SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer;
}SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _WOW64_FLOATING_SAVE_AREA
{
    ULONG ControlWord;
    ULONG StatusWord;
    ULONG TagWord;
    ULONG ErrorOffset;
    ULONG ErrorSelector;
    ULONG DataOffset;
    ULONG DataSelector;
    UCHAR RegisterArea[80];
    ULONG Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA, * PWOW64_FLOATING_SAVE_AREA;

typedef struct _WOW64_CONTEXT
{
    ULONG ContextFlags;

    ULONG Dr0;
    ULONG Dr1;
    ULONG Dr2;
    ULONG Dr3;
    ULONG Dr6;
    ULONG Dr7;

    WOW64_FLOATING_SAVE_AREA FloatSave;

    ULONG SegGs;
    ULONG SegFs;
    ULONG SegEs;
    ULONG SegDs;

    ULONG Edi;
    ULONG Esi;
    ULONG Ebx;
    ULONG Edx;
    ULONG Ecx;
    ULONG Eax;

    ULONG Ebp;
    ULONG Eip;
    ULONG SegCs;
    ULONG EFlags;
    ULONG Esp;
    ULONG SegSs;

    UCHAR ExtendedRegisters[512];

} WOW64_CONTEXT, * PWOW64_CONTEXT;

typedef struct _OBJECT_ALL_INFORMATION
{
    ULONG                   NumberOfObjectsTypes;
    OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;

typedef struct _SYSTEM_THREAD_INFO
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    ULONG_PTR PeakVirtualSize;
    ULONG_PTR VirtualSize;
    ULONG PageFaultCount;
    ULONG_PTR PeakWorkingSetSize;
    ULONG_PTR WorkingSetSize;
    ULONG_PTR QuotaPeakPagedPoolUsage;
    ULONG_PTR QuotaPagedPoolUsage;
    ULONG_PTR QuotaPeakNonPagedPoolUsage;
    ULONG_PTR QuotaNonPagedPoolUsage;
    ULONG_PTR PagefileUsage;
    ULONG_PTR PeakPagefileUsage;
    ULONG_PTR PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;



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

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

#ifndef _LDR_DATA_TABLE_ENTRY_
#define _LDR_DATA_TABLE_ENTRY_
typedef struct _LDR_DATA_TABLE_ENTRY                         // 24 elements, 0xE0 bytes (sizeof)
{
    /*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
    /*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
    /*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
    /*0x030*/     VOID* DllBase;
    /*0x038*/     VOID* EntryPoint;
    /*0x040*/     ULONG32      SizeOfImage;
    /*0x044*/     UINT8        _PADDING0_[0x4];
    /*0x048*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
    /*0x058*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
    /*0x068*/     ULONG32      Flags;
    /*0x06C*/     UINT16       LoadCount;
    /*0x06E*/     UINT16       TlsIndex;
    union                                                    // 2 elements, 0x10 bytes (sizeof)
    {
        /*0x070*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x10 bytes (sizeof)
        struct                                               // 2 elements, 0x10 bytes (sizeof)
        {
            /*0x070*/             VOID* SectionPointer;
            /*0x078*/             ULONG32      CheckSum;
            /*0x07C*/             UINT8        _PADDING1_[0x4];
        };
    };
    union                                                    // 2 elements, 0x8 bytes (sizeof)
    {
        /*0x080*/         ULONG32      TimeDateStamp;
        /*0x080*/         VOID* LoadedImports;
    };
    /*0x088*/     ULONG64 EntryPointActivationContext;
    /*0x090*/     VOID* PatchInformation;
    /*0x098*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x10 bytes (sizeof)
    /*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x10 bytes (sizeof)
    /*0x0B8*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x10 bytes (sizeof)
    /*0x0C8*/     VOID* ContextInformation;
    /*0x0D0*/     UINT64       OriginalBase;
    /*0x0D8*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#endif _LDR_DATA_TABLE_ENTRY_



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

/*
struct _EX_FAST_REF
{
    union
    {
        VOID* Object;                                                       //0x0
        ULONGLONG RefCnt : 4;                                                 //0x0
        ULONGLONG Value;                                                    //0x0
    };
};
*/
#endif // !_NTSTRUCT_H


