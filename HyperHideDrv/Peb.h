#pragma once

#include "Ntstructs.h"

typedef enum _SYSTEM_DLL_TYPE
{
    PsNativeSystemDll = 0,
    PsWowX86SystemDll = 1,
    PsWowArm32SystemDll = 2,
    PsWowAmd64SystemDll = 3,
    PsWowChpeX86SystemDll = 4,
    PsVsmEnclaveRuntimeDll = 5,
    PsSystemDllTotalTypes = 6
}SYSTEM_DLL_TYPE;

typedef struct _PEB_LDR_DATA32
{
    ULONG 	Length;
    BOOLEAN 	Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 	InLoadOrderModuleList;
    LIST_ENTRY32 	InMemoryOrderModuleList;
    LIST_ENTRY32 	InInitializationOrderModuleList;
    BOOLEAN 	ShutdownInProgress;
}PEB_LDR_DATA32, * PPEB_LDR_DATA32;

#ifndef _PEB_LDR_DATA_
#define _PEB_LDR_DATA_
typedef struct _PEB_LDR_DATA                            // 9 elements, 0x58 bytes (sizeof)
{
    /*0x000*/     ULONG32      Length;
    /*0x004*/     UINT8        Initialized;
    /*0x005*/     UINT8        _PADDING0_[0x3];
    /*0x008*/     VOID* SsHandle;
    /*0x010*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof)
    /*0x020*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof)
    /*0x030*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof)
    /*0x040*/     VOID* EntryInProgress;
    /*0x048*/     UINT8        ShutdownInProgress;
    /*0x049*/     UINT8        _PADDING1_[0x7];
    /*0x050*/     VOID* ShutdownThreadId;
}PEB_LDR_DATA, * PPEB_LDR_DATA;
#endif // !_PEB_LDR_DATA_

typedef struct _EWOW64PROCESS
{
    VOID* Peb;                                                              //0x0
    USHORT Machine;                                                         //0x8
    SYSTEM_DLL_TYPE NtdllType;                                        //0xc
}EWOW64PROCESS, * PEWOW64PROCESS;

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
    USHORT Type;                                                            //0x0
    USHORT CreatorBackTraceIndex;                                           //0x2
    VOID* CriticalSection;                                  //0x8
    LIST_ENTRY ProcessLocksList;                                            //0x10
    ULONG EntryCount;                                                       //0x20
    ULONG ContentionCount;                                                  //0x24
    ULONG Flags;                                                            //0x28
    USHORT CreatorBackTraceIndexHigh;                                       //0x2c
    USHORT SpareUSHORT;                                                     //0x2e
}RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG;


typedef struct _RTL_CRITICAL_SECTION
{
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;                          //0x0
    LONG LockCount;                                                         //0x8
    LONG RecursionCount;                                                    //0xc
    VOID* OwningThread;                                                     //0x10
    VOID* LockSemaphore;                                                    //0x18
    ULONGLONG SpinCount;                                                    //0x20
}RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

typedef struct _LEAP_SECOND_DATA
{
    UCHAR Enabled;                                                          //0x0
    ULONG Count;                                                            //0x4
    LARGE_INTEGER Data[1];                                           //0x8
}LEAP_SECOND_DATA, * PLEAP_SECOND_DATA;


#ifndef _LIST_ENTRY64_S_
#define _LIST_ENTRY64_S_
typedef struct _LIST_ENTRY64_S // 2 elements, 0x10 bytes (sizeof)
{
    /*0x000*/     UINT64       Flink;
    /*0x008*/     UINT64       Blink;
}LIST_ENTRY64_S, * PLIST_ENTRY64_S;
#endif // !_LIST_ENTRY64_S_

#ifndef _PEB_
#define _PEB_
typedef struct _PEB
{
    /* 0x0000 */ unsigned char InheritedAddressSpace;
    /* 0x0001 */ unsigned char ReadImageFileExecOptions;
    /* 0x0002 */ unsigned char BeingDebugged;
    union
    {
        /* 0x0003 */ unsigned char BitField;
        struct /* bitfield */
        {
            /* 0x0003 */ unsigned char ImageUsesLargePages : 1; /* bit position: 0 */
            /* 0x0003 */ unsigned char IsProtectedProcess : 1; /* bit position: 1 */
            /* 0x0003 */ unsigned char IsImageDynamicallyRelocated : 1; /* bit position: 2 */
            /* 0x0003 */ unsigned char SkipPatchingUser32Forwarders : 1; /* bit position: 3 */
            /* 0x0003 */ unsigned char IsPackagedProcess : 1; /* bit position: 4 */
            /* 0x0003 */ unsigned char IsAppContainer : 1; /* bit position: 5 */
            /* 0x0003 */ unsigned char IsProtectedProcessLight : 1; /* bit position: 6 */
            /* 0x0003 */ unsigned char IsLongPathAwareProcess : 1; /* bit position: 7 */
        }; /* bitfield */
    }; /* size: 0x0001 */
    /* 0x0004 */ unsigned char Padding0[4];
    /* 0x0008 */ void* Mutant;
    /* 0x0010 */ void* ImageBaseAddress;
    /* 0x0018 */ struct _PEB_LDR_DATA* Ldr;
    /* 0x0020 */ struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    /* 0x0028 */ void* SubSystemData;
    /* 0x0030 */ void* ProcessHeap;
    /* 0x0038 */ struct _RTL_CRITICAL_SECTION* FastPebLock;
    /* 0x0040 */ union _SLIST_HEADER* volatile AtlThunkSListPtr;
    /* 0x0048 */ void* IFEOKey;
    union
    {
        /* 0x0050 */ unsigned long CrossProcessFlags;
        struct /* bitfield */
        {
            /* 0x0050 */ unsigned long ProcessInJob : 1; /* bit position: 0 */
            /* 0x0050 */ unsigned long ProcessInitializing : 1; /* bit position: 1 */
            /* 0x0050 */ unsigned long ProcessUsingVEH : 1; /* bit position: 2 */
            /* 0x0050 */ unsigned long ProcessUsingVCH : 1; /* bit position: 3 */
            /* 0x0050 */ unsigned long ProcessUsingFTH : 1; /* bit position: 4 */
            /* 0x0050 */ unsigned long ProcessPreviouslyThrottled : 1; /* bit position: 5 */
            /* 0x0050 */ unsigned long ProcessCurrentlyThrottled : 1; /* bit position: 6 */
            /* 0x0050 */ unsigned long ProcessImagesHotPatched : 1; /* bit position: 7 */
            /* 0x0050 */ unsigned long ReservedBits0 : 24; /* bit position: 8 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x0054 */ unsigned char Padding1[4];
    union
    {
        /* 0x0058 */ void* KernelCallbackTable;
        /* 0x0058 */ void* UserSharedInfoPtr;
    }; /* size: 0x0008 */
    /* 0x0060 */ unsigned long SystemReserved;
    /* 0x0064 */ unsigned long AtlThunkSListPtr32;
    /* 0x0068 */ void* ApiSetMap;
    /* 0x0070 */ unsigned long TlsExpansionCounter;
    /* 0x0074 */ unsigned char Padding2[4];
    /* 0x0078 */ void* TlsBitmap;
    /* 0x0080 */ unsigned long TlsBitmapBits[2];
    /* 0x0088 */ void* ReadOnlySharedMemoryBase;
    /* 0x0090 */ void* SharedData;
    /* 0x0098 */ void** ReadOnlyStaticServerData;
    /* 0x00a0 */ void* AnsiCodePageData;
    /* 0x00a8 */ void* OemCodePageData;
    /* 0x00b0 */ void* UnicodeCaseTableData;
    /* 0x00b8 */ unsigned long NumberOfProcessors;
    /* 0x00bc */ unsigned long NtGlobalFlag;
    /* 0x00c0 */ union _LARGE_INTEGER CriticalSectionTimeout;
    /* 0x00c8 */ unsigned __int64 HeapSegmentReserve;
    /* 0x00d0 */ unsigned __int64 HeapSegmentCommit;
    /* 0x00d8 */ unsigned __int64 HeapDeCommitTotalFreeThreshold;
    /* 0x00e0 */ unsigned __int64 HeapDeCommitFreeBlockThreshold;
    /* 0x00e8 */ unsigned long NumberOfHeaps;
    /* 0x00ec */ unsigned long MaximumNumberOfHeaps;
    /* 0x00f0 */ void** ProcessHeaps;
    /* 0x00f8 */ void* GdiSharedHandleTable;
    /* 0x0100 */ void* ProcessStarterHelper;
    /* 0x0108 */ unsigned long GdiDCAttributeList;
    /* 0x010c */ unsigned char Padding3[4];
    /* 0x0110 */ struct _RTL_CRITICAL_SECTION* LoaderLock;
    /* 0x0118 */ unsigned long OSMajorVersion;
    /* 0x011c */ unsigned long OSMinorVersion;
    /* 0x0120 */ unsigned short OSBuildNumber;
    /* 0x0122 */ unsigned short OSCSDVersion;
    /* 0x0124 */ unsigned long OSPlatformId;
    /* 0x0128 */ unsigned long ImageSubsystem;
    /* 0x012c */ unsigned long ImageSubsystemMajorVersion;
    /* 0x0130 */ unsigned long ImageSubsystemMinorVersion;
    /* 0x0134 */ unsigned char Padding4[4];
    /* 0x0138 */ unsigned __int64 ActiveProcessAffinityMask;
    /* 0x0140 */ unsigned long GdiHandleBuffer[60];
    /* 0x0230 */ void* PostProcessInitRoutine /* function */;
    /* 0x0238 */ void* TlsExpansionBitmap;
    /* 0x0240 */ unsigned long TlsExpansionBitmapBits[32];
    /* 0x02c0 */ unsigned long SessionId;
    /* 0x02c4 */ unsigned char Padding5[4];
    /* 0x02c8 */ union _ULARGE_INTEGER AppCompatFlags;
    /* 0x02d0 */ union _ULARGE_INTEGER AppCompatFlagsUser;
    /* 0x02d8 */ void* pShimData;
    /* 0x02e0 */ void* AppCompatInfo;
    /* 0x02e8 */ struct _UNICODE_STRING CSDVersion;
    /* 0x02f8 */ const struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
    /* 0x0300 */ struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
    /* 0x0308 */ const struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
    /* 0x0310 */ struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
    /* 0x0318 */ unsigned __int64 MinimumStackCommit;
    /* 0x0320 */ void* SparePointers[4];
    /* 0x0340 */ unsigned long SpareUlongs[5];
    /* 0x0354 */ long Padding_1;
    /* 0x0358 */ void* WerRegistrationData;
    /* 0x0360 */ void* WerShipAssertPtr;
    /* 0x0368 */ void* pUnused;
    /* 0x0370 */ void* pImageHeaderHash;
    union
    {
        /* 0x0378 */ unsigned long TracingFlags;
        struct /* bitfield */
        {
            /* 0x0378 */ unsigned long HeapTracingEnabled : 1; /* bit position: 0 */
            /* 0x0378 */ unsigned long CritSecTracingEnabled : 1; /* bit position: 1 */
            /* 0x0378 */ unsigned long LibLoaderTracingEnabled : 1; /* bit position: 2 */
            /* 0x0378 */ unsigned long SpareTracingBits : 29; /* bit position: 3 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x037c */ unsigned char Padding6[4];
    /* 0x0380 */ unsigned __int64 CsrServerReadOnlySharedMemoryBase;
    /* 0x0388 */ unsigned __int64 TppWorkerpListLock;
    /* 0x0390 */ struct _LIST_ENTRY TppWorkerpList;
    /* 0x03a0 */ void* WaitOnAddressHashTable[128];
    /* 0x07a0 */ void* TelemetryCoverageHeader;
    /* 0x07a8 */ unsigned long CloudFileFlags;
    /* 0x07ac */ unsigned long CloudFileDiagFlags;
    /* 0x07b0 */ char PlaceholderCompatibilityMode;
    /* 0x07b1 */ char PlaceholderCompatibilityModeReserved[7];
    /* 0x07b8 */ struct _LEAP_SECOND_DATA* LeapSecondData;
    union
    {
        /* 0x07c0 */ unsigned long LeapSecondFlags;
        struct /* bitfield */
        {
            /* 0x07c0 */ unsigned long SixtySecondEnabled : 1; /* bit position: 0 */
            /* 0x07c0 */ unsigned long Reserved : 31; /* bit position: 1 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x07c4 */ unsigned long NtGlobalFlag2;
} PEB, * PPEB; /* size: 0x07c8 */
#endif // !_PEB_


typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    ULONG Mutant;                                                           //0x4
    ULONG ImageBaseAddress;                                                 //0x8
    ULONG Ldr;                                                              //0xc
    ULONG ProcessParameters;                                                //0x10
    ULONG SubSystemData;                                                    //0x14
    ULONG ProcessHeap;                                                      //0x18
    ULONG FastPebLock;                                                      //0x1c
    ULONG AtlThunkSListPtr;                                                 //0x20
    ULONG IFEOKey;                                                          //0x24
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x28
            ULONG ProcessInitializing : 1;                                    //0x28
            ULONG ProcessUsingVEH : 1;                                        //0x28
            ULONG ProcessUsingVCH : 1;                                        //0x28
            ULONG ProcessUsingFTH : 1;                                        //0x28
            ULONG ProcessPreviouslyThrottled : 1;                             //0x28
            ULONG ProcessCurrentlyThrottled : 1;                              //0x28
            ULONG ProcessImagesHotPatched : 1;                                //0x28
            ULONG ReservedBits0 : 24;                                         //0x28
        };
    };
    union
    {
        ULONG KernelCallbackTable;                                          //0x2c
        ULONG UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved;                                                   //0x30
    ULONG AtlThunkSListPtr32;                                               //0x34
    ULONG ApiSetMap;                                                        //0x38
    ULONG TlsExpansionCounter;                                              //0x3c
    ULONG TlsBitmap;                                                        //0x40
    ULONG TlsBitmapBits[2];                                                 //0x44
    ULONG ReadOnlySharedMemoryBase;                                         //0x4c
    ULONG SharedData;                                                       //0x50
    ULONG ReadOnlyStaticServerData;                                         //0x54
    ULONG AnsiCodePageData;                                                 //0x58
    ULONG OemCodePageData;                                                  //0x5c
    ULONG UnicodeCaseTableData;                                             //0x60
    ULONG NumberOfProcessors;                                               //0x64
    ULONG NtGlobalFlag;                                                     //0x68
    LARGE_INTEGER CriticalSectionTimeout;                            //0x70
    ULONG HeapSegmentReserve;                                               //0x78
    ULONG HeapSegmentCommit;                                                //0x7c
    ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
    ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
    ULONG NumberOfHeaps;                                                    //0x88
    ULONG MaximumNumberOfHeaps;                                             //0x8c
    ULONG ProcessHeaps;                                                     //0x90
    ULONG GdiSharedHandleTable;                                             //0x94
    ULONG ProcessStarterHelper;                                             //0x98
    ULONG GdiDCAttributeList;                                               //0x9c
    ULONG LoaderLock;                                                       //0xa0
    ULONG OSMajorVersion;                                                   //0xa4
    ULONG OSMinorVersion;                                                   //0xa8
    USHORT OSBuildNumber;                                                   //0xac
    USHORT OSCSDVersion;                                                    //0xae
    ULONG OSPlatformId;                                                     //0xb0
    ULONG ImageSubsystem;                                                   //0xb4
    ULONG ImageSubsystemMajorVersion;                                       //0xb8
    ULONG ImageSubsystemMinorVersion;                                       //0xbc
    ULONG ActiveProcessAffinityMask;                                        //0xc0
    ULONG GdiHandleBuffer[34];                                              //0xc4
    ULONG PostProcessInitRoutine;                                           //0x14c
    ULONG TlsExpansionBitmap;                                               //0x150
    ULONG TlsExpansionBitmapBits[32];                                       //0x154
    ULONG SessionId;                                                        //0x1d4
    ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
    ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
    ULONG pShimData;                                                        //0x1e8
    ULONG AppCompatInfo;                                                    //0x1ec
    STRING32 CSDVersion;                                            //0x1f0
    ULONG ActivationContextData;                                            //0x1f8
    ULONG ProcessAssemblyStorageMap;                                        //0x1fc
    ULONG SystemDefaultActivationContextData;                               //0x200
    ULONG SystemAssemblyStorageMap;                                         //0x204
    ULONG MinimumStackCommit;                                               //0x208
    ULONG SparePointers[4];                                                 //0x20c
    ULONG SpareUlongs[5];                                                   //0x21c
    ULONG WerRegistrationData;                                              //0x230
    ULONG WerShipAssertPtr;                                                 //0x234
    ULONG pUnused;                                                          //0x238
    ULONG pImageHeaderHash;                                                 //0x23c
    union
    {
        ULONG TracingFlags;                                                 //0x240
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x240
            ULONG CritSecTracingEnabled : 1;                                  //0x240
            ULONG LibLoaderTracingEnabled : 1;                                //0x240
            ULONG SpareTracingBits : 29;                                      //0x240
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
    ULONG TppWorkerpListLock;                                               //0x250
    LIST_ENTRY32 TppWorkerpList;                                     //0x254
    ULONG WaitOnAddressHashTable[128];                                      //0x25c
    ULONG TelemetryCoverageHeader;                                          //0x45c
    ULONG CloudFileFlags;                                                   //0x460
    ULONG CloudFileDiagFlags;                                               //0x464
    CHAR PlaceholderCompatibilityMode;                                      //0x468
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x469
    ULONG LeapSecondData;                                                   //0x470
    union
    {
        ULONG LeapSecondFlags;                                              //0x474
        struct
        {
            ULONG SixtySecondEnabled : 1;                                     //0x474
            ULONG Reserved : 31;                                              //0x474
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x478
}PEB32, * PPEB32;

BOOLEAN SetPebDeuggerFlag(PEPROCESS TargetProcess, BOOLEAN Value);

BOOLEAN ClearPebNtGlobalFlag(PEPROCESS TargetProcess);