#pragma once
#include <ntifs.h>

typedef struct _RTL_AVL_TREE
{
	/* 0x0000 */ struct _RTL_BALANCED_NODE* Root;
} RTL_AVL_TREE, * PRTL_AVL_TREE; /* size: 0x0008 */
typedef struct _MMSUPPORT_FLAGS                 // 15 elements, 0x4 bytes (sizeof)
{
	struct                                      // 6 elements, 0x1 bytes (sizeof)
	{
		/*0x000*/         UINT8        WorkingSetType : 3;        // 0 BitPosition
		/*0x000*/         UINT8        ModwriterAttached : 1;     // 3 BitPosition
		/*0x000*/         UINT8        TrimHard : 1;              // 4 BitPosition
		/*0x000*/         UINT8        MaximumWorkingSetHard : 1; // 5 BitPosition
		/*0x000*/         UINT8        ForceTrim : 1;             // 6 BitPosition
		/*0x000*/         UINT8        MinimumWorkingSetHard : 1; // 7 BitPosition
	};
	struct                                      // 4 elements, 0x1 bytes (sizeof)
	{
		/*0x001*/         UINT8        SessionMaster : 1;         // 0 BitPosition
		/*0x001*/         UINT8        TrimmerState : 2;          // 1 BitPosition
		/*0x001*/         UINT8        Reserved : 1;              // 3 BitPosition
		/*0x001*/         UINT8        PageStealers : 4;          // 4 BitPosition
	};
	/*0x002*/     UINT8        MemoryPriority : 8;            // 0 BitPosition
	struct                                      // 4 elements, 0x1 bytes (sizeof)
	{
		/*0x003*/         UINT8        WsleDeleted : 1;           // 0 BitPosition
		/*0x003*/         UINT8        VmExiting : 1;             // 1 BitPosition
		/*0x003*/         UINT8        ExpansionFailed : 1;       // 2 BitPosition
		/*0x003*/         UINT8        Available : 5;             // 3 BitPosition
	};
}MMSUPPORT_FLAGS, * PMMSUPPORT_FLAGS;
typedef struct _MMSUPPORT_INSTANCE
{
	/* 0x0000 */ unsigned long NextPageColor;
	/* 0x0004 */ unsigned long PageFaultCount;
	/* 0x0008 */ unsigned __int64 TrimmedPageCount;
	/* 0x0010 */ struct _MMWSL_INSTANCE* VmWorkingSetList;
	/* 0x0018 */ struct _LIST_ENTRY WorkingSetExpansionLinks;
	/* 0x0028 */ unsigned __int64 AgeDistribution[8];
	/* 0x0068 */ struct _KGATE* ExitOutswapGate;
	/* 0x0070 */ unsigned __int64 MinimumWorkingSetSize;
	/* 0x0078 */ unsigned __int64 WorkingSetLeafSize;
	/* 0x0080 */ unsigned __int64 WorkingSetLeafPrivateSize;
	/* 0x0088 */ unsigned __int64 WorkingSetSize;
	/* 0x0090 */ unsigned __int64 WorkingSetPrivateSize;
	/* 0x0098 */ unsigned __int64 MaximumWorkingSetSize;
	/* 0x00a0 */ unsigned __int64 PeakWorkingSetSize;
	/* 0x00a8 */ unsigned long HardFaultCount;
	/* 0x00ac */ unsigned short LastTrimStamp;
	/* 0x00ae */ unsigned short PartitionId;
	/* 0x00b0 */ unsigned __int64 SelfmapLock;
	/* 0x00b8 */ struct _MMSUPPORT_FLAGS Flags;
	/* 0x00bc */ long __PADDING__[1];
} MMSUPPORT_INSTANCE, * PMMSUPPORT_INSTANCE; /* size: 0x00c0 */
typedef struct _MMSUPPORT_SHARED
{
	/* 0x0000 */ volatile long WorkingSetLock;
	/* 0x0004 */ long GoodCitizenWaiting;
	/* 0x0008 */ unsigned __int64 ReleasedCommitDebt;
	/* 0x0010 */ unsigned __int64 ResetPagesRepurposedCount;
	/* 0x0018 */ void* WsSwapSupport;
	/* 0x0020 */ void* CommitReleaseContext;
	/* 0x0028 */ void* AccessLog;
	/* 0x0030 */ volatile unsigned __int64 ChargedWslePages;
	/* 0x0038 */ unsigned __int64 ActualWslePages;
	/* 0x0040 */ unsigned __int64 WorkingSetCoreLock;
	/* 0x0048 */ void* ShadowMapping;
	/* 0x0050 */ long __PADDING__[12];
} MMSUPPORT_SHARED, * PMMSUPPORT_SHARED; /* size: 0x0080 */
typedef struct _MMSUPPORT_FULL
{
	/* 0x0000 */ struct _MMSUPPORT_INSTANCE Instance;
	/* 0x00c0 */ struct _MMSUPPORT_SHARED Shared;
} MMSUPPORT_FULL, * PMMSUPPORT_FULL; /* size: 0x0140 */
typedef struct _PS_PROTECTION
{
	union
	{
		/* 0x0000 */ unsigned char Level;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned char Type : 3; /* bit position: 0 */
			/* 0x0000 */ unsigned char Audit : 1; /* bit position: 3 */
			/* 0x0000 */ unsigned char Signer : 4; /* bit position: 4 */
		}; /* bitfield */
	}; /* size: 0x0001 */
} PS_PROTECTION, * PPS_PROTECTION; /* size: 0x0001 */
typedef union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
	union
	{
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 DelayMs : 30; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 CoalescingWindowMs : 30; /* bit position: 30 */
			/* 0x0000 */ unsigned __int64 Reserved : 1; /* bit position: 60 */
			/* 0x0000 */ unsigned __int64 NewTimerWheel : 1; /* bit position: 61 */
			/* 0x0000 */ unsigned __int64 Retry : 1; /* bit position: 62 */
			/* 0x0000 */ unsigned __int64 Locked : 1; /* bit position: 63 */
		}; /* bitfield */
		/* 0x0000 */ unsigned __int64 All;
	}; /* size: 0x0008 */
} PS_INTERLOCKED_TIMER_DELAY_VALUES, * PPS_INTERLOCKED_TIMER_DELAY_VALUES; /* size: 0x0008 */
typedef struct _JOBOBJECT_WAKE_FILTER
{
	/* 0x0000 */ unsigned long HighEdgeFilter;
	/* 0x0004 */ unsigned long LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER; /* size: 0x0008 */
typedef struct _PS_PROCESS_WAKE_INFORMATION
{
	/* 0x0000 */ unsigned __int64 NotificationChannel;
	/* 0x0008 */ unsigned long WakeCounters[7];
	/* 0x0024 */ struct _JOBOBJECT_WAKE_FILTER WakeFilter;
	/* 0x002c */ unsigned long NoWakeCounter;
} PS_PROCESS_WAKE_INFORMATION, * PPS_PROCESS_WAKE_INFORMATION; /* size: 0x0030 */
typedef struct _EX_PUSH_LOCK
{
	union
	{
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 Locked : 1; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 Waiting : 1; /* bit position: 1 */
			/* 0x0000 */ unsigned __int64 Waking : 1; /* bit position: 2 */
			/* 0x0000 */ unsigned __int64 MultipleShared : 1; /* bit position: 3 */
			/* 0x0000 */ unsigned __int64 Shared : 60; /* bit position: 4 */
		}; /* bitfield */
		/* 0x0000 */ unsigned __int64 Value;
		/* 0x0000 */ void* Ptr;
	}; /* size: 0x0008 */
} EX_PUSH_LOCK, * PEX_PUSH_LOCK; /* size: 0x0008 */
typedef struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
	/* 0x0000 */ struct _RTL_AVL_TREE Tree;
	/* 0x0008 */ struct _EX_PUSH_LOCK Lock;
} PS_DYNAMIC_ENFORCED_ADDRESS_RANGES, * PPS_DYNAMIC_ENFORCED_ADDRESS_RANGES; /* size: 0x0010 */

typedef struct _KAFFINITY_EX
{
	/* 0x0000 */ unsigned short Count;
	/* 0x0002 */ unsigned short Size;
	/* 0x0004 */ unsigned long Reserved;
	/* 0x0008 */ unsigned __int64 Bitmap[20];
} KAFFINITY_EX, * PKAFFINITY_EX; /* size: 0x00a8 */

typedef union _KEXECUTE_OPTIONS
{
	union
	{
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned char ExecuteDisable : 1; /* bit position: 0 */
			/* 0x0000 */ unsigned char ExecuteEnable : 1; /* bit position: 1 */
			/* 0x0000 */ unsigned char DisableThunkEmulation : 1; /* bit position: 2 */
			/* 0x0000 */ unsigned char Permanent : 1; /* bit position: 3 */
			/* 0x0000 */ unsigned char ExecuteDispatchEnable : 1; /* bit position: 4 */
			/* 0x0000 */ unsigned char ImageDispatchEnable : 1; /* bit position: 5 */
			/* 0x0000 */ unsigned char DisableExceptionChainValidation : 1; /* bit position: 6 */
			/* 0x0000 */ unsigned char Spare : 1; /* bit position: 7 */
		}; /* bitfield */
		/* 0x0000 */ volatile unsigned char ExecuteOptions;
		/* 0x0000 */ unsigned char ExecuteOptionsNV;
	}; /* size: 0x0001 */
} KEXECUTE_OPTIONS, * PKEXECUTE_OPTIONS; /* size: 0x0001 */

typedef union _KSTACK_COUNT
{
	union
	{
		/* 0x0000 */ long Value;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned long State : 3; /* bit position: 0 */
			/* 0x0000 */ unsigned long StackCount : 29; /* bit position: 3 */
		}; /* bitfield */
	}; /* size: 0x0004 */
} KSTACK_COUNT, * PKSTACK_COUNT; /* size: 0x0004 */

typedef struct _KPROCESS
{
	/* 0x0000 */ struct _DISPATCHER_HEADER Header;
	/* 0x0018 */ struct _LIST_ENTRY ProfileListHead;
	/* 0x0028 */ unsigned __int64 DirectoryTableBase;
	/* 0x0030 */ struct _LIST_ENTRY ThreadListHead;
	/* 0x0040 */ unsigned long ProcessLock;
	/* 0x0044 */ unsigned long ProcessTimerDelay;
	/* 0x0048 */ unsigned __int64 DeepFreezeStartTime;
	/* 0x0050 */ struct _KAFFINITY_EX Affinity;
	/* 0x00f8 */ unsigned __int64 AffinityPadding[12];
	/* 0x0158 */ struct _LIST_ENTRY ReadyListHead;
	/* 0x0168 */ struct _SINGLE_LIST_ENTRY SwapListEntry;
	/* 0x0170 */ volatile struct _KAFFINITY_EX ActiveProcessors;
	/* 0x0218 */ unsigned __int64 ActiveProcessorsPadding[12];
	union
	{
		struct /* bitfield */
		{
			/* 0x0278 */ unsigned long AutoAlignment : 1; /* bit position: 0 */
			/* 0x0278 */ unsigned long DisableBoost : 1; /* bit position: 1 */
			/* 0x0278 */ unsigned long DisableQuantum : 1; /* bit position: 2 */
			/* 0x0278 */ unsigned long DeepFreeze : 1; /* bit position: 3 */
			/* 0x0278 */ unsigned long TimerVirtualization : 1; /* bit position: 4 */
			/* 0x0278 */ unsigned long CheckStackExtents : 1; /* bit position: 5 */
			/* 0x0278 */ unsigned long CacheIsolationEnabled : 1; /* bit position: 6 */
			/* 0x0278 */ unsigned long PpmPolicy : 3; /* bit position: 7 */
			/* 0x0278 */ unsigned long VaSpaceDeleted : 1; /* bit position: 10 */
			/* 0x0278 */ unsigned long ReservedFlags : 21; /* bit position: 11 */
		}; /* bitfield */
		/* 0x0278 */ volatile long ProcessFlags;
	}; /* size: 0x0004 */
	/* 0x027c */ unsigned long ActiveGroupsMask;
	/* 0x0280 */ char BasePriority;
	/* 0x0281 */ char QuantumReset;
	/* 0x0282 */ char Visited;
	/* 0x0283 */ union _KEXECUTE_OPTIONS Flags;
	/* 0x0284 */ unsigned short ThreadSeed[20];
	/* 0x02ac */ unsigned short ThreadSeedPadding[12];
	/* 0x02c4 */ unsigned short IdealProcessor[20];
	/* 0x02ec */ unsigned short IdealProcessorPadding[12];
	/* 0x0304 */ unsigned short IdealNode[20];
	/* 0x032c */ unsigned short IdealNodePadding[12];
	/* 0x0344 */ unsigned short IdealGlobalNode;
	/* 0x0346 */ unsigned short Spare1;
	/* 0x0348 */ volatile union _KSTACK_COUNT StackCount;
	/* 0x034c */ long Padding_0;
	/* 0x0350 */ struct _LIST_ENTRY ProcessListEntry;
	/* 0x0360 */ unsigned __int64 CycleTime;
	/* 0x0368 */ unsigned __int64 ContextSwitches;
	/* 0x0370 */ struct _KSCHEDULING_GROUP* SchedulingGroup;
	/* 0x0378 */ unsigned long FreezeCount;
	/* 0x037c */ unsigned long KernelTime;
	/* 0x0380 */ unsigned long UserTime;
	/* 0x0384 */ unsigned long ReadyTime;
	/* 0x0388 */ unsigned __int64 UserDirectoryTableBase;
	/* 0x0390 */ unsigned char AddressPolicy;
	/* 0x0391 */ unsigned char Spare2[71];
	/* 0x03d8 */ void* InstrumentationCallback;
	union
	{
		union
		{
			/* 0x03e0 */ unsigned __int64 SecureHandle;
			struct
			{
				struct /* bitfield */
				{
					/* 0x03e0 */ unsigned __int64 SecureProcess : 1; /* bit position: 0 */
					/* 0x03e0 */ unsigned __int64 Unused : 1; /* bit position: 1 */
				}; /* bitfield */
			} /* size: 0x0008 */ Flags;
		}; /* size: 0x0008 */
	} /* size: 0x0008 */ SecureState;
	/* 0x03e8 */ unsigned __int64 KernelWaitTime;
	/* 0x03f0 */ unsigned __int64 UserWaitTime;
	/* 0x03f8 */ unsigned __int64 EndPadding[8];
} KPROCESS, * PKPROCESS; /* size: 0x0438 */

typedef struct _EX_FAST_REF
{
	union
	{
		/* 0x0000 */ void* Object;
		/* 0x0000 */ unsigned __int64 RefCnt : 4; /* bit position: 0 */
		/* 0x0000 */ unsigned __int64 Value;
	}; /* size: 0x0008 */
} EX_FAST_REF, * PEX_FAST_REF; /* size: 0x0008 */

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
	/* 0x0000 */ struct _OBJECT_NAME_INFORMATION* ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO; /* size: 0x0008 */

typedef struct _MMSUPPORT_FLAGS
{
	union
	{
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned char WorkingSetType : 3; /* bit position: 0 */
				/* 0x0000 */ unsigned char Reserved0 : 3; /* bit position: 3 */
				/* 0x0000 */ unsigned char MaximumWorkingSetHard : 1; /* bit position: 6 */
				/* 0x0000 */ unsigned char MinimumWorkingSetHard : 1; /* bit position: 7 */
			}; /* bitfield */
			struct /* bitfield */
			{
				/* 0x0001 */ unsigned char SessionMaster : 1; /* bit position: 0 */
				/* 0x0001 */ unsigned char TrimmerState : 2; /* bit position: 1 */
				/* 0x0001 */ unsigned char Reserved : 1; /* bit position: 3 */
				/* 0x0001 */ unsigned char PageStealers : 4; /* bit position: 4 */
			}; /* bitfield */
		}; /* size: 0x0002 */
		/* 0x0000 */ unsigned short u1;
	}; /* size: 0x0002 */
	/* 0x0002 */ unsigned char MemoryPriority;
	union
	{
		struct /* bitfield */
		{
			/* 0x0003 */ unsigned char WsleDeleted : 1; /* bit position: 0 */
			/* 0x0003 */ unsigned char SvmEnabled : 1; /* bit position: 1 */
			/* 0x0003 */ unsigned char ForceAge : 1; /* bit position: 2 */
			/* 0x0003 */ unsigned char ForceTrim : 1; /* bit position: 3 */
			/* 0x0003 */ unsigned char NewMaximum : 1; /* bit position: 4 */
			/* 0x0003 */ unsigned char CommitReleaseState : 2; /* bit position: 5 */
		}; /* bitfield */
		/* 0x0003 */ unsigned char u2;
	}; /* size: 0x0001 */
} MMSUPPORT_FLAGS, * PMMSUPPORT_FLAGS; /* size: 0x0004 */

typedef struct _ALPC_PROCESS_CONTEXT
{
	/* 0x0000 */ struct _EX_PUSH_LOCK Lock;
	/* 0x0008 */ struct _LIST_ENTRY ViewListHead;
	/* 0x0018 */ volatile unsigned __int64 PagedPoolQuotaCache;
} ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT; /* size: 0x0020 */

typedef struct _EPROCESS_wrk
{
	/* 0x0000 */ struct _KPROCESS Pcb;
	/* 0x0438 */ struct _EX_PUSH_LOCK ProcessLock;
	/* 0x0440 */ void* UniqueProcessId;
	/* 0x0448 */ struct _LIST_ENTRY ActiveProcessLinks;
	/* 0x0458 */ struct _EX_RUNDOWN_REF RundownProtect;
	union
	{
		/* 0x0460 */ unsigned long Flags2;
		struct /* bitfield */
		{
			/* 0x0460 */ unsigned long JobNotReallyActive : 1; /* bit position: 0 */
			/* 0x0460 */ unsigned long AccountingFolded : 1; /* bit position: 1 */
			/* 0x0460 */ unsigned long NewProcessReported : 1; /* bit position: 2 */
			/* 0x0460 */ unsigned long ExitProcessReported : 1; /* bit position: 3 */
			/* 0x0460 */ unsigned long ReportCommitChanges : 1; /* bit position: 4 */
			/* 0x0460 */ unsigned long LastReportMemory : 1; /* bit position: 5 */
			/* 0x0460 */ unsigned long ForceWakeCharge : 1; /* bit position: 6 */
			/* 0x0460 */ unsigned long CrossSessionCreate : 1; /* bit position: 7 */
			/* 0x0460 */ unsigned long NeedsHandleRundown : 1; /* bit position: 8 */
			/* 0x0460 */ unsigned long RefTraceEnabled : 1; /* bit position: 9 */
			/* 0x0460 */ unsigned long PicoCreated : 1; /* bit position: 10 */
			/* 0x0460 */ unsigned long EmptyJobEvaluated : 1; /* bit position: 11 */
			/* 0x0460 */ unsigned long DefaultPagePriority : 3; /* bit position: 12 */
			/* 0x0460 */ unsigned long PrimaryTokenFrozen : 1; /* bit position: 15 */
			/* 0x0460 */ unsigned long ProcessVerifierTarget : 1; /* bit position: 16 */
			/* 0x0460 */ unsigned long RestrictSetThreadContext : 1; /* bit position: 17 */
			/* 0x0460 */ unsigned long AffinityPermanent : 1; /* bit position: 18 */
			/* 0x0460 */ unsigned long AffinityUpdateEnable : 1; /* bit position: 19 */
			/* 0x0460 */ unsigned long PropagateNode : 1; /* bit position: 20 */
			/* 0x0460 */ unsigned long ExplicitAffinity : 1; /* bit position: 21 */
			/* 0x0460 */ unsigned long ProcessExecutionState : 2; /* bit position: 22 */
			/* 0x0460 */ unsigned long EnableReadVmLogging : 1; /* bit position: 24 */
			/* 0x0460 */ unsigned long EnableWriteVmLogging : 1; /* bit position: 25 */
			/* 0x0460 */ unsigned long FatalAccessTerminationRequested : 1; /* bit position: 26 */
			/* 0x0460 */ unsigned long DisableSystemAllowedCpuSet : 1; /* bit position: 27 */
			/* 0x0460 */ unsigned long ProcessStateChangeRequest : 2; /* bit position: 28 */
			/* 0x0460 */ unsigned long ProcessStateChangeInProgress : 1; /* bit position: 30 */
			/* 0x0460 */ unsigned long InPrivate : 1; /* bit position: 31 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	union
	{
		/* 0x0464 */ unsigned long Flags;
		struct /* bitfield */
		{
			/* 0x0464 */ unsigned long CreateReported : 1; /* bit position: 0 */
			/* 0x0464 */ unsigned long NoDebugInherit : 1; /* bit position: 1 */
			/* 0x0464 */ unsigned long ProcessExiting : 1; /* bit position: 2 */
			/* 0x0464 */ unsigned long ProcessDelete : 1; /* bit position: 3 */
			/* 0x0464 */ unsigned long ManageExecutableMemoryWrites : 1; /* bit position: 4 */
			/* 0x0464 */ unsigned long VmDeleted : 1; /* bit position: 5 */
			/* 0x0464 */ unsigned long OutswapEnabled : 1; /* bit position: 6 */
			/* 0x0464 */ unsigned long Outswapped : 1; /* bit position: 7 */
			/* 0x0464 */ unsigned long FailFastOnCommitFail : 1; /* bit position: 8 */
			/* 0x0464 */ unsigned long Wow64VaSpace4Gb : 1; /* bit position: 9 */
			/* 0x0464 */ unsigned long AddressSpaceInitialized : 2; /* bit position: 10 */
			/* 0x0464 */ unsigned long SetTimerResolution : 1; /* bit position: 12 */
			/* 0x0464 */ unsigned long BreakOnTermination : 1; /* bit position: 13 */
			/* 0x0464 */ unsigned long DeprioritizeViews : 1; /* bit position: 14 */
			/* 0x0464 */ unsigned long WriteWatch : 1; /* bit position: 15 */
			/* 0x0464 */ unsigned long ProcessInSession : 1; /* bit position: 16 */
			/* 0x0464 */ unsigned long OverrideAddressSpace : 1; /* bit position: 17 */
			/* 0x0464 */ unsigned long HasAddressSpace : 1; /* bit position: 18 */
			/* 0x0464 */ unsigned long LaunchPrefetched : 1; /* bit position: 19 */
			/* 0x0464 */ unsigned long Background : 1; /* bit position: 20 */
			/* 0x0464 */ unsigned long VmTopDown : 1; /* bit position: 21 */
			/* 0x0464 */ unsigned long ImageNotifyDone : 1; /* bit position: 22 */
			/* 0x0464 */ unsigned long PdeUpdateNeeded : 1; /* bit position: 23 */
			/* 0x0464 */ unsigned long VdmAllowed : 1; /* bit position: 24 */
			/* 0x0464 */ unsigned long ProcessRundown : 1; /* bit position: 25 */
			/* 0x0464 */ unsigned long ProcessInserted : 1; /* bit position: 26 */
			/* 0x0464 */ unsigned long DefaultIoPriority : 3; /* bit position: 27 */
			/* 0x0464 */ unsigned long ProcessSelfDelete : 1; /* bit position: 30 */
			/* 0x0464 */ unsigned long SetTimerResolutionLink : 1; /* bit position: 31 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x0468 */ union _LARGE_INTEGER CreateTime;
	/* 0x0470 */ unsigned __int64 ProcessQuotaUsage[2];
	/* 0x0480 */ unsigned __int64 ProcessQuotaPeak[2];
	/* 0x0490 */ unsigned __int64 PeakVirtualSize;
	/* 0x0498 */ unsigned __int64 VirtualSize;
	/* 0x04a0 */ struct _LIST_ENTRY SessionProcessLinks;
	union
	{
		/* 0x04b0 */ void* ExceptionPortData;
		/* 0x04b0 */ unsigned __int64 ExceptionPortValue;
		/* 0x04b0 */ unsigned __int64 ExceptionPortState : 3; /* bit position: 0 */
	}; /* size: 0x0008 */
	/* 0x04b8 */ struct _EX_FAST_REF Token;
	/* 0x04c0 */ unsigned __int64 MmReserved;
	/* 0x04c8 */ struct _EX_PUSH_LOCK AddressCreationLock;
	/* 0x04d0 */ struct _EX_PUSH_LOCK PageTableCommitmentLock;
	/* 0x04d8 */ struct _ETHREAD* RotateInProgress;
	/* 0x04e0 */ struct _ETHREAD* ForkInProgress;
	/* 0x04e8 */ struct _EJOB* volatile CommitChargeJob;
	/* 0x04f0 */ struct _RTL_AVL_TREE CloneRoot;
	/* 0x04f8 */ volatile unsigned __int64 NumberOfPrivatePages;
	/* 0x0500 */ volatile unsigned __int64 NumberOfLockedPages;
	/* 0x0508 */ void* Win32Process;
	/* 0x0510 */ struct _EJOB* volatile Job;
	/* 0x0518 */ void* SectionObject;
	/* 0x0520 */ void* SectionBaseAddress;
	/* 0x0528 */ unsigned long Cookie;
	/* 0x052c */ long Padding_1;
	/* 0x0530 */ struct _PAGEFAULT_HISTORY* WorkingSetWatch;
	/* 0x0538 */ void* Win32WindowStation;
	/* 0x0540 */ void* InheritedFromUniqueProcessId;
	/* 0x0548 */ volatile unsigned __int64 OwnerProcessId;
	/* 0x0550 */ struct _PEB* Peb;
	/* 0x0558 */ struct _MM_SESSION_SPACE* Session;
	/* 0x0560 */ void* Spare1;
	/* 0x0568 */ struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;
	/* 0x0570 */ struct _HANDLE_TABLE* ObjectTable;
	/* 0x0578 */ void* DebugPort;
	/* 0x0580 */ struct _EWOW64PROCESS* WoW64Process;
	/* 0x0588 */ void* DeviceMap;
	/* 0x0590 */ void* EtwDataSource;
	/* 0x0598 */ unsigned __int64 PageDirectoryPte;
	/* 0x05a0 */ struct _FILE_OBJECT* ImageFilePointer;
	/* 0x05a8 */ unsigned char ImageFileName[15];
	/* 0x05b7 */ unsigned char PriorityClass;
	/* 0x05b8 */ void* SecurityPort;
	/* 0x05c0 */ struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
	/* 0x05c8 */ struct _LIST_ENTRY JobLinks;
	/* 0x05d8 */ void* HighestUserAddress;
	/* 0x05e0 */ struct _LIST_ENTRY ThreadListHead;
	/* 0x05f0 */ volatile unsigned long ActiveThreads;
	/* 0x05f4 */ unsigned long ImagePathHash;
	/* 0x05f8 */ unsigned long DefaultHardErrorProcessing;
	/* 0x05fc */ long LastThreadExitStatus;
	/* 0x0600 */ struct _EX_FAST_REF PrefetchTrace;
	/* 0x0608 */ void* LockedPagesList;
	/* 0x0610 */ union _LARGE_INTEGER ReadOperationCount;
	/* 0x0618 */ union _LARGE_INTEGER WriteOperationCount;
	/* 0x0620 */ union _LARGE_INTEGER OtherOperationCount;
	/* 0x0628 */ union _LARGE_INTEGER ReadTransferCount;
	/* 0x0630 */ union _LARGE_INTEGER WriteTransferCount;
	/* 0x0638 */ union _LARGE_INTEGER OtherTransferCount;
	/* 0x0640 */ unsigned __int64 CommitChargeLimit;
	/* 0x0648 */ volatile unsigned __int64 CommitCharge;
	/* 0x0650 */ volatile unsigned __int64 CommitChargePeak;
	/* 0x0658 */ long Padding_2[10];
	/* 0x0680 */ struct _MMSUPPORT_FULL Vm;
	/* 0x07c0 */ struct _LIST_ENTRY MmProcessLinks;
	/* 0x07d0 */ unsigned long ModifiedPageCount;
	/* 0x07d4 */ long ExitStatus;
	/* 0x07d8 */ struct _RTL_AVL_TREE VadRoot;
	/* 0x07e0 */ void* VadHint;
	/* 0x07e8 */ unsigned __int64 VadCount;
	/* 0x07f0 */ volatile unsigned __int64 VadPhysicalPages;
	/* 0x07f8 */ unsigned __int64 VadPhysicalPagesLimit;
	/* 0x0800 */ struct _ALPC_PROCESS_CONTEXT AlpcContext;
	/* 0x0820 */ struct _LIST_ENTRY TimerResolutionLink;
	/* 0x0830 */ struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;
	/* 0x0838 */ unsigned long RequestedTimerResolution;
	/* 0x083c */ unsigned long SmallestTimerResolution;
	/* 0x0840 */ union _LARGE_INTEGER ExitTime;
	/* 0x0848 */ struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;
	/* 0x0850 */ struct _EX_PUSH_LOCK InvertedFunctionTableLock;
	/* 0x0858 */ unsigned long ActiveThreadsHighWatermark;
	/* 0x085c */ unsigned long LargePrivateVadCount;
	/* 0x0860 */ struct _EX_PUSH_LOCK ThreadListLock;
	/* 0x0868 */ void* WnfContext;
	/* 0x0870 */ struct _EJOB* ServerSilo;
	/* 0x0878 */ unsigned char SignatureLevel;
	/* 0x0879 */ unsigned char SectionSignatureLevel;
	/* 0x087a */ struct _PS_PROTECTION Protection;
	struct /* bitfield */
	{
		/* 0x087b */ unsigned char HangCount : 3; /* bit position: 0 */
		/* 0x087b */ unsigned char GhostCount : 3; /* bit position: 3 */
		/* 0x087b */ unsigned char PrefilterException : 1; /* bit position: 6 */
	}; /* bitfield */
	union
	{
		/* 0x087c */ unsigned long Flags3;
		struct /* bitfield */
		{
			/* 0x087c */ unsigned long Minimal : 1; /* bit position: 0 */
			/* 0x087c */ unsigned long ReplacingPageRoot : 1; /* bit position: 1 */
			/* 0x087c */ unsigned long Crashed : 1; /* bit position: 2 */
			/* 0x087c */ unsigned long JobVadsAreTracked : 1; /* bit position: 3 */
			/* 0x087c */ unsigned long VadTrackingDisabled : 1; /* bit position: 4 */
			/* 0x087c */ unsigned long AuxiliaryProcess : 1; /* bit position: 5 */
			/* 0x087c */ unsigned long SubsystemProcess : 1; /* bit position: 6 */
			/* 0x087c */ unsigned long IndirectCpuSets : 1; /* bit position: 7 */
			/* 0x087c */ unsigned long RelinquishedCommit : 1; /* bit position: 8 */
			/* 0x087c */ unsigned long HighGraphicsPriority : 1; /* bit position: 9 */
			/* 0x087c */ unsigned long CommitFailLogged : 1; /* bit position: 10 */
			/* 0x087c */ unsigned long ReserveFailLogged : 1; /* bit position: 11 */
			/* 0x087c */ unsigned long SystemProcess : 1; /* bit position: 12 */
			/* 0x087c */ unsigned long HideImageBaseAddresses : 1; /* bit position: 13 */
			/* 0x087c */ unsigned long AddressPolicyFrozen : 1; /* bit position: 14 */
			/* 0x087c */ unsigned long ProcessFirstResume : 1; /* bit position: 15 */
			/* 0x087c */ unsigned long ForegroundExternal : 1; /* bit position: 16 */
			/* 0x087c */ unsigned long ForegroundSystem : 1; /* bit position: 17 */
			/* 0x087c */ unsigned long HighMemoryPriority : 1; /* bit position: 18 */
			/* 0x087c */ unsigned long EnableProcessSuspendResumeLogging : 1; /* bit position: 19 */
			/* 0x087c */ unsigned long EnableThreadSuspendResumeLogging : 1; /* bit position: 20 */
			/* 0x087c */ unsigned long SecurityDomainChanged : 1; /* bit position: 21 */
			/* 0x087c */ unsigned long SecurityFreezeComplete : 1; /* bit position: 22 */
			/* 0x087c */ unsigned long VmProcessorHost : 1; /* bit position: 23 */
			/* 0x087c */ unsigned long VmProcessorHostTransition : 1; /* bit position: 24 */
			/* 0x087c */ unsigned long AltSyscall : 1; /* bit position: 25 */
			/* 0x087c */ unsigned long TimerResolutionIgnore : 1; /* bit position: 26 */
			/* 0x087c */ unsigned long DisallowUserTerminate : 1; /* bit position: 27 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x0880 */ long DeviceAsid;
	/* 0x0884 */ long Padding_3;
	/* 0x0888 */ void* SvmData;
	/* 0x0890 */ struct _EX_PUSH_LOCK SvmProcessLock;
	/* 0x0898 */ unsigned __int64 SvmLock;
	/* 0x08a0 */ struct _LIST_ENTRY SvmProcessDeviceListHead;
	/* 0x08b0 */ unsigned __int64 LastFreezeInterruptTime;
	/* 0x08b8 */ struct _PROCESS_DISK_COUNTERS* DiskCounters;
	/* 0x08c0 */ void* PicoContext;
	/* 0x08c8 */ void* EnclaveTable;
	/* 0x08d0 */ unsigned __int64 EnclaveNumber;
	/* 0x08d8 */ struct _EX_PUSH_LOCK EnclaveLock;
	/* 0x08e0 */ unsigned long HighPriorityFaultsAllowed;
	/* 0x08e4 */ long Padding_4;
	/* 0x08e8 */ struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;
	/* 0x08f0 */ void* VmContext;
	/* 0x08f8 */ unsigned __int64 SequenceNumber;
	/* 0x0900 */ unsigned __int64 CreateInterruptTime;
	/* 0x0908 */ unsigned __int64 CreateUnbiasedInterruptTime;
	/* 0x0910 */ unsigned __int64 TotalUnbiasedFrozenTime;
	/* 0x0918 */ unsigned __int64 LastAppStateUpdateTime;
	struct /* bitfield */
	{
		/* 0x0920 */ unsigned __int64 LastAppStateUptime : 61; /* bit position: 0 */
		/* 0x0920 */ unsigned __int64 LastAppState : 3; /* bit position: 61 */
	}; /* bitfield */
	/* 0x0928 */ volatile unsigned __int64 SharedCommitCharge;
	/* 0x0930 */ struct _EX_PUSH_LOCK SharedCommitLock;
	/* 0x0938 */ struct _LIST_ENTRY SharedCommitLinks;
	union
	{
		struct
		{
			/* 0x0948 */ unsigned __int64 AllowedCpuSets;
			/* 0x0950 */ unsigned __int64 DefaultCpuSets;
		}; /* size: 0x0010 */
		struct
		{
			/* 0x0948 */ unsigned __int64* AllowedCpuSetsIndirect;
			/* 0x0950 */ unsigned __int64* DefaultCpuSetsIndirect;
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
	/* 0x0958 */ void* DiskIoAttribution;
	/* 0x0960 */ void* DxgProcess;
	/* 0x0968 */ unsigned long Win32KFilterSet;
	/* 0x096c */ long Padding_5;
	/* 0x0970 */ volatile union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;
	/* 0x0978 */ volatile unsigned long KTimerSets;
	/* 0x097c */ volatile unsigned long KTimer2Sets;
	/* 0x0980 */ volatile unsigned long ThreadTimerSets;
	/* 0x0984 */ long Padding_6;
	/* 0x0988 */ unsigned __int64 VirtualTimerListLock;
	/* 0x0990 */ struct _LIST_ENTRY VirtualTimerListHead;
	union
	{
		/* 0x09a0 */ struct _WNF_STATE_NAME WakeChannel;
		/* 0x09a0 */ struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;
	}; /* size: 0x0030 */
	union
	{
		/* 0x09d0 */ unsigned long MitigationFlags;
		struct
		{
			struct /* bitfield */
			{
				/* 0x09d0 */ unsigned long ControlFlowGuardEnabled : 1; /* bit position: 0 */
				/* 0x09d0 */ unsigned long ControlFlowGuardExportSuppressionEnabled : 1; /* bit position: 1 */
				/* 0x09d0 */ unsigned long ControlFlowGuardStrict : 1; /* bit position: 2 */
				/* 0x09d0 */ unsigned long DisallowStrippedImages : 1; /* bit position: 3 */
				/* 0x09d0 */ unsigned long ForceRelocateImages : 1; /* bit position: 4 */
				/* 0x09d0 */ unsigned long HighEntropyASLREnabled : 1; /* bit position: 5 */
				/* 0x09d0 */ unsigned long StackRandomizationDisabled : 1; /* bit position: 6 */
				/* 0x09d0 */ unsigned long ExtensionPointDisable : 1; /* bit position: 7 */
				/* 0x09d0 */ unsigned long DisableDynamicCode : 1; /* bit position: 8 */
				/* 0x09d0 */ unsigned long DisableDynamicCodeAllowOptOut : 1; /* bit position: 9 */
				/* 0x09d0 */ unsigned long DisableDynamicCodeAllowRemoteDowngrade : 1; /* bit position: 10 */
				/* 0x09d0 */ unsigned long AuditDisableDynamicCode : 1; /* bit position: 11 */
				/* 0x09d0 */ unsigned long DisallowWin32kSystemCalls : 1; /* bit position: 12 */
				/* 0x09d0 */ unsigned long AuditDisallowWin32kSystemCalls : 1; /* bit position: 13 */
				/* 0x09d0 */ unsigned long EnableFilteredWin32kAPIs : 1; /* bit position: 14 */
				/* 0x09d0 */ unsigned long AuditFilteredWin32kAPIs : 1; /* bit position: 15 */
				/* 0x09d0 */ unsigned long DisableNonSystemFonts : 1; /* bit position: 16 */
				/* 0x09d0 */ unsigned long AuditNonSystemFontLoading : 1; /* bit position: 17 */
				/* 0x09d0 */ unsigned long PreferSystem32Images : 1; /* bit position: 18 */
				/* 0x09d0 */ unsigned long ProhibitRemoteImageMap : 1; /* bit position: 19 */
				/* 0x09d0 */ unsigned long AuditProhibitRemoteImageMap : 1; /* bit position: 20 */
				/* 0x09d0 */ unsigned long ProhibitLowILImageMap : 1; /* bit position: 21 */
				/* 0x09d0 */ unsigned long AuditProhibitLowILImageMap : 1; /* bit position: 22 */
				/* 0x09d0 */ unsigned long SignatureMitigationOptIn : 1; /* bit position: 23 */
				/* 0x09d0 */ unsigned long AuditBlockNonMicrosoftBinaries : 1; /* bit position: 24 */
				/* 0x09d0 */ unsigned long AuditBlockNonMicrosoftBinariesAllowStore : 1; /* bit position: 25 */
				/* 0x09d0 */ unsigned long LoaderIntegrityContinuityEnabled : 1; /* bit position: 26 */
				/* 0x09d0 */ unsigned long AuditLoaderIntegrityContinuity : 1; /* bit position: 27 */
				/* 0x09d0 */ unsigned long EnableModuleTamperingProtection : 1; /* bit position: 28 */
				/* 0x09d0 */ unsigned long EnableModuleTamperingProtectionNoInherit : 1; /* bit position: 29 */
				/* 0x09d0 */ unsigned long RestrictIndirectBranchPrediction : 1; /* bit position: 30 */
				/* 0x09d0 */ unsigned long IsolateSecurityDomain : 1; /* bit position: 31 */
			}; /* bitfield */
		} /* size: 0x0004 */ MitigationFlagsValues;
	}; /* size: 0x0004 */
	union
	{
		/* 0x09d4 */ unsigned long MitigationFlags2;
		struct
		{
			struct /* bitfield */
			{
				/* 0x09d4 */ unsigned long EnableExportAddressFilter : 1; /* bit position: 0 */
				/* 0x09d4 */ unsigned long AuditExportAddressFilter : 1; /* bit position: 1 */
				/* 0x09d4 */ unsigned long EnableExportAddressFilterPlus : 1; /* bit position: 2 */
				/* 0x09d4 */ unsigned long AuditExportAddressFilterPlus : 1; /* bit position: 3 */
				/* 0x09d4 */ unsigned long EnableRopStackPivot : 1; /* bit position: 4 */
				/* 0x09d4 */ unsigned long AuditRopStackPivot : 1; /* bit position: 5 */
				/* 0x09d4 */ unsigned long EnableRopCallerCheck : 1; /* bit position: 6 */
				/* 0x09d4 */ unsigned long AuditRopCallerCheck : 1; /* bit position: 7 */
				/* 0x09d4 */ unsigned long EnableRopSimExec : 1; /* bit position: 8 */
				/* 0x09d4 */ unsigned long AuditRopSimExec : 1; /* bit position: 9 */
				/* 0x09d4 */ unsigned long EnableImportAddressFilter : 1; /* bit position: 10 */
				/* 0x09d4 */ unsigned long AuditImportAddressFilter : 1; /* bit position: 11 */
				/* 0x09d4 */ unsigned long DisablePageCombine : 1; /* bit position: 12 */
				/* 0x09d4 */ unsigned long SpeculativeStoreBypassDisable : 1; /* bit position: 13 */
				/* 0x09d4 */ unsigned long CetUserShadowStacks : 1; /* bit position: 14 */
				/* 0x09d4 */ unsigned long AuditCetUserShadowStacks : 1; /* bit position: 15 */
				/* 0x09d4 */ unsigned long AuditCetUserShadowStacksLogged : 1; /* bit position: 16 */
				/* 0x09d4 */ unsigned long UserCetSetContextIpValidation : 1; /* bit position: 17 */
				/* 0x09d4 */ unsigned long AuditUserCetSetContextIpValidation : 1; /* bit position: 18 */
				/* 0x09d4 */ unsigned long AuditUserCetSetContextIpValidationLogged : 1; /* bit position: 19 */
				/* 0x09d4 */ unsigned long CetUserShadowStacksStrictMode : 1; /* bit position: 20 */
				/* 0x09d4 */ unsigned long BlockNonCetBinaries : 1; /* bit position: 21 */
				/* 0x09d4 */ unsigned long BlockNonCetBinariesNonEhcont : 1; /* bit position: 22 */
				/* 0x09d4 */ unsigned long AuditBlockNonCetBinaries : 1; /* bit position: 23 */
				/* 0x09d4 */ unsigned long AuditBlockNonCetBinariesLogged : 1; /* bit position: 24 */
				/* 0x09d4 */ unsigned long Reserved1 : 1; /* bit position: 25 */
				/* 0x09d4 */ unsigned long Reserved2 : 1; /* bit position: 26 */
				/* 0x09d4 */ unsigned long Reserved3 : 1; /* bit position: 27 */
				/* 0x09d4 */ unsigned long Reserved4 : 1; /* bit position: 28 */
				/* 0x09d4 */ unsigned long Reserved5 : 1; /* bit position: 29 */
				/* 0x09d4 */ unsigned long CetDynamicApisOutOfProcOnly : 1; /* bit position: 30 */
				/* 0x09d4 */ unsigned long UserCetSetContextIpValidationRelaxedMode : 1; /* bit position: 31 */
			}; /* bitfield */
		} /* size: 0x0004 */ MitigationFlags2Values;
	}; /* size: 0x0004 */
	/* 0x09d8 */ void* PartitionObject;
	/* 0x09e0 */ unsigned __int64 SecurityDomain;
	/* 0x09e8 */ unsigned __int64 ParentSecurityDomain;
	/* 0x09f0 */ void* CoverageSamplerContext;
	/* 0x09f8 */ void* MmHotPatchContext;
	/* 0x0a00 */ struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;
	/* 0x0a08 */ struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;
	/* 0x0a10 */ struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges;
	/* 0x0a20 */ unsigned long DisabledComponentFlags;
	/* 0x0a24 */ long __PADDING__[7];
} EPROCESS_wrk, * PEPROCESS_wrk; /* size: 0x0a40 */