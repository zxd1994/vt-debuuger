#pragma once

#include <ntifs.h>

typedef struct _KERNEL_STACK_SEGMENT // 5 elements, 0x28 bytes (sizeof)
{
	/*0x000*/     UINT64       StackBase;
	/*0x008*/     UINT64       StackLimit;
	/*0x010*/     UINT64       KernelStack;
	/*0x018*/     UINT64       InitialStack;
	/*0x020*/     UINT64       ActualLimit;
}KERNEL_STACK_SEGMENT, * PKERNEL_STACK_SEGMENT;

typedef struct _KERNEL_STACK_CONTROL       // 2 elements, 0x50 bytes (sizeof)
{
	/*0x000*/     struct _KERNEL_STACK_SEGMENT Current;  // 5 elements, 0x28 bytes (sizeof)
	/*0x028*/     struct _KERNEL_STACK_SEGMENT Previous; // 5 elements, 0x28 bytes (sizeof)
}KERNEL_STACK_CONTROL, * PKERNEL_STACK_CONTROL;

#ifndef _EX_FAST_REF_
#define _EX_FAST_REF_
typedef struct _EX_FAST_REF      // 3 elements, 0x8 bytes (sizeof)
{
	union                        // 3 elements, 0x8 bytes (sizeof)
	{
		/*0x000*/         VOID* Object;
		/*0x000*/         UINT64       RefCnt : 4; // 0 BitPosition
		/*0x000*/         UINT64       Value;
	};
}EX_FAST_REF, * PEX_FAST_REF;
#endif // !_EX_FAST_REF_

#ifndef _KWAIT_STATUS_REGISTER_
#define _KWAIT_STATUS_REGISTER_
typedef union _KWAIT_STATUS_REGISTER // 8 elements, 0x1 bytes (sizeof) 
{
	/*0x000*/     UINT8        Flags;
	struct                           // 7 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        State : 2;      // 0 BitPosition                  
		/*0x000*/         UINT8        Affinity : 1;   // 2 BitPosition                  
		/*0x000*/         UINT8        Priority : 1;   // 3 BitPosition                  
		/*0x000*/         UINT8        Apc : 1;        // 4 BitPosition                  
		/*0x000*/         UINT8        UserApc : 1;    // 5 BitPosition                  
		/*0x000*/         UINT8        Alert : 1;      // 6 BitPosition                  
		/*0x000*/         UINT8        Unused : 1;     // 7 BitPosition                  
	};
}KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER;
#endif // !_KWAIT_STATUS_REGISTER_

#ifndef _PS_CLIENT_SECURITY_CONTEXT_
#define _PS_CLIENT_SECURITY_CONTEXT_
typedef union _PS_CLIENT_SECURITY_CONTEXT    // 4 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG_PTR      ImpersonationData;
	/*0x000*/     VOID* ImpersonationToken;
	struct                                   // 2 elements, 0x4 bytes (sizeof) 
	{
		/*0x000*/         ULONG_PTR      ImpersonationLevel : 2; // 0 BitPosition                  
		/*0x000*/         ULONG_PTR      EffectiveOnly : 1;      // 2 BitPosition                  
	};
}PS_CLIENT_SECURITY_CONTEXT, * PPS_CLIENT_SECURITY_CONTEXT;
#endif // !_PS_CLIENT_SECURITY_CONTEXT_

#ifndef _EX_PUSH_LOCK_
#define _EX_PUSH_LOCK_
typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof)
{
	union                                    // 3 elements, 0x8 bytes (sizeof)
	{
		struct                               // 5 elements, 0x8 bytes (sizeof)
		{
			/*0x000*/             UINT64       Locked : 1;         // 0 BitPosition
			/*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition
			/*0x000*/             UINT64       Waking : 1;         // 2 BitPosition
			/*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition
			/*0x000*/             UINT64       Shared : 60;        // 4 BitPosition
		};
		/*0x000*/         UINT64       Value;
		/*0x000*/         VOID* Ptr;
	};
}/*EX_PUSH_LOCK, *PEX_PUSH_LOCK*/;
#endif // !_EX_PUSH_LOCK_


#ifndef _KTHREAD_S_
#define _KTHREAD_S_
typedef struct _RTL_RB_TREE
{
	/* 0x0000 */ struct _RTL_BALANCED_NODE* Root;
	union
	{
		/* 0x0008 */ unsigned char Encoded : 1; /* bit position: 0 */
		/* 0x0008 */ struct _RTL_BALANCED_NODE* Min;
	}; /* size: 0x0008 */
} RTL_RB_TREE, * PRTL_RB_TREE; /* size: 0x0010 */

typedef union _KLOCK_ENTRY_BOOST_BITMAP
{
	union
	{
		/* 0x0000 */ unsigned long AllFields;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned long AllBoosts : 17; /* bit position: 0 */
			/* 0x0000 */ unsigned long Reserved : 15; /* bit position: 17 */
		}; /* bitfield */
		struct
		{
			struct /* bitfield */
			{
				/* 0x0000 */ unsigned short CpuBoostsBitmap : 15; /* bit position: 0 */
				/* 0x0000 */ unsigned short IoBoost : 1; /* bit position: 15 */
			}; /* bitfield */
			struct /* bitfield */
			{
				/* 0x0002 */ unsigned short IoQoSBoost : 1; /* bit position: 0 */
				/* 0x0002 */ unsigned short IoNormalPriorityWaiterCount : 8; /* bit position: 1 */
				/* 0x0002 */ unsigned short IoQoSWaiterCount : 7; /* bit position: 9 */
			}; /* bitfield */
		}; /* size: 0x0004 */
	}; /* size: 0x0004 */
} KLOCK_ENTRY_BOOST_BITMAP, * PKLOCK_ENTRY_BOOST_BITMAP; /* size: 0x0004 */

typedef struct _KLOCK_ENTRY_LOCK_STATE
{
	union
	{
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned __int64 CrossThreadReleasable : 1; /* bit position: 0 */
			/* 0x0000 */ unsigned __int64 Busy : 1; /* bit position: 1 */
			/* 0x0000 */ unsigned __int64 Reserved : 61; /* bit position: 2 */
			/* 0x0000 */ unsigned __int64 InTree : 1; /* bit position: 63 */
		}; /* bitfield */
		/* 0x0000 */ void* LockState;
	}; /* size: 0x0008 */
	union
	{
		/* 0x0008 */ void* SessionState;
		struct
		{
			/* 0x0008 */ unsigned long SessionId;
			/* 0x000c */ unsigned long SessionPad;
		}; /* size: 0x0008 */
	}; /* size: 0x0008 */
} KLOCK_ENTRY_LOCK_STATE, * PKLOCK_ENTRY_LOCK_STATE; /* size: 0x0010 */

typedef struct _KLOCK_ENTRY
{
	union
	{
		/* 0x0000 */ struct _RTL_BALANCED_NODE TreeNode;
		/* 0x0000 */ struct _SINGLE_LIST_ENTRY FreeListEntry;
	}; /* size: 0x0018 */
	union
	{
		/* 0x0018 */ unsigned long EntryFlags;
		struct
		{
			/* 0x0018 */ unsigned char EntryOffset;
			union
			{
				/* 0x0019 */ unsigned char ThreadLocalFlags;
				struct
				{
					struct /* bitfield */
					{
						/* 0x0019 */ unsigned char WaitingBit : 1; /* bit position: 0 */
						/* 0x0019 */ unsigned char Spare0 : 7; /* bit position: 1 */
					}; /* bitfield */
					union
					{
						/* 0x001a */ unsigned char AcquiredByte;
						struct
						{
							/* 0x001a */ unsigned char AcquiredBit : 1; /* bit position: 0 */
							union
							{
								/* 0x001b */ unsigned char CrossThreadFlags;
								struct /* bitfield */
								{
									/* 0x001b */ unsigned char HeadNodeBit : 1; /* bit position: 0 */
									/* 0x001b */ unsigned char IoPriorityBit : 1; /* bit position: 1 */
									/* 0x001b */ unsigned char IoQoSWaiter : 1; /* bit position: 2 */
									/* 0x001b */ unsigned char Spare1 : 5; /* bit position: 3 */
								}; /* bitfield */
							}; /* size: 0x0001 */
						}; /* size: 0x0002 */
					}; /* size: 0x0002 */
				}; /* size: 0x0003 */
			}; /* size: 0x0003 */
		}; /* size: 0x0004 */
		struct /* bitfield */
		{
			/* 0x0018 */ unsigned long StaticState : 8; /* bit position: 0 */
			/* 0x0018 */ unsigned long AllFlags : 24; /* bit position: 8 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x001c */ unsigned long SpareFlags;
	union
	{
		/* 0x0020 */ struct _KLOCK_ENTRY_LOCK_STATE LockState;
		/* 0x0020 */ void* volatile LockUnsafe;
		struct
		{
			/* 0x0020 */ volatile unsigned char CrossThreadReleasableAndBusyByte;
			/* 0x0021 */ unsigned char Reserved[6];
			/* 0x0027 */ volatile unsigned char InTreeByte;
			union
			{
				/* 0x0028 */ void* SessionState;
				struct
				{
					/* 0x0028 */ unsigned long SessionId;
					/* 0x002c */ unsigned long SessionPad;
				}; /* size: 0x0008 */
			}; /* size: 0x0008 */
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
	union
	{
		struct
		{
			/* 0x0030 */ struct _RTL_RB_TREE OwnerTree;
			/* 0x0040 */ struct _RTL_RB_TREE WaiterTree;
		}; /* size: 0x0020 */
		/* 0x0030 */ char CpuPriorityKey;
	}; /* size: 0x0020 */
	/* 0x0050 */ unsigned __int64 EntryLock;
	/* 0x0058 */ union _KLOCK_ENTRY_BOOST_BITMAP BoostBitmap;
	/* 0x005c */ unsigned long SparePad;
} KLOCK_ENTRY, * PKLOCK_ENTRY; /* size: 0x0060 */

typedef struct _PS_PROPERTY_SET
{
	/* 0x0000 */ struct _LIST_ENTRY ListHead;
	/* 0x0010 */ unsigned __int64 Lock;
} PS_PROPERTY_SET, * PPS_PROPERTY_SET; /* size: 0x0018 */

typedef struct _KTHREAD_S
{
	/* 0x0000 */ struct _DISPATCHER_HEADER Header;
	/* 0x0018 */ void* SListFaultAddress;
	/* 0x0020 */ unsigned __int64 QuantumTarget;
	/* 0x0028 */ void* InitialStack;
	/* 0x0030 */ void* volatile StackLimit;
	/* 0x0038 */ void* StackBase;
	/* 0x0040 */ unsigned __int64 ThreadLock;
	/* 0x0048 */ volatile unsigned __int64 CycleTime;
	/* 0x0050 */ unsigned long CurrentRunTime;
	/* 0x0054 */ unsigned long ExpectedRunTime;
	/* 0x0058 */ void* KernelStack;
	/* 0x0060 */ struct _XSAVE_FORMAT* StateSaveArea;
	/* 0x0068 */ struct _KSCHEDULING_GROUP* volatile SchedulingGroup;
	/* 0x0070 */ union _KWAIT_STATUS_REGISTER WaitRegister;
	/* 0x0071 */ volatile unsigned char Running;
	/* 0x0072 */ unsigned char Alerted[2];
	union
	{
		struct /* bitfield */
		{
			/* 0x0074 */ unsigned long AutoBoostActive : 1; /* bit position: 0 */
			/* 0x0074 */ unsigned long ReadyTransition : 1; /* bit position: 1 */
			/* 0x0074 */ unsigned long WaitNext : 1; /* bit position: 2 */
			/* 0x0074 */ unsigned long SystemAffinityActive : 1; /* bit position: 3 */
			/* 0x0074 */ unsigned long Alertable : 1; /* bit position: 4 */
			/* 0x0074 */ unsigned long UserStackWalkActive : 1; /* bit position: 5 */
			/* 0x0074 */ unsigned long ApcInterruptRequest : 1; /* bit position: 6 */
			/* 0x0074 */ unsigned long QuantumEndMigrate : 1; /* bit position: 7 */
			/* 0x0074 */ unsigned long UmsDirectedSwitchEnable : 1; /* bit position: 8 */
			/* 0x0074 */ unsigned long TimerActive : 1; /* bit position: 9 */
			/* 0x0074 */ unsigned long SystemThread : 1; /* bit position: 10 */
			/* 0x0074 */ unsigned long ProcessDetachActive : 1; /* bit position: 11 */
			/* 0x0074 */ unsigned long CalloutActive : 1; /* bit position: 12 */
			/* 0x0074 */ unsigned long ScbReadyQueue : 1; /* bit position: 13 */
			/* 0x0074 */ unsigned long ApcQueueable : 1; /* bit position: 14 */
			/* 0x0074 */ unsigned long ReservedStackInUse : 1; /* bit position: 15 */
			/* 0x0074 */ unsigned long UmsPerformingSyscall : 1; /* bit position: 16 */
			/* 0x0074 */ unsigned long TimerSuspended : 1; /* bit position: 17 */
			/* 0x0074 */ unsigned long SuspendedWaitMode : 1; /* bit position: 18 */
			/* 0x0074 */ unsigned long SuspendSchedulerApcWait : 1; /* bit position: 19 */
			/* 0x0074 */ unsigned long CetUserShadowStack : 1; /* bit position: 20 */
			/* 0x0074 */ unsigned long BypassProcessFreeze : 1; /* bit position: 21 */
			/* 0x0074 */ unsigned long Reserved : 10; /* bit position: 22 */
		}; /* bitfield */
		/* 0x0074 */ long MiscFlags;
	}; /* size: 0x0004 */
	union
	{
		struct /* bitfield */
		{
			/* 0x0078 */ unsigned long ThreadFlagsSpare : 2; /* bit position: 0 */
			/* 0x0078 */ unsigned long AutoAlignment : 1; /* bit position: 2 */
			/* 0x0078 */ unsigned long DisableBoost : 1; /* bit position: 3 */
			/* 0x0078 */ unsigned long AlertedByThreadId : 1; /* bit position: 4 */
			/* 0x0078 */ unsigned long QuantumDonation : 1; /* bit position: 5 */
			/* 0x0078 */ unsigned long EnableStackSwap : 1; /* bit position: 6 */
			/* 0x0078 */ unsigned long GuiThread : 1; /* bit position: 7 */
			/* 0x0078 */ unsigned long DisableQuantum : 1; /* bit position: 8 */
			/* 0x0078 */ unsigned long ChargeOnlySchedulingGroup : 1; /* bit position: 9 */
			/* 0x0078 */ unsigned long DeferPreemption : 1; /* bit position: 10 */
			/* 0x0078 */ unsigned long QueueDeferPreemption : 1; /* bit position: 11 */
			/* 0x0078 */ unsigned long ForceDeferSchedule : 1; /* bit position: 12 */
			/* 0x0078 */ unsigned long SharedReadyQueueAffinity : 1; /* bit position: 13 */
			/* 0x0078 */ unsigned long FreezeCount : 1; /* bit position: 14 */
			/* 0x0078 */ unsigned long TerminationApcRequest : 1; /* bit position: 15 */
			/* 0x0078 */ unsigned long AutoBoostEntriesExhausted : 1; /* bit position: 16 */
			/* 0x0078 */ unsigned long KernelStackResident : 1; /* bit position: 17 */
			/* 0x0078 */ unsigned long TerminateRequestReason : 2; /* bit position: 18 */
			/* 0x0078 */ unsigned long ProcessStackCountDecremented : 1; /* bit position: 20 */
			/* 0x0078 */ unsigned long RestrictedGuiThread : 1; /* bit position: 21 */
			/* 0x0078 */ unsigned long VpBackingThread : 1; /* bit position: 22 */
			/* 0x0078 */ unsigned long ThreadFlagsSpare2 : 1; /* bit position: 23 */
			/* 0x0078 */ unsigned long EtwStackTraceApcInserted : 8; /* bit position: 24 */
		}; /* bitfield */
		/* 0x0078 */ volatile long ThreadFlags;
	}; /* size: 0x0004 */
	/* 0x007c */ volatile unsigned char Tag;
	/* 0x007d */ unsigned char SystemHeteroCpuPolicy;
	struct /* bitfield */
	{
		/* 0x007e */ unsigned char UserHeteroCpuPolicy : 7; /* bit position: 0 */
		/* 0x007e */ unsigned char ExplicitSystemHeteroCpuPolicy : 1; /* bit position: 7 */
	}; /* bitfield */
	union
	{
		struct /* bitfield */
		{
			/* 0x007f */ unsigned char RunningNonRetpolineCode : 1; /* bit position: 0 */
			/* 0x007f */ unsigned char SpecCtrlSpare : 7; /* bit position: 1 */
		}; /* bitfield */
		/* 0x007f */ unsigned char SpecCtrl;
	}; /* size: 0x0001 */
	/* 0x0080 */ unsigned long SystemCallNumber;
	/* 0x0084 */ unsigned long ReadyTime;
	/* 0x0088 */ void* FirstArgument;
	/* 0x0090 */ struct _KTRAP_FRAME* TrapFrame;
	union
	{
		/* 0x0098 */ struct _KAPC_STATE ApcState;
		struct
		{
			/* 0x0098 */ unsigned char ApcStateFill[43];
			/* 0x00c3 */ char Priority;
			/* 0x00c4 */ unsigned long UserIdealProcessor;
		}; /* size: 0x0030 */
	}; /* size: 0x0030 */
	/* 0x00c8 */ volatile __int64 WaitStatus;
	/* 0x00d0 */ struct _KWAIT_BLOCK* WaitBlockList;
	union
	{
		/* 0x00d8 */ struct _LIST_ENTRY WaitListEntry;
		/* 0x00d8 */ struct _SINGLE_LIST_ENTRY SwapListEntry;
	}; /* size: 0x0010 */
	/* 0x00e8 */ struct _DISPATCHER_HEADER* volatile Queue;
	/* 0x00f0 */ void* Teb;
	/* 0x00f8 */ unsigned __int64 RelativeTimerBias;
	/* 0x0100 */ struct _KTIMER Timer;
	union
	{
		/* 0x0140 */ struct _KWAIT_BLOCK WaitBlock[4];
		struct
		{
			/* 0x0140 */ unsigned char WaitBlockFill4[20];
			/* 0x0154 */ unsigned long ContextSwitches;
		}; /* size: 0x0018 */
		struct
		{
			/* 0x0140 */ unsigned char WaitBlockFill5[68];
			/* 0x0184 */ volatile unsigned char State;
			/* 0x0185 */ char Spare13;
			/* 0x0186 */ unsigned char WaitIrql;
			/* 0x0187 */ char WaitMode;
		}; /* size: 0x0048 */
		struct
		{
			/* 0x0140 */ unsigned char WaitBlockFill6[116];
			/* 0x01b4 */ unsigned long WaitTime;
		}; /* size: 0x0078 */
		struct
		{
			/* 0x0140 */ unsigned char WaitBlockFill7[164];
			union
			{
				struct
				{
					/* 0x01e4 */ short KernelApcDisable;
					/* 0x01e6 */ short SpecialApcDisable;
				}; /* size: 0x0004 */
				/* 0x01e4 */ unsigned long CombinedApcDisable;
			}; /* size: 0x0004 */
		}; /* size: 0x00a8 */
		struct
		{
			/* 0x0140 */ unsigned char WaitBlockFill8[40];
			/* 0x0168 */ struct _KTHREAD_COUNTERS* ThreadCounters;
		}; /* size: 0x0030 */
		struct
		{
			/* 0x0140 */ unsigned char WaitBlockFill9[88];
			/* 0x0198 */ struct _XSTATE_SAVE* XStateSave;
		}; /* size: 0x0060 */
		struct
		{
			/* 0x0140 */ unsigned char WaitBlockFill10[136];
			/* 0x01c8 */ void* volatile Win32Thread;
		}; /* size: 0x0090 */
		struct
		{
			/* 0x0140 */ unsigned char WaitBlockFill11[176];
			/* 0x01f0 */ struct _UMS_CONTROL_BLOCK* Ucb;
			/* 0x01f8 */ struct _KUMS_CONTEXT_HEADER* volatile Uch;
		}; /* size: 0x00c0 */
	}; /* size: 0x00c0 */
	union
	{
		/* 0x0200 */ volatile long ThreadFlags2;
		struct /* bitfield */
		{
			/* 0x0200 */ unsigned long BamQosLevel : 8; /* bit position: 0 */
			/* 0x0200 */ unsigned long ThreadFlags2Reserved : 24; /* bit position: 8 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x0204 */ unsigned long Spare21;
	/* 0x0208 */ struct _LIST_ENTRY QueueListEntry;
	union
	{
		/* 0x0218 */ volatile unsigned long NextProcessor;
		struct /* bitfield */
		{
			/* 0x0218 */ unsigned long NextProcessorNumber : 31; /* bit position: 0 */
			/* 0x0218 */ unsigned long SharedReadyQueue : 1; /* bit position: 31 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x021c */ long QueuePriority;
	/* 0x0220 */ struct _KPROCESS* Process;
	union
	{
		/* 0x0228 */ struct _GROUP_AFFINITY UserAffinity;
		struct
		{
			/* 0x0228 */ unsigned char UserAffinityFill[10];
			/* 0x0232 */ char PreviousMode;
			/* 0x0233 */ char BasePriority;
			union
			{
				/* 0x0234 */ char PriorityDecrement;
				struct /* bitfield */
				{
					/* 0x0234 */ unsigned char ForegroundBoost : 4; /* bit position: 0 */
					/* 0x0234 */ unsigned char UnusualBoost : 4; /* bit position: 4 */
				}; /* bitfield */
			}; /* size: 0x0001 */
			/* 0x0235 */ unsigned char Preempted;
			/* 0x0236 */ unsigned char AdjustReason;
			/* 0x0237 */ char AdjustIncrement;
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
	/* 0x0238 */ unsigned __int64 AffinityVersion;
	union
	{
		/* 0x0240 */ struct _GROUP_AFFINITY Affinity;
		struct
		{
			/* 0x0240 */ unsigned char AffinityFill[10];
			/* 0x024a */ unsigned char ApcStateIndex;
			/* 0x024b */ unsigned char WaitBlockCount;
			/* 0x024c */ unsigned long IdealProcessor;
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
	/* 0x0250 */ unsigned __int64 NpxState;
	union
	{
		/* 0x0258 */ struct _KAPC_STATE SavedApcState;
		struct
		{
			/* 0x0258 */ unsigned char SavedApcStateFill[43];
			/* 0x0283 */ unsigned char WaitReason;
			/* 0x0284 */ char SuspendCount;
			/* 0x0285 */ char Saturation;
			/* 0x0286 */ unsigned short SListFaultCount;
		}; /* size: 0x0030 */
	}; /* size: 0x0030 */
	union
	{
		/* 0x0288 */ struct _KAPC SchedulerApc;
		struct
		{
			/* 0x0288 */ unsigned char SchedulerApcFill0[1];
			/* 0x0289 */ unsigned char ResourceIndex;
		}; /* size: 0x0002 */
		struct
		{
			/* 0x0288 */ unsigned char SchedulerApcFill1[3];
			/* 0x028b */ unsigned char QuantumReset;
		}; /* size: 0x0004 */
		struct
		{
			/* 0x0288 */ unsigned char SchedulerApcFill2[4];
			/* 0x028c */ unsigned long KernelTime;
		}; /* size: 0x0008 */
		struct
		{
			/* 0x0288 */ unsigned char SchedulerApcFill3[64];
			/* 0x02c8 */ struct _KPRCB* volatile WaitPrcb;
		}; /* size: 0x0048 */
		struct
		{
			/* 0x0288 */ unsigned char SchedulerApcFill4[72];
			/* 0x02d0 */ void* LegoData;
		}; /* size: 0x0050 */
		struct
		{
			/* 0x0288 */ unsigned char SchedulerApcFill5[83];
			/* 0x02db */ unsigned char CallbackNestingLevel;
			/* 0x02dc */ unsigned long UserTime;
		}; /* size: 0x0058 */
	}; /* size: 0x0058 */
	/* 0x02e0 */ struct _KEVENT SuspendEvent;
	/* 0x02f8 */ struct _LIST_ENTRY ThreadListEntry;
	/* 0x0308 */ struct _LIST_ENTRY MutantListHead;
	/* 0x0318 */ unsigned char AbEntrySummary;
	/* 0x0319 */ unsigned char AbWaitEntryCount;
	/* 0x031a */ unsigned char AbAllocationRegionCount;
	/* 0x031b */ char SystemPriority;
	/* 0x031c */ unsigned long SecureThreadCookie;
	/* 0x0320 */ struct _KLOCK_ENTRY* LockEntries;
	/* 0x0328 */ struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;
	/* 0x0330 */ struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;
	/* 0x0338 */ unsigned char PriorityFloorCounts[16];
	/* 0x0348 */ unsigned char PriorityFloorCountsReserved[16];
	/* 0x0358 */ unsigned long PriorityFloorSummary;
	/* 0x035c */ volatile long AbCompletedIoBoostCount;
	/* 0x0360 */ volatile long AbCompletedIoQoSBoostCount;
	/* 0x0364 */ volatile short KeReferenceCount;
	/* 0x0366 */ unsigned char AbOrphanedEntrySummary;
	/* 0x0367 */ unsigned char AbOwnedEntryCount;
	/* 0x0368 */ unsigned long ForegroundLossTime;
	/* 0x036c */ long Padding_0;
	union
	{
		/* 0x0370 */ struct _LIST_ENTRY GlobalForegroundListEntry;
		struct
		{
			/* 0x0370 */ struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;
			/* 0x0378 */ unsigned __int64 InGlobalForegroundList;
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
	/* 0x0380 */ __int64 ReadOperationCount;
	/* 0x0388 */ __int64 WriteOperationCount;
	/* 0x0390 */ __int64 OtherOperationCount;
	/* 0x0398 */ __int64 ReadTransferCount;
	/* 0x03a0 */ __int64 WriteTransferCount;
	/* 0x03a8 */ __int64 OtherTransferCount;
	/* 0x03b0 */ struct _KSCB* QueuedScb;
	/* 0x03b8 */ volatile unsigned long ThreadTimerDelay;
	union
	{
		/* 0x03bc */ volatile long ThreadFlags3;
		struct /* bitfield */
		{
			/* 0x03bc */ unsigned long ThreadFlags3Reserved : 8; /* bit position: 0 */
			/* 0x03bc */ unsigned long PpmPolicy : 2; /* bit position: 8 */
			/* 0x03bc */ unsigned long ThreadFlags3Reserved2 : 22; /* bit position: 10 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x03c0 */ unsigned __int64 TracingPrivate[1];
	/* 0x03c8 */ void* SchedulerAssist;
	/* 0x03d0 */ void* volatile AbWaitObject;
	/* 0x03d8 */ unsigned long ReservedPreviousReadyTimeValue;
	/* 0x03dc */ long Padding_1;
	/* 0x03e0 */ unsigned __int64 KernelWaitTime;
	/* 0x03e8 */ unsigned __int64 UserWaitTime;
	union
	{
		/* 0x03f0 */ struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;
		struct
		{
			/* 0x03f0 */ struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry;
			/* 0x03f8 */ unsigned __int64 InGlobalUpdateVpThreadPriorityList;
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
	/* 0x0400 */ long SchedulerAssistPriorityFloor;
	/* 0x0404 */ unsigned long Spare28;
	/* 0x0408 */ unsigned __int64 EndPadding[5];
} KTHREAD_S, * PKTHREAD_S; /* size: 0x0430 */

typedef struct _ETHREAD_S
{
	/* 0x0000 */ struct _KTHREAD_S Tcb;
	/* 0x0430 */ union _LARGE_INTEGER CreateTime;
	union
	{
		/* 0x0438 */ union _LARGE_INTEGER ExitTime;
		/* 0x0438 */ struct _LIST_ENTRY KeyedWaitChain;
	}; /* size: 0x0010 */
	union
	{
		/* 0x0448 */ struct _LIST_ENTRY PostBlockList;
		struct
		{
			/* 0x0448 */ void* ForwardLinkShadow;
			/* 0x0450 */ void* StartAddress;
		}; /* size: 0x0010 */
	}; /* size: 0x0010 */
	union
	{
		/* 0x0458 */ struct _TERMINATION_PORT* TerminationPort;
		/* 0x0458 */ struct _ETHREAD* ReaperLink;
		/* 0x0458 */ void* KeyedWaitValue;
	}; /* size: 0x0008 */
	/* 0x0460 */ unsigned __int64 ActiveTimerListLock;
	/* 0x0468 */ struct _LIST_ENTRY ActiveTimerListHead;
	/* 0x0478 */ struct _CLIENT_ID Cid;
	union
	{
		/* 0x0488 */ struct _KSEMAPHORE KeyedWaitSemaphore;
		/* 0x0488 */ struct _KSEMAPHORE AlpcWaitSemaphore;
	}; /* size: 0x0020 */
	/* 0x04a8 */ union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;
	/* 0x04b0 */ struct _LIST_ENTRY IrpList;
	/* 0x04c0 */ unsigned __int64 TopLevelIrp;
	/* 0x04c8 */ struct _DEVICE_OBJECT* DeviceToVerify;
	/* 0x04d0 */ void* Win32StartAddress;
	/* 0x04d8 */ void* ChargeOnlySession;
	/* 0x04e0 */ void* LegacyPowerObject;
	/* 0x04e8 */ struct _LIST_ENTRY ThreadListEntry;
	/* 0x04f8 */ struct _EX_RUNDOWN_REF RundownProtect;
	/* 0x0500 */ struct _EX_PUSH_LOCK ThreadLock;
	/* 0x0508 */ unsigned long ReadClusterSize;
	/* 0x050c */ volatile long MmLockOrdering;
	union
	{
		/* 0x0510 */ unsigned long CrossThreadFlags;
		struct /* bitfield */
		{
			/* 0x0510 */ unsigned long Terminated : 1; /* bit position: 0 */
			/* 0x0510 */ unsigned long ThreadInserted : 1; /* bit position: 1 */
			/* 0x0510 */ unsigned long HideFromDebugger : 1; /* bit position: 2 */
			/* 0x0510 */ unsigned long ActiveImpersonationInfo : 1; /* bit position: 3 */
			/* 0x0510 */ unsigned long HardErrorsAreDisabled : 1; /* bit position: 4 */
			/* 0x0510 */ unsigned long BreakOnTermination : 1; /* bit position: 5 */
			/* 0x0510 */ unsigned long SkipCreationMsg : 1; /* bit position: 6 */
			/* 0x0510 */ unsigned long SkipTerminationMsg : 1; /* bit position: 7 */
			/* 0x0510 */ unsigned long CopyTokenOnOpen : 1; /* bit position: 8 */
			/* 0x0510 */ unsigned long ThreadIoPriority : 3; /* bit position: 9 */
			/* 0x0510 */ unsigned long ThreadPagePriority : 3; /* bit position: 12 */
			/* 0x0510 */ unsigned long RundownFail : 1; /* bit position: 15 */
			/* 0x0510 */ unsigned long UmsForceQueueTermination : 1; /* bit position: 16 */
			/* 0x0510 */ unsigned long IndirectCpuSets : 1; /* bit position: 17 */
			/* 0x0510 */ unsigned long DisableDynamicCodeOptOut : 1; /* bit position: 18 */
			/* 0x0510 */ unsigned long ExplicitCaseSensitivity : 1; /* bit position: 19 */
			/* 0x0510 */ unsigned long PicoNotifyExit : 1; /* bit position: 20 */
			/* 0x0510 */ unsigned long DbgWerUserReportActive : 1; /* bit position: 21 */
			/* 0x0510 */ unsigned long ForcedSelfTrimActive : 1; /* bit position: 22 */
			/* 0x0510 */ unsigned long SamplingCoverage : 1; /* bit position: 23 */
			/* 0x0510 */ unsigned long ReservedCrossThreadFlags : 8; /* bit position: 24 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	union
	{
		/* 0x0514 */ unsigned long SameThreadPassiveFlags;
		struct /* bitfield */
		{
			/* 0x0514 */ unsigned long ActiveExWorker : 1; /* bit position: 0 */
			/* 0x0514 */ unsigned long MemoryMaker : 1; /* bit position: 1 */
			/* 0x0514 */ unsigned long StoreLockThread : 2; /* bit position: 2 */
			/* 0x0514 */ unsigned long ClonedThread : 1; /* bit position: 4 */
			/* 0x0514 */ unsigned long KeyedEventInUse : 1; /* bit position: 5 */
			/* 0x0514 */ unsigned long SelfTerminate : 1; /* bit position: 6 */
			/* 0x0514 */ unsigned long RespectIoPriority : 1; /* bit position: 7 */
			/* 0x0514 */ unsigned long ActivePageLists : 1; /* bit position: 8 */
			/* 0x0514 */ unsigned long SecureContext : 1; /* bit position: 9 */
			/* 0x0514 */ unsigned long ZeroPageThread : 1; /* bit position: 10 */
			/* 0x0514 */ unsigned long WorkloadClass : 1; /* bit position: 11 */
			/* 0x0514 */ unsigned long ReservedSameThreadPassiveFlags : 20; /* bit position: 12 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	union
	{
		/* 0x0518 */ unsigned long SameThreadApcFlags;
		struct
		{
			struct /* bitfield */
			{
				/* 0x0518 */ unsigned char OwnsProcessAddressSpaceExclusive : 1; /* bit position: 0 */
				/* 0x0518 */ unsigned char OwnsProcessAddressSpaceShared : 1; /* bit position: 1 */
				/* 0x0518 */ unsigned char HardFaultBehavior : 1; /* bit position: 2 */
				/* 0x0518 */ volatile unsigned char StartAddressInvalid : 1; /* bit position: 3 */
				/* 0x0518 */ unsigned char EtwCalloutActive : 1; /* bit position: 4 */
				/* 0x0518 */ unsigned char SuppressSymbolLoad : 1; /* bit position: 5 */
				/* 0x0518 */ unsigned char Prefetching : 1; /* bit position: 6 */
				/* 0x0518 */ unsigned char OwnsVadExclusive : 1; /* bit position: 7 */
			}; /* bitfield */
			struct /* bitfield */
			{
				/* 0x0519 */ unsigned char SystemPagePriorityActive : 1; /* bit position: 0 */
				/* 0x0519 */ unsigned char SystemPagePriority : 3; /* bit position: 1 */
				/* 0x0519 */ unsigned char AllowUserWritesToExecutableMemory : 1; /* bit position: 4 */
				/* 0x0519 */ unsigned char AllowKernelWritesToExecutableMemory : 1; /* bit position: 5 */
				/* 0x0519 */ unsigned char OwnsVadShared : 1; /* bit position: 6 */
			}; /* bitfield */
		}; /* size: 0x0002 */
	}; /* size: 0x0004 */
	/* 0x051c */ unsigned char CacheManagerActive;
	/* 0x051d */ unsigned char DisablePageFaultClustering;
	/* 0x051e */ unsigned char ActiveFaultCount;
	/* 0x051f */ unsigned char LockOrderState;
	/* 0x0520 */ unsigned long PerformanceCountLowReserved;
	/* 0x0524 */ long PerformanceCountHighReserved;
	/* 0x0528 */ unsigned __int64 AlpcMessageId;
	union
	{
		/* 0x0530 */ void* AlpcMessage;
		/* 0x0530 */ unsigned long AlpcReceiveAttributeSet;
	}; /* size: 0x0008 */
	/* 0x0538 */ struct _LIST_ENTRY AlpcWaitListEntry;
	/* 0x0548 */ long ExitStatus;
	/* 0x054c */ unsigned long CacheManagerCount;
	/* 0x0550 */ unsigned long IoBoostCount;
	/* 0x0554 */ unsigned long IoQoSBoostCount;
	/* 0x0558 */ unsigned long IoQoSThrottleCount;
	/* 0x055c */ unsigned long KernelStackReference;
	/* 0x0560 */ struct _LIST_ENTRY BoostList;
	/* 0x0570 */ struct _LIST_ENTRY DeboostList;
	/* 0x0580 */ unsigned __int64 BoostListLock;
	/* 0x0588 */ unsigned __int64 IrpListLock;
	/* 0x0590 */ void* ReservedForSynchTracking;
	/* 0x0598 */ struct _SINGLE_LIST_ENTRY CmCallbackListHead;
	/* 0x05a0 */ const struct _GUID* ActivityId;
	/* 0x05a8 */ struct _SINGLE_LIST_ENTRY SeLearningModeListHead;
	/* 0x05b0 */ void* VerifierContext;
	/* 0x05b8 */ void* AdjustedClientToken;
	/* 0x05c0 */ void* WorkOnBehalfThread;
	/* 0x05c8 */ struct _PS_PROPERTY_SET PropertySet;
	/* 0x05e0 */ void* PicoContext;
	/* 0x05e8 */ unsigned __int64 UserFsBase;
	/* 0x05f0 */ unsigned __int64 UserGsBase;
	/* 0x05f8 */ struct _THREAD_ENERGY_VALUES* EnergyValues;
	union
	{
		/* 0x0600 */ unsigned __int64 SelectedCpuSets;
		/* 0x0600 */ unsigned __int64* SelectedCpuSetsIndirect;
	}; /* size: 0x0008 */
	/* 0x0608 */ struct _EJOB* Silo;
	/* 0x0610 */ struct _UNICODE_STRING* ThreadName;
	/* 0x0618 */ struct _CONTEXT* SetContextState;
	/* 0x0620 */ unsigned long LastExpectedRunTime;
	/* 0x0624 */ unsigned long HeapData;
	/* 0x0628 */ struct _LIST_ENTRY OwnerEntryListHead;
	/* 0x0638 */ unsigned __int64 DisownedOwnerEntryListLock;
	/* 0x0640 */ struct _LIST_ENTRY DisownedOwnerEntryListHead;
	/* 0x0650 */ struct _KLOCK_ENTRY LockEntries[6];
	/* 0x0890 */ void* CmDbgInfo;
} ETHREAD_S, * PETHREAD_S; /* size: 0x0898 */
#endif // !_KTHREAD_S_


#define DEBUG_OBJECT_DELETE_PENDING			(0x1) // Debug object is delete pending.
#define DEBUG_OBJECT_KILL_ON_CLOSE			(0x2) // Kill all debugged processes on close
#define DEBUG_KILL_ON_CLOSE					(0x01)
#define DEBUG_EVENT_READ					(0x01)  // Event had been seen by win32 app
#define DEBUG_EVENT_NOWAIT					(0x02)  // No waiter one this. Just free the pool
#define DEBUG_EVENT_INACTIVE				(0x04)  // The message is in inactive. It may be activated or deleted later
#define DEBUG_EVENT_RELEASE					(0x08)  // Release rundown protection on this thread
#define DEBUG_EVENT_PROTECT_FAILED			(0x10)  // Rundown protection failed to be acquired on this thread
#define DEBUG_EVENT_SUSPEND					(0x20)  // Resume thread on continue

//
// Define debug object access types. No security is present on this object.
//
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
	DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

//一些内核其他定义声明

//
// Used to signify that the delete APC has been queued or the
// thread has called PspExitThread itself.
//
#define PS_CROSS_THREAD_FLAGS_TERMINATED           0x00000001UL
//
// Thread create failed
//
#define PS_CROSS_THREAD_FLAGS_DEADTHREAD           0x00000002UL
//
// Debugger isn't shown this thread
//
#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG          0x00000004UL
//
// Thread is impersonating
//
#define PS_CROSS_THREAD_FLAGS_IMPERSONATING        0x00000008UL
//
// This is a system thread
//
#define PS_CROSS_THREAD_FLAGS_SYSTEM               0x00000010UL
//
// Hard errors are disabled for this thread
//
#define PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED 0x00000020UL
//
// We should break in when this thread is terminated
//
#define PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION 0x00000040UL
//
// This thread should skip sending its create thread message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG    0x00000080UL
//
// This thread should skip sending its final thread termination message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x00000100UL

#define IS_SYSTEM_THREAD(Thread)  (((Thread)->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SYSTEM) != 0)

#define PS_PROCESS_FLAGS_CREATE_REPORTED        0x00000001UL // Create process debug call has occurred
#define PS_PROCESS_FLAGS_NO_DEBUG_INHERIT       0x00000002UL // Don't inherit debug port
#define PS_PROCESS_FLAGS_PROCESS_EXITING        0x00000004UL // PspExitProcess entered
#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL // Delete process has been issued
#define PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES      0x00000010UL // Wow64 split pages
#define PS_PROCESS_FLAGS_VM_DELETED             0x00000020UL // VM is deleted
#define PS_PROCESS_FLAGS_OUTSWAP_ENABLED        0x00000040UL // Outswap enabled
#define PS_PROCESS_FLAGS_OUTSWAPPED             0x00000080UL // Outswapped
#define PS_PROCESS_FLAGS_FORK_FAILED            0x00000100UL // Fork status
#define PS_PROCESS_FLAGS_WOW64_4GB_VA_SPACE     0x00000200UL // Wow64 process with 4gb virtual address space
#define PS_PROCESS_FLAGS_ADDRESS_SPACE1         0x00000400UL // Addr space state1
#define PS_PROCESS_FLAGS_ADDRESS_SPACE2         0x00000800UL // Addr space state2
#define PS_PROCESS_FLAGS_SET_TIMER_RESOLUTION   0x00001000UL // SetTimerResolution has been called
#define PS_PROCESS_FLAGS_BREAK_ON_TERMINATION   0x00002000UL // Break on process termination
#define PS_PROCESS_FLAGS_CREATING_SESSION       0x00004000UL // Process is creating a session
#define PS_PROCESS_FLAGS_USING_WRITE_WATCH      0x00008000UL // Process is using the write watch APIs
#define PS_PROCESS_FLAGS_IN_SESSION             0x00010000UL // Process is in a session
#define PS_PROCESS_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00020000UL // Process must use native address space (Win64 only)
#define PS_PROCESS_FLAGS_HAS_ADDRESS_SPACE      0x00040000UL // This process has an address space
#define PS_PROCESS_FLAGS_LAUNCH_PREFETCHED      0x00080000UL // Process launch was prefetched
#define PS_PROCESS_INJECT_INPAGE_ERRORS         0x00100000UL // Process should be given inpage errors - hardcoded in trap.asm too
#define PS_PROCESS_FLAGS_VM_TOP_DOWN            0x00200000UL // Process memory allocations default to top-down
#define PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE      0x00400000UL // We have sent a message for this image
#define PS_PROCESS_FLAGS_PDE_UPDATE_NEEDED      0x00800000UL // The system PDEs need updating for this process (NT32 only)
#define PS_PROCESS_FLAGS_VDM_ALLOWED            0x01000000UL // Process allowed to invoke NTVDM support
#define PS_PROCESS_FLAGS_SMAP_ALLOWED           0x02000000UL // Process allowed to invoke SMAP support
#define PS_PROCESS_FLAGS_CREATE_FAILED          0x04000000UL // Process create failed

#define PS_PROCESS_FLAGS_DEFAULT_IO_PRIORITY    0x38000000UL // The default I/O priority for created threads. (3 bits)

#define PS_PROCESS_FLAGS_PRIORITY_SHIFT         27

#define PS_PROCESS_FLAGS_EXECUTE_SPARE1         0x40000000UL //
#define PS_PROCESS_FLAGS_EXECUTE_SPARE2         0x80000000UL //


#define THREAD_TERMINATE						(0x0001)  
#define THREAD_SUSPEND_RESUME					(0x0002)  
#define THREAD_GET_CONTEXT						(0x0008)  
#define THREAD_SET_CONTEXT						(0x0010)  
#define THREAD_QUERY_INFORMATION				(0x0040)  
#define THREAD_SET_INFORMATION					(0x0020)  
#define THREAD_SET_THREAD_TOKEN					(0x0080)
#define THREAD_IMPERSONATE						(0x0100)
#define THREAD_DIRECT_IMPERSONATION				(0x0200)

#define PROCESS_TERMINATE						(0x0001)  
#define PROCESS_CREATE_THREAD					(0x0002)  
#define PROCESS_SET_SESSIONID					(0x0004)  
#define PROCESS_VM_OPERATION					(0x0008)  
#define PROCESS_VM_READ							(0x0010)  
#define PROCESS_VM_WRITE						(0x0020)  
#define PROCESS_DUP_HANDLE						(0x0040)  
#define PROCESS_CREATE_PROCESS					(0x0080)  
#define PROCESS_SET_QUOTA						(0x0100)  
#define PROCESS_SET_INFORMATION					(0x0200)  
#define PROCESS_QUERY_INFORMATION				(0x0400)  
#define PROCESS_SUSPEND_RESUME					(0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION		(0x1000)  
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFF)


#define LPC_REQUEST								1
#define LPC_REPLY								2
#define LPC_DATAGRAM							3
#define LPC_LOST_REPLY							4
#define LPC_PORT_CLOSED							5
#define LPC_CLIENT_DIED							6
#define LPC_EXCEPTION							7
#define LPC_DEBUG_EVENT							8
#define LPC_ERROR_EVENT							9
#define LPC_CONNECTION_REQUEST					10
#define DBGK_KILL_PROCESS_ON_EXIT         (0x1)
#define DBGK_ALL_FLAGS                    (DBGK_KILL_PROCESS_ON_EXIT)

typedef struct _OBJECT_TYPE_INITIALIZER_S                                                                                                                                      // 25 elements, 0x70 bytes (sizeof)
{
	/*0x000*/     UINT16       Length;
	union                                                                                                                                                                       // 2 elements, 0x1 bytes (sizeof)
	{
		/*0x002*/         UINT16        ObjectTypeFlags;
		struct                                                                                                                                                                  // 7 elements, 0x1 bytes (sizeof)
		{
			/*0x002*/             UINT8        CaseInsensitive : 1;                                                                                                                                   // 0 BitPosition
			/*0x002*/             UINT8        UnnamedObjectsOnly : 1;                                                                                                                                // 1 BitPosition
			/*0x002*/             UINT8        UseDefaultObject : 1;                                                                                                                                  // 2 BitPosition
			/*0x002*/             UINT8        SecurityRequired : 1;                                                                                                                                  // 3 BitPosition
			/*0x002*/             UINT8        MaintainHandleCount : 1;                                                                                                                               // 4 BitPosition
			/*0x002*/             UINT8        MaintainTypeList : 1;                                                                                                                                  // 5 BitPosition
			/*0x002*/             UINT8        SupportsObjectCallbacks : 1;                                                                                                                           // 6 BitPosition
		};
	};
	/*0x004*/     ULONG32      ObjectTypeCode;
	/*0x008*/     ULONG32      InvalidAttributes;
	/*0x00C*/     struct _GENERIC_MAPPING GenericMapping;                                                                                                                                     // 4 elements, 0x10 bytes (sizeof)
	/*0x01C*/     ULONG32      ValidAccessMask;
	/*0x020*/     ULONG32      RetainAccess;
	/*0x024*/     enum _POOL_TYPE PoolType;
	/*0x028*/     ULONG32      DefaultPagedPoolCharge;
	/*0x02C*/     ULONG32      DefaultNonPagedPoolCharge;
	/*0x030*/     PVOID DumpProcedure;
	/*0x038*/     PVOID OpenProcedure;
	/*0x040*/     PVOID CloseProcedure;
	/*0x048*/     PVOID DeleteProcedure;
	/*0x050*/     PVOID ParseProcedure;
	/*0x058*/     PVOID SecurityProcedure;
	/*0x060*/     PVOID QueryNameProcedure;
	/*0x068*/     PVOID OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER_S, * POBJECT_TYPE_INITIALIZER_S;

/*
+0x000 Length           : Uint2B
+ 0x002 ObjectTypeFlags : Uint2B
+ 0x002 CaseInsensitive : Pos 0, 1 Bit
+ 0x002 UnnamedObjectsOnly : Pos 1, 1 Bit
+ 0x002 UseDefaultObject : Pos 2, 1 Bit
+ 0x002 SecurityRequired : Pos 3, 1 Bit
+ 0x002 MaintainHandleCount : Pos 4, 1 Bit
+ 0x002 MaintainTypeList : Pos 5, 1 Bit
+ 0x002 SupportsObjectCallbacks : Pos 6, 1 Bit
+ 0x002 CacheAligned : Pos 7, 1 Bit
+ 0x003 UseExtendedParameters : Pos 0, 1 Bit
+ 0x003 Reserved : Pos 1, 7 Bits
+ 0x004 ObjectTypeCode : Uint4B
+ 0x008 InvalidAttributes : Uint4B
+ 0x00c GenericMapping : _GENERIC_MAPPING
+ 0x01c ValidAccessMask : Uint4B
+ 0x020 RetainAccess : Uint4B
+ 0x024 PoolType : _POOL_TYPE
+ 0x028 DefaultPagedPoolCharge : Uint4B
+ 0x02c DefaultNonPagedPoolCharge : Uint4B
+ 0x030 DumpProcedure : Ptr64     void
+ 0x038 OpenProcedure : Ptr64     long
+ 0x040 CloseProcedure : Ptr64     void
+ 0x048 DeleteProcedure : Ptr64     void
+ 0x050 ParseProcedure : Ptr64     long
+ 0x050 ParseProcedureEx : Ptr64     long
+ 0x058 SecurityProcedure : Ptr64     long
+ 0x060 QueryNameProcedure : Ptr64     long
+ 0x068 OkayToCloseProcedure : Ptr64     unsigned char
+ 0x070 WaitObjectFlagMask : Uint4B
+ 0x074 WaitObjectFlagOffset : Uint2B
+ 0x076 WaitObjectPointerOffset : Uint2B
*/

typedef struct _OBJECT_TYPE_S                    // 12 elements, 0xD0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)
	/*0x020*/     VOID* DefaultObject;
	/*0x028*/     UINT8        Index;
	/*0x02C*/     ULONG32      TotalNumberOfObjects;
	/*0x030*/     ULONG32      TotalNumberOfHandles;
	/*0x034*/     ULONG32      HighWaterNumberOfObjects;
	/*0x038*/     ULONG32      HighWaterNumberOfHandles;
	/*0x040*/     struct _OBJECT_TYPE_INITIALIZER_S TypeInfo; // 25 elements, 0x70 bytes (sizeof)
	/*0x0B8*/     struct _EX_PUSH_LOCK TypeLock;            // 7 elements, 0x8 bytes (sizeof)
	/*0x0C0*/     ULONG32      Key;
	/*0x0C8*/     struct _LIST_ENTRY CallbackList;          // 2 elements, 0x10 bytes (sizeof)
}OBJECT_TYPE_S, * POBJECT_TYPE_S;

/*
+0x000 TypeList         : _LIST_ENTRY
+ 0x010 Name : _UNICODE_STRING
+ 0x020 DefaultObject : Ptr64 Void
+ 0x028 Index : UChar
+ 0x02c TotalNumberOfObjects : Uint4B
+ 0x030 TotalNumberOfHandles : Uint4B
+ 0x034 HighWaterNumberOfObjects : Uint4B
+ 0x038 HighWaterNumberOfHandles : Uint4B
+ 0x040 TypeInfo : _OBJECT_TYPE_INITIALIZER
+ 0x0b8 TypeLock : _EX_PUSH_LOCK
+ 0x0c0 Key : Uint4B
+ 0x0c8 CallbackList : _LIST_ENTRY
*/

#ifndef _MODULE_INFO_
#define _MODULE_INFO_
typedef struct _MODULE_INFO
{
	ULONG64			UnKown1;
	UNICODE_STRING	FileName;		//+0x4
	PVOID			BaseOfDll;		//+0xC
	wchar_t* Buffer;			//+0x10
	//...
}MODULE_INFO, * PMODULE_INFO;
#endif // !_MODULE_INFO_

#ifndef _SYSTEM_DLL_
#define _SYSTEM_DLL_
typedef struct _SYSTEM_DLL
{
	EX_FAST_REF		FastRef;
	EX_PUSH_LOCK	Lock;
	MODULE_INFO		ModuleInfo;
}SYSTEM_DLL, * PSYSTEM_DLL;
#endif // !_SYSTEM_DLL_

typedef NTSTATUS
(*OBCREATEOBJECTTYPE)(
	PUNICODE_STRING usTypeName,
	POBJECT_TYPE_INITIALIZER_S ObjectTypeInit,
	PVOID	Reserved,
	POBJECT_TYPE* ObjectType);

#ifndef _KAFFINITY_EX_
#define _KAFFINITY_EX_
typedef struct _KAFFINITY_EX // 4 elements, 0x28 bytes (sizeof)
{
	/*0x000*/     UINT16       Count;
	/*0x002*/     UINT16       Size;
	/*0x004*/     ULONG32      Reserved;
	/*0x008*/     UINT64       Bitmap[4];
}KAFFINITY_EX, * PKAFFINITY_EX;
#endif // !_KAFFINITY_EX_

typedef struct _KGUARDED_MUTEX64              // 7 elements, 0x38 bytes (sizeof)
{
	/*0x000*/     LONG32       Count;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     ULONG64 Owner;
	/*0x010*/     ULONG32      Contention;
	/*0x014*/     UINT8        _PADDING1_[0x4];
	/*0x018*/     struct _KGATE Gate;                     // 1 elements, 0x18 bytes (sizeof)
	union                                   // 2 elements, 0x8 bytes (sizeof)
	{
		struct                              // 2 elements, 0x8 bytes (sizeof)
		{
			/*0x030*/             INT16        KernelApcDisable;
			/*0x032*/             INT16        SpecialApcDisable;
			/*0x034*/             UINT8        _PADDING2_[0x4];
		};
		/*0x030*/         ULONG32      CombinedApcDisable;
	};
}KGUARDED_MUTEX64, * PKGUARDED_MUTEX64;

typedef union _KGDTENTRY64 {
	struct {
		USHORT  LimitLow;
		USHORT  BaseLow;
		union {
			struct {
				UCHAR   BaseMiddle;
				UCHAR   Flags1;
				UCHAR   Flags2;
				UCHAR   BaseHigh;
			} Bytes;

			struct {
				ULONG   BaseMiddle : 8;
				ULONG   Type : 5;//把S位包含进去了，也就是是否为系统段描述符的位。
				ULONG   Dpl : 2;
				ULONG   Present : 1;
				ULONG   LimitHigh : 4;
				ULONG   System : 1;//即AVL，系统软件自定义的。
				ULONG   LongMode : 1;
				ULONG   DefaultBig : 1;//即INTEL的D/B (default operation size/default stack pointer size and/or upper bound) flag。
				ULONG   Granularity : 1;
				ULONG   BaseHigh : 8;
			} Bits;
		};

		ULONG BaseUpper;
		ULONG MustBeZero;
	};

	ULONG64 Alignment;
} KGDTENTRY64, * PKGDTENTRY64;

typedef struct _PS_PER_CPU_QUOTA_CACHE_AWARE // 5 elements, 0x40 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY SortedListEntry;      // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _LIST_ENTRY IdleOnlyListHead;     // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     UINT64       CycleBaseAllowance;
	/*0x028*/     INT64        CyclesRemaining;
	/*0x030*/     ULONG32      CurrentGeneration;
	/*0x034*/     UINT8        _PADDING0_[0xC];
}PS_PER_CPU_QUOTA_CACHE_AWARE, * PPS_PER_CPU_QUOTA_CACHE_AWARE;

#ifndef _MMADDRESS_NODE_
#define _MMADDRESS_NODE_
typedef struct _MMADDRESS_NODE          // 5 elements, 0x28 bytes (sizeof)
{
	union                               // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x000*/         INT64        Balance : 2;       // 0 BitPosition
		/*0x000*/         struct _MMADDRESS_NODE* Parent;
	}u1;
	/*0x008*/     struct _MMADDRESS_NODE* LeftChild;
	/*0x010*/     struct _MMADDRESS_NODE* RightChild;
	/*0x018*/     UINT64       StartingVpn;
	/*0x020*/     UINT64       EndingVpn;
}MMADDRESS_NODE, * PMMADDRESS_NODE;
#endif // !_MMADDRESS_NODE_

typedef struct _MM_AVL_TABLE                          // 6 elements, 0x40 bytes (sizeof)
{
	/*0x000*/     struct _MMADDRESS_NODE BalancedRoot;              // 5 elements, 0x28 bytes (sizeof)
	struct                                            // 3 elements, 0x8 bytes (sizeof)
	{
		/*0x028*/         UINT64       DepthOfTree : 5;                 // 0 BitPosition
		/*0x028*/         UINT64       Unused : 3;                      // 5 BitPosition
		/*0x028*/         UINT64       NumberGenericTableElements : 56; // 8 BitPosition
	};
	/*0x030*/     VOID* NodeHint;
	/*0x038*/     VOID* NodeFreeHint;
}MM_AVL_TABLE, * PMM_AVL_TABLE;

typedef struct _PS_CPU_QUOTA_BLOCK                                        // 14 elements, 0x4080 bytes (sizeof)
{
	union                                                                 // 2 elements, 0x40 bytes (sizeof)
	{
		struct                                                            // 5 elements, 0x40 bytes (sizeof)
		{
			/*0x000*/             struct _LIST_ENTRY ListEntry;                                 // 2 elements, 0x10 bytes (sizeof)
			/*0x010*/             ULONG32      SessionId;
			/*0x014*/             ULONG32      CpuShareWeight;
			/*0x018*/             CHAR CapturedWeightData[0x8]; // 3 elements, 0x8 bytes (sizeof)
			union                                                         // 2 elements, 0x4 bytes (sizeof)
			{
				struct                                                    // 2 elements, 0x4 bytes (sizeof)
				{
					/*0x020*/                     ULONG32      DuplicateInputMarker : 1;                // 0 BitPosition
					/*0x020*/                     ULONG32      Reserved : 31;                           // 1 BitPosition
				};
				/*0x020*/                 LONG32       MiscFlags;
			};
		};
		struct                                                            // 2 elements, 0x40 bytes (sizeof)
		{
			/*0x000*/             UINT64       BlockCurrentGenerationLock;
			/*0x008*/             UINT64       CyclesAccumulated;
			/*0x010*/             UINT8        _PADDING0_[0x30];
		};
	};
	/*0x040*/     UINT64       CycleCredit;
	/*0x048*/     ULONG32      BlockCurrentGeneration;
	/*0x04C*/     ULONG32      CpuCyclePercent;
	/*0x050*/     UINT8        CyclesFinishedForCurrentGeneration;
	/*0x051*/     UINT8        _PADDING1_[0x2F];
	/*0x080*/     struct _PS_PER_CPU_QUOTA_CACHE_AWARE Cpu[256];
}PS_CPU_QUOTA_BLOCK, * PPS_CPU_QUOTA_BLOCK;

typedef struct _EJOB                                // 42 elements, 0x1C8 bytes (sizeof)
{
	/*0x000*/     struct _KEVENT Event;                           // 1 elements, 0x18 bytes (sizeof)
	/*0x018*/     struct _LIST_ENTRY JobLinks;                    // 2 elements, 0x10 bytes (sizeof)
	/*0x028*/     struct _LIST_ENTRY ProcessListHead;             // 2 elements, 0x10 bytes (sizeof)
	/*0x038*/     struct _ERESOURCE JobLock;                      // 15 elements, 0x68 bytes (sizeof)
	/*0x0A0*/     union _LARGE_INTEGER TotalUserTime;             // 4 elements, 0x8 bytes (sizeof)
	/*0x0A8*/     union _LARGE_INTEGER TotalKernelTime;           // 4 elements, 0x8 bytes (sizeof)
	/*0x0B0*/     union _LARGE_INTEGER ThisPeriodTotalUserTime;   // 4 elements, 0x8 bytes (sizeof)
	/*0x0B8*/     union _LARGE_INTEGER ThisPeriodTotalKernelTime; // 4 elements, 0x8 bytes (sizeof)
	/*0x0C0*/     ULONG32      TotalPageFaultCount;
	/*0x0C4*/     ULONG32      TotalProcesses;
	/*0x0C8*/     ULONG32      ActiveProcesses;
	/*0x0CC*/     ULONG32      TotalTerminatedProcesses;
	/*0x0D0*/     union _LARGE_INTEGER PerProcessUserTimeLimit;   // 4 elements, 0x8 bytes (sizeof)
	/*0x0D8*/     union _LARGE_INTEGER PerJobUserTimeLimit;       // 4 elements, 0x8 bytes (sizeof)
	/*0x0E0*/     UINT64       MinimumWorkingSetSize;
	/*0x0E8*/     UINT64       MaximumWorkingSetSize;
	/*0x0F0*/     ULONG32      LimitFlags;
	/*0x0F4*/     ULONG32      ActiveProcessLimit;
	/*0x0F8*/     struct _KAFFINITY_EX Affinity;                  // 4 elements, 0x28 bytes (sizeof)
	/*0x120*/     UINT8        PriorityClass;
	/*0x121*/     UINT8        _PADDING0_[0x7];
	/*0x128*/     ULONG64 AccessState;
	/*0x130*/     ULONG32      UIRestrictionsClass;
	/*0x134*/     ULONG32      EndOfJobTimeAction;
	/*0x138*/     VOID* CompletionPort;
	/*0x140*/     VOID* CompletionKey;
	/*0x148*/     ULONG32      SessionId;
	/*0x14C*/     ULONG32      SchedulingClass;
	/*0x150*/     UINT64       ReadOperationCount;
	/*0x158*/     UINT64       WriteOperationCount;
	/*0x160*/     UINT64       OtherOperationCount;
	/*0x168*/     UINT64       ReadTransferCount;
	/*0x170*/     UINT64       WriteTransferCount;
	/*0x178*/     UINT64       OtherTransferCount;
	/*0x180*/     UINT64       ProcessMemoryLimit;
	/*0x188*/     UINT64       JobMemoryLimit;
	/*0x190*/     UINT64       PeakProcessMemoryUsed;
	/*0x198*/     UINT64       PeakJobMemoryUsed;
	/*0x1A0*/     UINT64       CurrentJobMemoryUsed;
	/*0x1A8*/     struct _EX_PUSH_LOCK MemoryLimitsLock;          // 7 elements, 0x8 bytes (sizeof)
	/*0x1B0*/     struct _LIST_ENTRY JobSetLinks;                 // 2 elements, 0x10 bytes (sizeof)
	/*0x1C0*/     ULONG32      MemberLevel;
	/*0x1C4*/     ULONG32      JobFlags;
}EJOB, * PEJOB;

typedef struct _HARDWARE_PTE
{
	ULONG64 Valid : 1;
	ULONG64 Write : 1;
	ULONG64 Owner : 1;
	ULONG64 WriteThrough : 1;
	ULONG64 CacheDisable : 1;
	ULONG64 Accessed : 1;
	ULONG64 Dirty : 1;
	ULONG64 LargePage : 1;
	ULONG64 Global : 1;
	ULONG64 CopyOnWrite : 1;
	ULONG64 Prototype : 1;
	ULONG64 reserved0 : 1;
	ULONG64 PageFrameNumber : 28;
	ULONG64 reserved1 : 12;
	ULONG64 SoftwareWsIndex : 11;
	ULONG64 NoExecute : 1;
} HARDWARE_PTE, * PHARDWARE_PTE;

typedef struct _MMWSLE_NONDIRECT_HASH // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     VOID* Key;
	/*0x008*/     ULONG32      Index;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
}MMWSLE_NONDIRECT_HASH, * PMMWSLE_NONDIRECT_HASH;

typedef struct _MMWSLENTRY               // 7 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     UINT64       Valid : 1;              // 0 BitPosition
	/*0x000*/     UINT64       Spare : 1;              // 1 BitPosition
	/*0x000*/     UINT64       Hashed : 1;             // 2 BitPosition
	/*0x000*/     UINT64       Direct : 1;             // 3 BitPosition
	/*0x000*/     UINT64       Protection : 5;         // 4 BitPosition
	/*0x000*/     UINT64       Age : 3;                // 9 BitPosition
	/*0x000*/     UINT64       VirtualPageNumber : 52; // 12 BitPosition
}MMWSLENTRY, * PMMWSLENTRY;

typedef struct _MMWSLE_FREE_ENTRY   // 3 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     UINT64       MustBeZero : 1;    // 0 BitPosition
	/*0x000*/     UINT64       PreviousFree : 31; // 1 BitPosition
	/*0x000*/     UINT64       NextFree : 32;     // 32 BitPosition
}MMWSLE_FREE_ENTRY, * PMMWSLE_FREE_ENTRY;

typedef struct _MMWSLE                // 1 elements, 0x8 bytes (sizeof)
{
	union                             // 4 elements, 0x8 bytes (sizeof)
	{
		/*0x000*/         VOID* VirtualAddress;
		/*0x000*/         UINT64       Long;
		/*0x000*/         struct _MMWSLENTRY e1;        // 7 elements, 0x8 bytes (sizeof)
		/*0x000*/         struct _MMWSLE_FREE_ENTRY e2; // 3 elements, 0x8 bytes (sizeof)
	}u1;
}MMWSLE, * PMMWSLE;

typedef struct _MMWSLE_HASH // 1 elements, 0x4 bytes (sizeof)
{
	/*0x000*/     ULONG32      Index;
}MMWSLE_HASH, * PMMWSLE_HASH;

typedef struct _MMWSL                                   // 25 elements, 0x488 bytes (sizeof)
{
	/*0x000*/     ULONG32      FirstFree;
	/*0x004*/     ULONG32      FirstDynamic;
	/*0x008*/     ULONG32      LastEntry;
	/*0x00C*/     ULONG32      NextSlot;
	/*0x010*/     struct _MMWSLE* Wsle;
	/*0x018*/     VOID* LowestPagableAddress;
	/*0x020*/     ULONG32      LastInitializedWsle;
	/*0x024*/     ULONG32      NextAgingSlot;
	/*0x028*/     ULONG32      NumberOfCommittedPageTables;
	/*0x02C*/     ULONG32      VadBitMapHint;
	/*0x030*/     ULONG32      NonDirectCount;
	/*0x034*/     ULONG32      LastVadBit;
	/*0x038*/     ULONG32      MaximumLastVadBit;
	/*0x03C*/     ULONG32      LastAllocationSizeHint;
	/*0x040*/     ULONG32      LastAllocationSize;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _MMWSLE_NONDIRECT_HASH* NonDirectHash;
	/*0x050*/     struct _MMWSLE_HASH* HashTableStart;
	/*0x058*/     struct _MMWSLE_HASH* HighestPermittedHashAddress;
	/*0x060*/     ULONG32      MaximumUserPageTablePages;
	/*0x064*/     ULONG32      MaximumUserPageDirectoryPages;
	/*0x068*/     ULONG32* CommittedPageTables;
	/*0x070*/     ULONG32      NumberOfCommittedPageDirectories;
	/*0x074*/     UINT8        _PADDING1_[0x4];
	/*0x078*/     UINT64       CommittedPageDirectories[128];
	/*0x478*/     ULONG32      NumberOfCommittedPageDirectoryParents;
	/*0x47C*/     UINT8        _PADDING2_[0x4];
	/*0x480*/     UINT64       CommittedPageDirectoryParents[1];
}MMWSL, * PMMWSL;

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

typedef struct _MMSUPPORT                        // 21 elements, 0x88 bytes (sizeof)
{
	/*0x000*/     struct _EX_PUSH_LOCK WorkingSetMutex;        // 7 elements, 0x8 bytes (sizeof)
	/*0x008*/     struct _KGATE* ExitGate;
	/*0x010*/     VOID* AccessLog;
	/*0x018*/     struct _LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x10 bytes (sizeof)
	/*0x028*/     ULONG32      AgeDistribution[7];
	/*0x044*/     ULONG32      MinimumWorkingSetSize;
	/*0x048*/     ULONG32      WorkingSetSize;
	/*0x04C*/     ULONG32      WorkingSetPrivateSize;
	/*0x050*/     ULONG32      MaximumWorkingSetSize;
	/*0x054*/     ULONG32      ChargedWslePages;
	/*0x058*/     ULONG32      ActualWslePages;
	/*0x05C*/     ULONG32      WorkingSetSizeOverhead;
	/*0x060*/     ULONG32      PeakWorkingSetSize;
	/*0x064*/     ULONG32      HardFaultCount;
	/*0x068*/     struct _MMWSL* VmWorkingSetList;
	/*0x070*/     UINT16       NextPageColor;
	/*0x072*/     UINT16       LastTrimStamp;
	/*0x074*/     ULONG32      PageFaultCount;
	/*0x078*/     ULONG32      RepurposeCount;
	/*0x07C*/     ULONG32      Spare[2];
	/*0x084*/     struct _MMSUPPORT_FLAGS Flags;               // 15 elements, 0x4 bytes (sizeof)
}MMSUPPORT, * PMMSUPPORT;

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO      // 1 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     struct _OBJECT_NAME_INFORMATION* ImageFileName;
}SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _ALPC_PROCESS_CONTEXT  // 3 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     struct _EX_PUSH_LOCK Lock;        // 7 elements, 0x8 bytes (sizeof)
	/*0x008*/     struct _LIST_ENTRY ViewListHead;  // 2 elements, 0x10 bytes (sizeof)
	/*0x018*/     UINT64       PagedPoolQuotaCache;
}ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT;

typedef struct _PO_DIAG_STACK_RECORD // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     ULONG32      StackDepth;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     VOID* Stack[1];
}PO_DIAG_STACK_RECORD, * PPO_DIAG_STACK_RECORD;

typedef union _KEXECUTE_OPTIONS                           // 9 elements, 0x1 bytes (sizeof) 
{
	struct                                                // 8 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        ExecuteDisable : 1;                  // 0 BitPosition                  
		/*0x000*/         UINT8        ExecuteEnable : 1;                   // 1 BitPosition                  
		/*0x000*/         UINT8        DisableThunkEmulation : 1;           // 2 BitPosition                  
		/*0x000*/         UINT8        Permanent : 1;                       // 3 BitPosition                  
		/*0x000*/         UINT8        ExecuteDispatchEnable : 1;           // 4 BitPosition                  
		/*0x000*/         UINT8        ImageDispatchEnable : 1;             // 5 BitPosition                  
		/*0x000*/         UINT8        DisableExceptionChainValidation : 1; // 6 BitPosition                  
		/*0x000*/         UINT8        Spare : 1;                           // 7 BitPosition                  
	};
	/*0x000*/     UINT8        ExecuteOptions;
}KEXECUTE_OPTIONS, * PKEXECUTE_OPTIONS;

typedef union _KSTACK_COUNT           // 3 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     LONG32       Value;
	struct                            // 2 elements, 0x4 bytes (sizeof) 
	{
		/*0x000*/         ULONG32      State : 3;       // 0 BitPosition                  
		/*0x000*/         ULONG32      StackCount : 29; // 3 BitPosition                  
	};
}KSTACK_COUNT, * PKSTACK_COUNT;

#pragma pack(push) //保存对齐状态
#pragma pack(1)//设定为4字节对齐
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
#pragma pack(pop)//恢复对齐状态

typedef struct _RTL_UMS_CONTEXT                       // 28 elements, 0x540 bytes (sizeof)
{
	/*0x000*/     struct _SINGLE_LIST_ENTRY Link;                   // 1 elements, 0x8 bytes (sizeof)
	/*0x008*/     UINT8        _PADDING0_[0x8];
	/*0x010*/     struct _CONTEXT Context;                          // 64 elements, 0x4D0 bytes (sizeof)
	/*0x4E0*/     VOID* Teb;
	/*0x4E8*/     VOID* UserContext;
	union                                             // 2 elements, 0x8 bytes (sizeof)
	{
		struct                                        // 11 elements, 0x4 bytes (sizeof)
		{
			/*0x4F0*/             ULONG32      ScheduledThread : 1;         // 0 BitPosition
			/*0x4F0*/             ULONG32      HasQuantumReq : 1;           // 1 BitPosition
			/*0x4F0*/             ULONG32      HasAffinityReq : 1;          // 2 BitPosition
			/*0x4F0*/             ULONG32      HasPriorityReq : 1;          // 3 BitPosition
			/*0x4F0*/             ULONG32      Suspended : 1;               // 4 BitPosition
			/*0x4F0*/             ULONG32      VolatileContext : 1;         // 5 BitPosition
			/*0x4F0*/             ULONG32      Terminated : 1;              // 6 BitPosition
			/*0x4F0*/             ULONG32      DebugActive : 1;             // 7 BitPosition
			/*0x4F0*/             ULONG32      RunningOnSelfThread : 1;     // 8 BitPosition
			/*0x4F0*/             ULONG32      DenyRunningOnSelfThread : 1; // 9 BitPosition
			/*0x4F0*/             ULONG32      ReservedFlags : 22;          // 10 BitPosition
		};
		/*0x4F0*/         LONG32       Flags;
	};
	union                                             // 2 elements, 0x8 bytes (sizeof)
	{
		struct                                        // 3 elements, 0x8 bytes (sizeof)
		{
			/*0x4F8*/             UINT64       KernelUpdateLock : 1;        // 0 BitPosition
			/*0x4F8*/             UINT64       Reserved : 1;                // 1 BitPosition
			/*0x4F8*/             UINT64       PrimaryClientID : 62;        // 2 BitPosition
		};
		/*0x4F8*/         UINT64       ContextLock;
	};
	/*0x500*/     UINT64       QuantumValue;
	/*0x508*/     struct _GROUP_AFFINITY AffinityMask;              // 3 elements, 0x10 bytes (sizeof)
	/*0x518*/     LONG32       Priority;
	/*0x51C*/     UINT8        _PADDING1_[0x4];
	/*0x520*/     struct _RTL_UMS_CONTEXT* PrimaryUmsContext;
	/*0x528*/     ULONG32      SwitchCount;
	/*0x52C*/     ULONG32      KernelYieldCount;
	/*0x530*/     ULONG32      MixedYieldCount;
	/*0x534*/     ULONG32      YieldCount;
	/*0x538*/     UINT8        _PADDING2_[0x8];
}RTL_UMS_CONTEXT, * PRTL_UMS_CONTEXT;

typedef struct _UMS_CONTROL_BLOCK                                // 22 elements, 0x98 bytes (sizeof)
{
	/*0x000*/     struct _RTL_UMS_CONTEXT* UmsContext;
	/*0x008*/     struct _SINGLE_LIST_ENTRY* CompletionListEntry;
	/*0x010*/     struct _KEVENT* CompletionListEvent;
	/*0x018*/     ULONG32      ServiceSequenceNumber;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
	union                                                        // 2 elements, 0x6C bytes (sizeof)
	{
		struct                                                   // 6 elements, 0x6C bytes (sizeof)
		{
			/*0x020*/             struct _KQUEUE UmsQueue;                             // 5 elements, 0x40 bytes (sizeof)
			/*0x060*/             struct _LIST_ENTRY QueueEntry;                       // 2 elements, 0x10 bytes (sizeof)
			/*0x070*/             struct _RTL_UMS_CONTEXT* YieldingUmsContext;
			/*0x078*/             VOID* YieldingParam;
			/*0x080*/             VOID* UmsTeb;
			union                                                // 2 elements, 0x4 bytes (sizeof)
			{
				/*0x088*/                 ULONG32      PrimaryFlags;
				/*0x088*/                 ULONG32      UmsContextHeaderReady : 1;          // 0 BitPosition
			};
		};
		struct                                                   // 6 elements, 0x6C bytes (sizeof)
		{
			/*0x020*/             struct _KQUEUE* UmsAssociatedQueue;
			/*0x028*/             struct _LIST_ENTRY* UmsQueueListEntry;
			/*0x030*/             struct _KUMS_CONTEXT_HEADER* UmsContextHeader;
			/*0x038*/             struct _KGATE UmsWaitGate;                           // 1 elements, 0x18 bytes (sizeof)
			/*0x050*/             VOID* StagingArea;
			union                                                // 2 elements, 0x4 bytes (sizeof)
			{
				/*0x058*/                 LONG32       Flags;
				struct                                           // 4 elements, 0x4 bytes (sizeof)
				{
					/*0x058*/                     ULONG32      UmsForceQueueTermination : 1;   // 0 BitPosition
					/*0x058*/                     ULONG32      UmsAssociatedQueueUsed : 1;     // 1 BitPosition
					/*0x058*/                     ULONG32      UmsThreadParked : 1;            // 2 BitPosition
					/*0x058*/                     ULONG32      UmsPrimaryDeliveredContext : 1; // 3 BitPosition
				};
			};
		};
	};
	/*0x090*/     UINT16       TebSelector;
	/*0x092*/     UINT8        _PADDING1_[0x6];
}UMS_CONTROL_BLOCK, * PUMS_CONTROL_BLOCK;

typedef struct _KDESCRIPTOR // 3 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     UINT16       Pad[3];
	/*0x006*/     UINT16       Limit;
	/*0x008*/     VOID* Base;
}KDESCRIPTOR, * PKDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS     // 27 elements, 0xD8 bytes (sizeof)
{
	/*0x000*/     UINT64       Cr0;
	/*0x008*/     UINT64       Cr2;
	/*0x010*/     UINT64       Cr3;
	/*0x018*/     UINT64       Cr4;
	/*0x020*/     UINT64       KernelDr0;
	/*0x028*/     UINT64       KernelDr1;
	/*0x030*/     UINT64       KernelDr2;
	/*0x038*/     UINT64       KernelDr3;
	/*0x040*/     UINT64       KernelDr6;
	/*0x048*/     UINT64       KernelDr7;
	/*0x050*/     struct _KDESCRIPTOR Gdtr;          // 3 elements, 0x10 bytes (sizeof)
	/*0x060*/     struct _KDESCRIPTOR Idtr;          // 3 elements, 0x10 bytes (sizeof)
	/*0x070*/     UINT16       Tr;
	/*0x072*/     UINT16       Ldtr;
	/*0x074*/     ULONG32      MxCsr;
	/*0x078*/     UINT64       DebugControl;
	/*0x080*/     UINT64       LastBranchToRip;
	/*0x088*/     UINT64       LastBranchFromRip;
	/*0x090*/     UINT64       LastExceptionToRip;
	/*0x098*/     UINT64       LastExceptionFromRip;
	/*0x0A0*/     UINT64       Cr8;
	/*0x0A8*/     UINT64       MsrGsBase;
	/*0x0B0*/     UINT64       MsrGsSwap;
	/*0x0B8*/     UINT64       MsrStar;
	/*0x0C0*/     UINT64       MsrLStar;
	/*0x0C8*/     UINT64       MsrCStar;
	/*0x0D0*/     UINT64       MsrSyscallMask;
}KSPECIAL_REGISTERS, * PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE                 // 2 elements, 0x5B0 bytes (sizeof)
{
	/*0x000*/     struct _KSPECIAL_REGISTERS SpecialRegisters; // 27 elements, 0xD8 bytes (sizeof)
	/*0x0D8*/     UINT8        _PADDING0_[0x8];
	/*0x0E0*/     struct _CONTEXT ContextFrame;                // 64 elements, 0x4D0 bytes (sizeof)
}KPROCESSOR_STATE, * PKPROCESSOR_STATE;

typedef struct _PP_LOOKASIDE_LIST // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     struct _GENERAL_LOOKASIDE* P;
	/*0x008*/     struct _GENERAL_LOOKASIDE* L;
}PP_LOOKASIDE_LIST, * PPP_LOOKASIDE_LIST;

typedef struct _KDPC_DATA           // 4 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY DpcListHead; // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     UINT64       DpcLock;
	/*0x018*/     LONG32       DpcQueueDepth;
	/*0x01C*/     ULONG32      DpcCount;
}KDPC_DATA, * PKDPC_DATA;

typedef struct _KTIMER_TABLE_ENTRY // 3 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     UINT64       Lock;
	/*0x008*/     struct _LIST_ENTRY Entry;      // 2 elements, 0x10 bytes (sizeof)
	/*0x018*/     union _ULARGE_INTEGER Time;    // 4 elements, 0x8 bytes (sizeof)
}KTIMER_TABLE_ENTRY, * PKTIMER_TABLE_ENTRY;

typedef struct _KTIMER_TABLE                      // 2 elements, 0x2200 bytes (sizeof)
{
	/*0x000*/     struct _KTIMER* TimerExpiry[64];
	/*0x200*/     struct _KTIMER_TABLE_ENTRY TimerEntries[256];
}KTIMER_TABLE, * PKTIMER_TABLE;

typedef struct _flags                      // 5 elements, 0x1 bytes (sizeof)
{
	/*0x000*/     UINT8        Removable : 1;            // 0 BitPosition
	/*0x000*/     UINT8        GroupAssigned : 1;        // 1 BitPosition
	/*0x000*/     UINT8        GroupCommitted : 1;       // 2 BitPosition
	/*0x000*/     UINT8        GroupAssignmentFixed : 1; // 3 BitPosition
	/*0x000*/     UINT8        Fill : 4;                 // 4 BitPosition
}flags, * Pflags;

typedef struct _CACHED_KSTACK_LIST // 5 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     union _SLIST_HEADER SListHead; // 5 elements, 0x10 bytes (sizeof)
	/*0x010*/     LONG32       MinimumFree;
	/*0x014*/     ULONG32      Misses;
	/*0x018*/     ULONG32      MissesLast;
	/*0x01C*/     ULONG32      Pad0;
}CACHED_KSTACK_LIST, * PCACHED_KSTACK_LIST;

typedef struct _KNODE                              // 18 elements, 0xC0 bytes (sizeof)
{
	/*0x000*/     union _SLIST_HEADER PagedPoolSListHead;        // 5 elements, 0x10 bytes (sizeof)
	/*0x010*/     union _SLIST_HEADER NonPagedPoolSListHead[3];
	/*0x040*/     struct _GROUP_AFFINITY Affinity;               // 3 elements, 0x10 bytes (sizeof)
	/*0x050*/     ULONG32      ProximityId;
	/*0x054*/     UINT16       NodeNumber;
	/*0x056*/     UINT16       PrimaryNodeNumber;
	/*0x058*/     UINT8        MaximumProcessors;
	/*0x059*/     UINT8        Color;
	/*0x05A*/     struct _flags Flags;                           // 5 elements, 0x1 bytes (sizeof)
	/*0x05B*/     UINT8        NodePad0;
	/*0x05C*/     ULONG32      Seed;
	/*0x060*/     ULONG32      MmShiftedColor;
	/*0x064*/     UINT8        _PADDING0_[0x4];
	/*0x068*/     UINT64       FreeCount[2];
	/*0x078*/     ULONG32      Right;
	/*0x07C*/     ULONG32      Left;
	/*0x080*/     struct _CACHED_KSTACK_LIST CachedKernelStacks; // 5 elements, 0x20 bytes (sizeof)
	/*0x0A0*/     LONG32       ParkLock;
	/*0x0A4*/     ULONG32      NodePad1;
	/*0x0A8*/     UINT8        _PADDING1_[0x18];
}KNODE, * PKNODE;

typedef struct _PPM_IDLE_STATE                                                                                                                                              // 14 elements, 0x60 bytes (sizeof)
{
	/*0x000*/     struct _KAFFINITY_EX DomainMembers;                                                                                                                                     // 4 elements, 0x28 bytes (sizeof)
	/*0x028*/     PVOID IdleCheck;
	/*0x030*/     PVOID IdleHandler;
	/*0x038*/     UINT64       HvConfig;
	/*0x040*/     VOID* Context;
	/*0x048*/     ULONG32      Latency;
	/*0x04C*/     ULONG32      Power;
	/*0x050*/     ULONG32      TimeCheck;
	/*0x054*/     ULONG32      StateFlags;
	/*0x058*/     UINT8        PromotePercent;
	/*0x059*/     UINT8        DemotePercent;
	/*0x05A*/     UINT8        PromotePercentBase;
	/*0x05B*/     UINT8        DemotePercentBase;
	/*0x05C*/     UINT8        StateType;
	/*0x05D*/     UINT8        _PADDING0_[0x3];
}PPM_IDLE_STATE, * PPPM_IDLE_STATE;

typedef struct _PPM_IDLE_STATES            // 8 elements, 0xA0 bytes (sizeof)
{
	/*0x000*/     ULONG32      Count;
	union                                  // 5 elements, 0x4 bytes (sizeof)
	{
		/*0x004*/         ULONG32      AsULONG;
		struct                             // 4 elements, 0x4 bytes (sizeof)
		{
			/*0x004*/             ULONG32      AllowScaling : 1; // 0 BitPosition
			/*0x004*/             ULONG32      Disabled : 1;     // 1 BitPosition
			/*0x004*/             ULONG32      HvMaxCState : 4;  // 2 BitPosition
			/*0x004*/             ULONG32      Reserved : 26;    // 6 BitPosition
		};
	}Flags;
	/*0x008*/     ULONG32      TargetState;
	/*0x00C*/     ULONG32      ActualState;
	/*0x010*/     ULONG32      OldState;
	/*0x014*/     UINT8        NewlyUnparked;
	/*0x015*/     UINT8        _PADDING0_[0x3];
	/*0x018*/     struct _KAFFINITY_EX TargetProcessors; // 4 elements, 0x28 bytes (sizeof)
	/*0x040*/     struct _PPM_IDLE_STATE State[1];
}PPM_IDLE_STATES, * PPPM_IDLE_STATES;

typedef struct _PROC_IDLE_STATE_BUCKET // 4 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     UINT64       TotalTime;
	/*0x008*/     UINT64       MinTime;
	/*0x010*/     UINT64       MaxTime;
	/*0x018*/     ULONG32      Count;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
}PROC_IDLE_STATE_BUCKET, * PPROC_IDLE_STATE_BUCKET;

typedef struct _PROC_IDLE_STATE_ACCOUNTING              // 7 elements, 0x228 bytes (sizeof)
{
	/*0x000*/     UINT64       TotalTime;
	/*0x008*/     ULONG32      IdleTransitions;
	/*0x00C*/     ULONG32      FailedTransitions;
	/*0x010*/     ULONG32      InvalidBucketIndex;
	/*0x014*/     UINT8        _PADDING0_[0x4];
	/*0x018*/     UINT64       MinTime;
	/*0x020*/     UINT64       MaxTime;
	/*0x028*/     struct _PROC_IDLE_STATE_BUCKET IdleTimeBuckets[16];
}PROC_IDLE_STATE_ACCOUNTING, * PPROC_IDLE_STATE_ACCOUNTING;

typedef struct _PROC_IDLE_ACCOUNTING             // 6 elements, 0x2C0 bytes (sizeof)
{
	/*0x000*/     ULONG32      StateCount;
	/*0x004*/     ULONG32      TotalTransitions;
	/*0x008*/     ULONG32      ResetCount;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
	/*0x010*/     UINT64       StartTime;
	/*0x018*/     UINT64       BucketLimits[16];
	/*0x098*/     struct _PROC_IDLE_STATE_ACCOUNTING State[1];
}PROC_IDLE_ACCOUNTING, * PPROC_IDLE_ACCOUNTING;

typedef enum _PROC_HYPERVISOR_STATE  // 3 elements, 0x4 bytes
{
	ProcHypervisorNone = 0 /*0x0*/,
	ProcHypervisorPresent = 1 /*0x1*/,
	ProcHypervisorPower = 2 /*0x2*/
}PROC_HYPERVISOR_STATE, * PPROC_HYPERVISOR_STATE;

typedef struct _PPM_FFH_THROTTLE_STATE_INFO // 5 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     UINT8        EnableLogging;
	/*0x001*/     UINT8        _PADDING0_[0x3];
	/*0x004*/     ULONG32      MismatchCount;
	/*0x008*/     UINT8        Initialized;
	/*0x009*/     UINT8        _PADDING1_[0x7];
	/*0x010*/     UINT64       LastValue;
	/*0x018*/     union _LARGE_INTEGER LastLogTickCount;  // 4 elements, 0x8 bytes (sizeof)
}PPM_FFH_THROTTLE_STATE_INFO, * PPPM_FFH_THROTTLE_STATE_INFO;

typedef struct _PROC_IDLE_SNAP // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     UINT64       Time;
	/*0x008*/     UINT64       Idle;
}PROC_IDLE_SNAP, * PPROC_IDLE_SNAP;

typedef struct _PROC_PERF_CONSTRAINT      // 9 elements, 0x30 bytes (sizeof)
{
	/*0x000*/     struct _KPRCB* Prcb;
	/*0x008*/     UINT64       PerfContext;
	/*0x010*/     ULONG32      PercentageCap;
	/*0x014*/     ULONG32      ThermalCap;
	/*0x018*/     ULONG32      TargetFrequency;
	/*0x01C*/     ULONG32      AcumulatedFullFrequency;
	/*0x020*/     ULONG32      AcumulatedZeroFrequency;
	/*0x024*/     ULONG32      FrequencyHistoryTotal;
	/*0x028*/     ULONG32      AverageFrequency;
	/*0x02C*/     UINT8        _PADDING0_[0x4];
}PROC_PERF_CONSTRAINT, * PPROC_PERF_CONSTRAINT;

typedef struct _PROC_PERF_DOMAIN                                         // 26 elements, 0xB8 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY Link;                                             // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _KPRCB* Master;
	/*0x018*/     struct _KAFFINITY_EX Members;                                        // 4 elements, 0x28 bytes (sizeof)
	/*0x040*/     PVOID FeedbackHandler;
	/*0x048*/     PVOID GetFFHThrottleState;
	/*0x050*/     PVOID BoostPolicyHandler;
	/*0x058*/     PVOID PerfSelectionHandler;
	/*0x060*/     PVOID PerfHandler;
	/*0x068*/     struct _PROC_PERF_CONSTRAINT* Processors;
	/*0x070*/     UINT64       PerfChangeTime;
	/*0x078*/     ULONG32      ProcessorCount;
	/*0x07C*/     ULONG32      PreviousFrequencyMhz;
	/*0x080*/     ULONG32      CurrentFrequencyMhz;
	/*0x084*/     ULONG32      PreviousFrequency;
	/*0x088*/     ULONG32      CurrentFrequency;
	/*0x08C*/     ULONG32      CurrentPerfContext;
	/*0x090*/     ULONG32      DesiredFrequency;
	/*0x094*/     ULONG32      MaxFrequency;
	/*0x098*/     ULONG32      MinPerfPercent;
	/*0x09C*/     ULONG32      MinThrottlePercent;
	/*0x0A0*/     ULONG32      MaxPercent;
	/*0x0A4*/     ULONG32      MinPercent;
	/*0x0A8*/     ULONG32      ConstrainedMaxPercent;
	/*0x0AC*/     ULONG32      ConstrainedMinPercent;
	/*0x0B0*/     UINT8        Coordination;
	/*0x0B1*/     UINT8        _PADDING0_[0x3];
	/*0x0B4*/     LONG32       PerfChangeIntervalCount;
}PROC_PERF_DOMAIN, * PPROC_PERF_DOMAIN;

typedef struct _PROC_PERF_LOAD        // 2 elements, 0x2 bytes (sizeof)
{
	/*0x000*/     UINT8        BusyPercentage;
	/*0x001*/     UINT8        FrequencyPercentage;
}PROC_PERF_LOAD, * PPROC_PERF_LOAD;

typedef struct _PROC_HISTORY_ENTRY // 3 elements, 0x4 bytes (sizeof)
{
	/*0x000*/     UINT16       Utility;
	/*0x002*/     UINT8        Frequency;
	/*0x003*/     UINT8        Reserved;
}PROC_HISTORY_ENTRY, * PPROC_HISTORY_ENTRY;

typedef struct _PROCESSOR_POWER_STATE                         // 27 elements, 0x100 bytes (sizeof)
{
	/*0x000*/     struct _PPM_IDLE_STATES* IdleStates;
	/*0x008*/     UINT64       IdleTimeLast;
	/*0x010*/     UINT64       IdleTimeTotal;
	/*0x018*/     UINT64       IdleTimeEntry;
	/*0x020*/     struct _PROC_IDLE_ACCOUNTING* IdleAccounting;
	/*0x028*/     enum _PROC_HYPERVISOR_STATE Hypervisor;
	/*0x02C*/     ULONG32      PerfHistoryTotal;
	/*0x030*/     UINT8        ThermalConstraint;
	/*0x031*/     UINT8        PerfHistoryCount;
	/*0x032*/     UINT8        PerfHistorySlot;
	/*0x033*/     UINT8        Reserved;
	/*0x034*/     ULONG32      LastSysTime;
	/*0x038*/     UINT64       WmiDispatchPtr;
	/*0x040*/     LONG32       WmiInterfaceEnabled;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _PPM_FFH_THROTTLE_STATE_INFO FFHThrottleStateInfo; // 5 elements, 0x20 bytes (sizeof)
	/*0x068*/     struct _KDPC PerfActionDpc;                               // 9 elements, 0x40 bytes (sizeof)
	/*0x0A8*/     LONG32       PerfActionMask;
	/*0x0AC*/     UINT8        _PADDING1_[0x4];
	/*0x0B0*/     struct _PROC_IDLE_SNAP IdleCheck;                         // 2 elements, 0x10 bytes (sizeof)
	/*0x0C0*/     struct _PROC_IDLE_SNAP PerfCheck;                         // 2 elements, 0x10 bytes (sizeof)
	/*0x0D0*/     struct _PROC_PERF_DOMAIN* Domain;
	/*0x0D8*/     struct _PROC_PERF_CONSTRAINT* PerfConstraint;
	/*0x0E0*/     struct _PROC_PERF_LOAD* Load;
	/*0x0E8*/     struct _PROC_HISTORY_ENTRY* PerfHistory;
	/*0x0F0*/     ULONG32      Utility;
	/*0x0F4*/     ULONG32      OverUtilizedHistory;
	/*0x0F8*/     ULONG32      AffinityCount;
	/*0x0FC*/     ULONG32      AffinityHistory;
}PROCESSOR_POWER_STATE, * PPROCESSOR_POWER_STATE;

typedef struct _KREQUEST_PACKET                   // 2 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     VOID* CurrentPacket[3];
	/*0x018*/     PVOID WorkerRoutine;
}KREQUEST_PACKET, * PKREQUEST_PACKET;

typedef struct _REQUEST_MAILBOX            // 3 elements, 0x40 bytes (sizeof)
{
	/*0x000*/     struct _REQUEST_MAILBOX* Next;
	/*0x008*/     INT64        RequestSummary;
	/*0x010*/     struct _KREQUEST_PACKET RequestPacket; // 2 elements, 0x20 bytes (sizeof)
	/*0x030*/     UINT8        _PADDING0_[0x10];
}REQUEST_MAILBOX, * PREQUEST_MAILBOX;

typedef struct _KPRCB                                                   // 242 elements, 0x4D00 bytes (sizeof)
{
	/*0x000*/      ULONG32      MxCsr;
	/*0x004*/      UINT8        LegacyNumber;
	/*0x005*/      UINT8        ReservedMustBeZero;
	/*0x006*/      UINT8        InterruptRequest;
	/*0x007*/      UINT8        IdleHalt;
	/*0x008*/      struct _KTHREAD* CurrentThread;
	/*0x010*/      struct _KTHREAD* NextThread;
	/*0x018*/      struct _KTHREAD* IdleThread;
	/*0x020*/      UINT8        NestingLevel;
	/*0x021*/      UINT8        PrcbPad00[3];
	/*0x024*/      ULONG32      Number;
	/*0x028*/      UINT64       RspBase;
	/*0x030*/      UINT64       PrcbLock;
	/*0x038*/      UINT64       PrcbPad01;
	/*0x040*/      struct _KPROCESSOR_STATE ProcessorState;                            // 2 elements, 0x5B0 bytes (sizeof)
	/*0x5F0*/      CHAR         CpuType;
	/*0x5F1*/      CHAR         CpuID;
	union                                                               // 2 elements, 0x2 bytes (sizeof)
	{
		/*0x5F2*/          UINT16       CpuStep;
		struct                                                          // 2 elements, 0x2 bytes (sizeof)
		{
			/*0x5F2*/              UINT8        CpuStepping;
			/*0x5F3*/              UINT8        CpuModel;
		};
	};
	/*0x5F4*/      ULONG32      MHz;
	/*0x5F8*/      UINT64       HalReserved[8];
	/*0x638*/      UINT16       MinorVersion;
	/*0x63A*/      UINT16       MajorVersion;
	/*0x63C*/      UINT8        BuildType;
	/*0x63D*/      UINT8        CpuVendor;
	/*0x63E*/      UINT8        CoresPerPhysicalProcessor;
	/*0x63F*/      UINT8        LogicalProcessorsPerCore;
	/*0x640*/      ULONG32      ApicMask;
	/*0x644*/      ULONG32      CFlushSize;
	/*0x648*/      VOID* AcpiReserved;
	/*0x650*/      ULONG32      InitialApicId;
	/*0x654*/      ULONG32      Stride;
	/*0x658*/      UINT16       Group;
	/*0x65A*/      UINT8        _PADDING0_[0x6];
	/*0x660*/      UINT64       GroupSetMember;
	/*0x668*/      UINT8        GroupIndex;
	/*0x669*/      UINT8        _PADDING1_[0x7];
	/*0x670*/      struct _KSPIN_LOCK_QUEUE LockQueue[17];
	/*0x780*/      struct _PP_LOOKASIDE_LIST PPLookasideList[16];
	/*0x880*/      struct _GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
	/*0x1480*/     struct _GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
	/*0x2080*/     LONG32       PacketBarrier;
	/*0x2084*/     UINT8        _PADDING2_[0x4];
	/*0x2088*/     struct _SINGLE_LIST_ENTRY DeferredReadyListHead;                    // 1 elements, 0x8 bytes (sizeof)
	/*0x2090*/     LONG32       MmPageFaultCount;
	/*0x2094*/     LONG32       MmCopyOnWriteCount;
	/*0x2098*/     LONG32       MmTransitionCount;
	/*0x209C*/     LONG32       MmDemandZeroCount;
	/*0x20A0*/     LONG32       MmPageReadCount;
	/*0x20A4*/     LONG32       MmPageReadIoCount;
	/*0x20A8*/     LONG32       MmDirtyPagesWriteCount;
	/*0x20AC*/     LONG32       MmDirtyWriteIoCount;
	/*0x20B0*/     LONG32       MmMappedPagesWriteCount;
	/*0x20B4*/     LONG32       MmMappedWriteIoCount;
	/*0x20B8*/     ULONG32      KeSystemCalls;
	/*0x20BC*/     ULONG32      KeContextSwitches;
	/*0x20C0*/     ULONG32      CcFastReadNoWait;
	/*0x20C4*/     ULONG32      CcFastReadWait;
	/*0x20C8*/     ULONG32      CcFastReadNotPossible;
	/*0x20CC*/     ULONG32      CcCopyReadNoWait;
	/*0x20D0*/     ULONG32      CcCopyReadWait;
	/*0x20D4*/     ULONG32      CcCopyReadNoWaitMiss;
	/*0x20D8*/     LONG32       LookasideIrpFloat;
	/*0x20DC*/     LONG32       IoReadOperationCount;
	/*0x20E0*/     LONG32       IoWriteOperationCount;
	/*0x20E4*/     LONG32       IoOtherOperationCount;
	/*0x20E8*/     union _LARGE_INTEGER IoReadTransferCount;                           // 4 elements, 0x8 bytes (sizeof)
	/*0x20F0*/     union _LARGE_INTEGER IoWriteTransferCount;                          // 4 elements, 0x8 bytes (sizeof)
	/*0x20F8*/     union _LARGE_INTEGER IoOtherTransferCount;                          // 4 elements, 0x8 bytes (sizeof)
	/*0x2100*/     LONG32       TargetCount;
	/*0x2104*/     ULONG32      IpiFrozen;
	/*0x2108*/     UINT8        _PADDING3_[0x78];
	/*0x2180*/     struct _KDPC_DATA DpcData[2];
	/*0x21C0*/     VOID* DpcStack;
	/*0x21C8*/     LONG32       MaximumDpcQueueDepth;
	/*0x21CC*/     ULONG32      DpcRequestRate;
	/*0x21D0*/     ULONG32      MinimumDpcRate;
	/*0x21D4*/     ULONG32      DpcLastCount;
	/*0x21D8*/     UINT8        ThreadDpcEnable;
	/*0x21D9*/     UINT8        QuantumEnd;
	/*0x21DA*/     UINT8        DpcRoutineActive;
	/*0x21DB*/     UINT8        IdleSchedule;
	union                                                               // 3 elements, 0x4 bytes (sizeof)
	{
		/*0x21DC*/         LONG32       DpcRequestSummary;
		/*0x21DC*/         INT16        DpcRequestSlot[2];
		struct                                                          // 2 elements, 0x4 bytes (sizeof)
		{
			/*0x21DC*/             INT16        NormalDpcState;
			union                                                       // 2 elements, 0x2 bytes (sizeof)
			{
				/*0x21DE*/                 UINT16       DpcThreadActive : 1;                       // 0 BitPosition
				/*0x21DE*/                 INT16        ThreadDpcState;
			};
		};
	};
	/*0x21E0*/     ULONG32      TimerHand;
	/*0x21E4*/     LONG32       MasterOffset;
	/*0x21E8*/     ULONG32      LastTick;
	/*0x21EC*/     ULONG32      UnusedPad;
	/*0x21F0*/     UINT64       PrcbPad50[2];
	/*0x2200*/     struct _KTIMER_TABLE TimerTable;                                    // 2 elements, 0x2200 bytes (sizeof)
	/*0x4400*/     struct _KGATE DpcGate;                                              // 1 elements, 0x18 bytes (sizeof)
	/*0x4418*/     VOID* PrcbPad52;
	/*0x4420*/     struct _KDPC CallDpc;                                               // 9 elements, 0x40 bytes (sizeof)
	/*0x4460*/     LONG32       ClockKeepAlive;
	/*0x4464*/     UINT8        ClockCheckSlot;
	/*0x4465*/     UINT8        ClockPollCycle;
	/*0x4466*/     UINT16       NmiActive;
	/*0x4468*/     LONG32       DpcWatchdogPeriod;
	/*0x446C*/     LONG32       DpcWatchdogCount;
	/*0x4470*/     UINT64       TickOffset;
	/*0x4478*/     LONG32       KeSpinLockOrdering;
	/*0x447C*/     ULONG32      PrcbPad70;
	/*0x4480*/     struct _LIST_ENTRY WaitListHead;                                    // 2 elements, 0x10 bytes (sizeof)
	/*0x4490*/     UINT64       WaitLock;
	/*0x4498*/     ULONG32      ReadySummary;
	/*0x449C*/     ULONG32      QueueIndex;
	/*0x44A0*/     struct _KDPC TimerExpirationDpc;                                    // 9 elements, 0x40 bytes (sizeof)
	/*0x44E0*/     UINT64       PrcbPad72[4];
	/*0x4500*/     struct _LIST_ENTRY DispatcherReadyListHead[32];
	/*0x4700*/     ULONG32      InterruptCount;
	/*0x4704*/     ULONG32      KernelTime;
	/*0x4708*/     ULONG32      UserTime;
	/*0x470C*/     ULONG32      DpcTime;
	/*0x4710*/     ULONG32      InterruptTime;
	/*0x4714*/     ULONG32      AdjustDpcThreshold;
	/*0x4718*/     UINT8        DebuggerSavedIRQL;
	/*0x4719*/     UINT8        PrcbPad80[7];
	/*0x4720*/     ULONG32      DpcTimeCount;
	/*0x4724*/     ULONG32      DpcTimeLimit;
	/*0x4728*/     ULONG32      PeriodicCount;
	/*0x472C*/     ULONG32      PeriodicBias;
	/*0x4730*/     ULONG32      AvailableTime;
	/*0x4734*/     ULONG32      KeExceptionDispatchCount;
	/*0x4738*/     struct _KNODE* ParentNode;
	/*0x4740*/     UINT64       StartCycles;
	/*0x4748*/     UINT64       PrcbPad82[3];
	/*0x4760*/     LONG32       MmSpinLockOrdering;
	/*0x4764*/     ULONG32      PageColor;
	/*0x4768*/     ULONG32      NodeColor;
	/*0x476C*/     ULONG32      NodeShiftedColor;
	/*0x4770*/     ULONG32      SecondaryColorMask;
	/*0x4774*/     ULONG32      PrcbPad83;
	/*0x4778*/     UINT64       CycleTime;
	/*0x4780*/     ULONG32      CcFastMdlReadNoWait;
	/*0x4784*/     ULONG32      CcFastMdlReadWait;
	/*0x4788*/     ULONG32      CcFastMdlReadNotPossible;
	/*0x478C*/     ULONG32      CcMapDataNoWait;
	/*0x4790*/     ULONG32      CcMapDataWait;
	/*0x4794*/     ULONG32      CcPinMappedDataCount;
	/*0x4798*/     ULONG32      CcPinReadNoWait;
	/*0x479C*/     ULONG32      CcPinReadWait;
	/*0x47A0*/     ULONG32      CcMdlReadNoWait;
	/*0x47A4*/     ULONG32      CcMdlReadWait;
	/*0x47A8*/     ULONG32      CcLazyWriteHotSpots;
	/*0x47AC*/     ULONG32      CcLazyWriteIos;
	/*0x47B0*/     ULONG32      CcLazyWritePages;
	/*0x47B4*/     ULONG32      CcDataFlushes;
	/*0x47B8*/     ULONG32      CcDataPages;
	/*0x47BC*/     ULONG32      CcLostDelayedWrites;
	/*0x47C0*/     ULONG32      CcFastReadResourceMiss;
	/*0x47C4*/     ULONG32      CcCopyReadWaitMiss;
	/*0x47C8*/     ULONG32      CcFastMdlReadResourceMiss;
	/*0x47CC*/     ULONG32      CcMapDataNoWaitMiss;
	/*0x47D0*/     ULONG32      CcMapDataWaitMiss;
	/*0x47D4*/     ULONG32      CcPinReadNoWaitMiss;
	/*0x47D8*/     ULONG32      CcPinReadWaitMiss;
	/*0x47DC*/     ULONG32      CcMdlReadNoWaitMiss;
	/*0x47E0*/     ULONG32      CcMdlReadWaitMiss;
	/*0x47E4*/     ULONG32      CcReadAheadIos;
	/*0x47E8*/     LONG32       MmCacheTransitionCount;
	/*0x47EC*/     LONG32       MmCacheReadCount;
	/*0x47F0*/     LONG32       MmCacheIoCount;
	/*0x47F4*/     ULONG32      PrcbPad91[1];
	/*0x47F8*/     UINT64       RuntimeAccumulation;
	/*0x4800*/     struct _PROCESSOR_POWER_STATE PowerState;                           // 27 elements, 0x100 bytes (sizeof)
	/*0x4900*/     UINT8        PrcbPad92[16];
	/*0x4910*/     ULONG32      KeAlignmentFixupCount;
	/*0x4914*/     UINT8        _PADDING4_[0x4];
	/*0x4918*/     struct _KDPC DpcWatchdogDpc;                                        // 9 elements, 0x40 bytes (sizeof)
	/*0x4958*/     struct _KTIMER DpcWatchdogTimer;                                    // 6 elements, 0x40 bytes (sizeof)
	/*0x4998*/     struct _CACHE_DESCRIPTOR Cache[5];
	/*0x49D4*/     ULONG32      CacheCount;
	/*0x49D8*/     ULONG32      CachedCommit;
	/*0x49DC*/     ULONG32      CachedResidentAvailable;
	/*0x49E0*/     VOID* HyperPte;
	/*0x49E8*/     VOID* WheaInfo;
	/*0x49F0*/     VOID* EtwSupport;
	/*0x49F8*/     UINT8        _PADDING5_[0x8];
	/*0x4A00*/     union _SLIST_HEADER InterruptObjectPool;                            // 5 elements, 0x10 bytes (sizeof)
	/*0x4A10*/     union _SLIST_HEADER HypercallPageList;                              // 5 elements, 0x10 bytes (sizeof)
	/*0x4A20*/     VOID* HypercallPageVirtual;
	/*0x4A28*/     VOID* VirtualApicAssist;
	/*0x4A30*/     UINT64* StatisticsPage;
	/*0x4A38*/     VOID* RateControl;
	/*0x4A40*/     UINT64       CacheProcessorMask[5];
	/*0x4A68*/     struct _KAFFINITY_EX PackageProcessorSet;                           // 4 elements, 0x28 bytes (sizeof)
	/*0x4A90*/     UINT64       CoreProcessorSet;
	/*0x4A98*/     VOID* PebsIndexAddress;
	/*0x4AA0*/     UINT64       PrcbPad93[12];
	/*0x4B00*/     ULONG32      SpinLockAcquireCount;
	/*0x4B04*/     ULONG32      SpinLockContentionCount;
	/*0x4B08*/     ULONG32      SpinLockSpinCount;
	/*0x4B0C*/     ULONG32      IpiSendRequestBroadcastCount;
	/*0x4B10*/     ULONG32      IpiSendRequestRoutineCount;
	/*0x4B14*/     ULONG32      IpiSendSoftwareInterruptCount;
	/*0x4B18*/     ULONG32      ExInitializeResourceCount;
	/*0x4B1C*/     ULONG32      ExReInitializeResourceCount;
	/*0x4B20*/     ULONG32      ExDeleteResourceCount;
	/*0x4B24*/     ULONG32      ExecutiveResourceAcquiresCount;
	/*0x4B28*/     ULONG32      ExecutiveResourceContentionsCount;
	/*0x4B2C*/     ULONG32      ExecutiveResourceReleaseExclusiveCount;
	/*0x4B30*/     ULONG32      ExecutiveResourceReleaseSharedCount;
	/*0x4B34*/     ULONG32      ExecutiveResourceConvertsCount;
	/*0x4B38*/     ULONG32      ExAcqResExclusiveAttempts;
	/*0x4B3C*/     ULONG32      ExAcqResExclusiveAcquiresExclusive;
	/*0x4B40*/     ULONG32      ExAcqResExclusiveAcquiresExclusiveRecursive;
	/*0x4B44*/     ULONG32      ExAcqResExclusiveWaits;
	/*0x4B48*/     ULONG32      ExAcqResExclusiveNotAcquires;
	/*0x4B4C*/     ULONG32      ExAcqResSharedAttempts;
	/*0x4B50*/     ULONG32      ExAcqResSharedAcquiresExclusive;
	/*0x4B54*/     ULONG32      ExAcqResSharedAcquiresShared;
	/*0x4B58*/     ULONG32      ExAcqResSharedAcquiresSharedRecursive;
	/*0x4B5C*/     ULONG32      ExAcqResSharedWaits;
	/*0x4B60*/     ULONG32      ExAcqResSharedNotAcquires;
	/*0x4B64*/     ULONG32      ExAcqResSharedStarveExclusiveAttempts;
	/*0x4B68*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresExclusive;
	/*0x4B6C*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresShared;
	/*0x4B70*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresSharedRecursive;
	/*0x4B74*/     ULONG32      ExAcqResSharedStarveExclusiveWaits;
	/*0x4B78*/     ULONG32      ExAcqResSharedStarveExclusiveNotAcquires;
	/*0x4B7C*/     ULONG32      ExAcqResSharedWaitForExclusiveAttempts;
	/*0x4B80*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresExclusive;
	/*0x4B84*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresShared;
	/*0x4B88*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive;
	/*0x4B8C*/     ULONG32      ExAcqResSharedWaitForExclusiveWaits;
	/*0x4B90*/     ULONG32      ExAcqResSharedWaitForExclusiveNotAcquires;
	/*0x4B94*/     ULONG32      ExSetResOwnerPointerExclusive;
	/*0x4B98*/     ULONG32      ExSetResOwnerPointerSharedNew;
	/*0x4B9C*/     ULONG32      ExSetResOwnerPointerSharedOld;
	/*0x4BA0*/     ULONG32      ExTryToAcqExclusiveAttempts;
	/*0x4BA4*/     ULONG32      ExTryToAcqExclusiveAcquires;
	/*0x4BA8*/     ULONG32      ExBoostExclusiveOwner;
	/*0x4BAC*/     ULONG32      ExBoostSharedOwners;
	/*0x4BB0*/     ULONG32      ExEtwSynchTrackingNotificationsCount;
	/*0x4BB4*/     ULONG32      ExEtwSynchTrackingNotificationsAccountedCount;
	/*0x4BB8*/     UINT8        VendorString[13];
	/*0x4BC5*/     UINT8        PrcbPad10[3];
	/*0x4BC8*/     ULONG32      FeatureBits;
	/*0x4BCC*/     UINT8        _PADDING6_[0x4];
	/*0x4BD0*/     union _LARGE_INTEGER UpdateSignature;                               // 4 elements, 0x8 bytes (sizeof)
	/*0x4BD8*/     struct _CONTEXT* Context;
	/*0x4BE0*/     ULONG32      ContextFlags;
	/*0x4BE4*/     UINT8        _PADDING7_[0x4];
	/*0x4BE8*/     struct _XSAVE_AREA* ExtendedState;
	/*0x4BF0*/     UINT8        _PADDING8_[0x10];
	/*0x4C00*/     struct _REQUEST_MAILBOX* Mailbox;
	/*0x4C08*/     UINT8        _PADDING9_[0x78];
	/*0x4C80*/     struct _REQUEST_MAILBOX RequestMailbox[1];
	/*0x4CC0*/     UINT8        _PADDING10_[0x40];
}KPRCB, * PKPRCB;

typedef struct _COUNTER_READING       // 4 elements, 0x18 bytes (sizeof)
{
	/*0x000*/     enum _HARDWARE_COUNTER_TYPE Type;
	/*0x004*/     ULONG32      Index;
	/*0x008*/     UINT64       Start;
	/*0x010*/     UINT64       Total;
}COUNTER_READING, * PCOUNTER_READING;

typedef struct _THREAD_PERFORMANCE_DATA       // 10 elements, 0x1C0 bytes (sizeof)
{
	/*0x000*/     UINT16       Size;
	/*0x002*/     UINT16       Version;
	/*0x004*/     struct _PROCESSOR_NUMBER ProcessorNumber; // 3 elements, 0x4 bytes (sizeof)
	/*0x008*/     ULONG32      ContextSwitches;
	/*0x00C*/     ULONG32      HwCountersCount;
	/*0x010*/     UINT64       UpdateCount;
	/*0x018*/     UINT64       WaitReasonBitMap;
	/*0x020*/     UINT64       HardwareCounters;
	/*0x028*/     struct _COUNTER_READING CycleTime;        // 4 elements, 0x18 bytes (sizeof)
	/*0x040*/     struct _COUNTER_READING HwCounters[16];
}THREAD_PERFORMANCE_DATA, * PTHREAD_PERFORMANCE_DATA;

typedef struct _KTHREAD_COUNTERS               // 7 elements, 0x1A8 bytes (sizeof)
{
	/*0x000*/     UINT64       WaitReasonBitMap;
	/*0x008*/     struct _THREAD_PERFORMANCE_DATA* UserData;
	/*0x010*/     ULONG32      Flags;
	/*0x014*/     ULONG32      ContextSwitches;
	/*0x018*/     UINT64       CycleTimeBias;
	/*0x020*/     UINT64       HardwareCounters;
	/*0x028*/     struct _COUNTER_READING HwCounter[16];
}KTHREAD_COUNTERS, * PKTHREAD_COUNTERS;
/*
typedef struct __XSAVE_FORMAT{
	WORD	 ControlWord;//     : Uint2B
	WORD	 StatusWord;// : Uint2B
	UCHAR	 TagWord;// : UChar
	UCHAR Reserved1; //: UChar
	WORD ErrorOpcode;// : Uint2B
	DWORD ErrorOffset;// : Uint4B
	WORD ErrorSelector;// : Uint2B
	WORD Reserved2;// : Uint2B
	DWORD DataOffset;// : Uint4B
	WORD DataSelector;// : Uint2B
	WORD	 Reserved3;// : Uint2B
	DWORD	MxCsr;// : Uint4B
	DWORD MxCsr_Mask;// : Uint4B
	M128A FloatRegisters[8];// : [8] _M128A
	M128A	 XmmRegisters[16];// _M128A
	UCHAR Reserved4[96];// UChar



}KXSAVE_FORMAT, *KPXSAVE_FORMAT;*/

typedef struct _TERMINATION_PORT    // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     struct _TERMINATION_PORT* Next;
	/*0x008*/     VOID* Port;
}TERMINATION_PORT, * PTERMINATION_PORT;

#ifndef _LIST_ENTRY64_S_
#define _LIST_ENTRY64_S_
typedef struct _LIST_ENTRY64_S // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     UINT64       Flink;
	/*0x008*/     UINT64       Blink;
}LIST_ENTRY64_S, * PLIST_ENTRY64_S;
#endif // !_LIST_ENTRY64_S_

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

typedef struct _RTL_AVL_TREE
{
	/* 0x0000 */ struct _RTL_BALANCED_NODE* Root;
} RTL_AVL_TREE, * PRTL_AVL_TREE; /* size: 0x0008 */

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

typedef struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
	/* 0x0000 */ struct _RTL_AVL_TREE Tree;
	/* 0x0008 */ struct _EX_PUSH_LOCK Lock;
} PS_DYNAMIC_ENFORCED_ADDRESS_RANGES, * PPS_DYNAMIC_ENFORCED_ADDRESS_RANGES; /* size: 0x0010 */

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
/*
+0x000 InheritedAddressSpace : UChar
+ 0x001 ReadImageFileExecOptions : UChar
+ 0x002 BeingDebugged : UChar
+ 0x003 BitField : UChar
+ 0x003 ImageUsesLargePages : Pos 0, 1 Bit
+ 0x003 IsProtectedProcess : Pos 1, 1 Bit
+ 0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
+ 0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
+ 0x003 IsPackagedProcess : Pos 4, 1 Bit
+ 0x003 IsAppContainer : Pos 5, 1 Bit
+ 0x003 IsProtectedProcessLight : Pos 6, 1 Bit
+ 0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
+ 0x004 Padding0 : [4] UChar
+ 0x008 Mutant : Ptr64 Void
+ 0x010 ImageBaseAddress : Ptr64 Void
+ 0x018 Ldr : Ptr64 _PEB_LDR_DATA
+ 0x020 ProcessParameters : Ptr64 _RTL_USER_PROCESS_PARAMETERS
+ 0x028 SubSystemData : Ptr64 Void
+ 0x030 ProcessHeap : Ptr64 Void
+ 0x038 FastPebLock : Ptr64 _RTL_CRITICAL_SECTION
+ 0x040 AtlThunkSListPtr : Ptr64 _SLIST_HEADER
+ 0x048 IFEOKey : Ptr64 Void
+ 0x050 CrossProcessFlags : Uint4B
+ 0x050 ProcessInJob : Pos 0, 1 Bit
+ 0x050 ProcessInitializing : Pos 1, 1 Bit
+ 0x050 ProcessUsingVEH : Pos 2, 1 Bit
+ 0x050 ProcessUsingVCH : Pos 3, 1 Bit
+ 0x050 ProcessUsingFTH : Pos 4, 1 Bit
+ 0x050 ProcessPreviouslyThrottled : Pos 5, 1 Bit
+ 0x050 ProcessCurrentlyThrottled : Pos 6, 1 Bit
+ 0x050 ProcessImagesHotPatched : Pos 7, 1 Bit
+ 0x050 ReservedBits0 : Pos 8, 24 Bits
+ 0x054 Padding1 : [4] UChar
+ 0x058 KernelCallbackTable : Ptr64 Void
+ 0x058 UserSharedInfoPtr : Ptr64 Void
+ 0x060 SystemReserved : Uint4B
+ 0x064 AtlThunkSListPtr32 : Uint4B
+ 0x068 ApiSetMap : Ptr64 Void
+ 0x070 TlsExpansionCounter : Uint4B
+ 0x074 Padding2 : [4] UChar
+ 0x078 TlsBitmap : Ptr64 Void
+ 0x080 TlsBitmapBits : [2] Uint4B
+ 0x088 ReadOnlySharedMemoryBase : Ptr64 Void
+ 0x090 SharedData : Ptr64 Void
+ 0x098 ReadOnlyStaticServerData : Ptr64 Ptr64 Void
+ 0x0a0 AnsiCodePageData : Ptr64 Void
+ 0x0a8 OemCodePageData : Ptr64 Void
+ 0x0b0 UnicodeCaseTableData : Ptr64 Void
+ 0x0b8 NumberOfProcessors : Uint4B
+ 0x0bc NtGlobalFlag : Uint4B
+ 0x0c0 CriticalSectionTimeout : _LARGE_INTEGER
+ 0x0c8 HeapSegmentReserve : Uint8B
+ 0x0d0 HeapSegmentCommit : Uint8B
+ 0x0d8 HeapDeCommitTotalFreeThreshold : Uint8B
+ 0x0e0 HeapDeCommitFreeBlockThreshold : Uint8B
+ 0x0e8 NumberOfHeaps : Uint4B
+ 0x0ec MaximumNumberOfHeaps : Uint4B
+ 0x0f0 ProcessHeaps : Ptr64 Ptr64 Void
+ 0x0f8 GdiSharedHandleTable : Ptr64 Void
+ 0x100 ProcessStarterHelper : Ptr64 Void
+ 0x108 GdiDCAttributeList : Uint4B
+ 0x10c Padding3 : [4] UChar
+ 0x110 LoaderLock : Ptr64 _RTL_CRITICAL_SECTION
+ 0x118 OSMajorVersion : Uint4B
+ 0x11c OSMinorVersion : Uint4B
+ 0x120 OSBuildNumber : Uint2B
+ 0x122 OSCSDVersion : Uint2B
+ 0x124 OSPlatformId : Uint4B
+ 0x128 ImageSubsystem : Uint4B
+ 0x12c ImageSubsystemMajorVersion : Uint4B
+ 0x130 ImageSubsystemMinorVersion : Uint4B
+ 0x134 Padding4 : [4] UChar
+ 0x138 ActiveProcessAffinityMask : Uint8B
+ 0x140 GdiHandleBuffer : [60] Uint4B
+ 0x230 PostProcessInitRoutine : Ptr64     void
+ 0x238 TlsExpansionBitmap : Ptr64 Void
+ 0x240 TlsExpansionBitmapBits : [32] Uint4B
+ 0x2c0 SessionId : Uint4B
+ 0x2c4 Padding5 : [4] UChar
+ 0x2c8 AppCompatFlags : _ULARGE_INTEGER
+ 0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER
+ 0x2d8 pShimData : Ptr64 Void
+ 0x2e0 AppCompatInfo : Ptr64 Void
+ 0x2e8 CSDVersion : _UNICODE_STRING
+ 0x2f8 ActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
+ 0x300 ProcessAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
+ 0x308 SystemDefaultActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
+ 0x310 SystemAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
+ 0x318 MinimumStackCommit : Uint8B
+ 0x320 SparePointers : [4] Ptr64 Void
+ 0x340 SpareUlongs : [5] Uint4B
+ 0x358 WerRegistrationData : Ptr64 Void
+ 0x360 WerShipAssertPtr : Ptr64 Void
+ 0x368 pUnused : Ptr64 Void
+ 0x370 pImageHeaderHash : Ptr64 Void
+ 0x378 TracingFlags : Uint4B
+ 0x378 HeapTracingEnabled : Pos 0, 1 Bit
+ 0x378 CritSecTracingEnabled : Pos 1, 1 Bit
+ 0x378 LibLoaderTracingEnabled : Pos 2, 1 Bit
+ 0x378 SpareTracingBits : Pos 3, 29 Bits
+ 0x37c Padding6 : [4] UChar
+ 0x380 CsrServerReadOnlySharedMemoryBase : Uint8B
+ 0x388 TppWorkerpListLock : Uint8B
+ 0x390 TppWorkerpList : _LIST_ENTRY
+ 0x3a0 WaitOnAddressHashTable : [128] Ptr64 Void
+ 0x7a0 TelemetryCoverageHeader : Ptr64 Void
+ 0x7a8 CloudFileFlags : Uint4B
+ 0x7ac CloudFileDiagFlags : Uint4B
+ 0x7b0 PlaceholderCompatibilityMode : Char
+ 0x7b1 PlaceholderCompatibilityModeReserved : [7] Char
+ 0x7b8 LeapSecondData : Ptr64 _LEAP_SECOND_DATA
+ 0x7c0 LeapSecondFlags : Uint4B
+ 0x7c0 SixtySecondEnabled : Pos 0, 1 Bit
+ 0x7c0 Reserved : Pos 1, 31 Bits
+ 0x7c4 NtGlobalFlag2 : Uint4B
*/
#endif

typedef struct _EPROCESS_S
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
} EPROCESS_S, * PEPROCESS_S; /* size: 0x0a40 */

typedef struct _EPROCESS_test
{
	/* 0x0000 */ struct _KPROCESS Pcb;
	/* 0x0438 */ struct _EX_PUSH_LOCK ProcessLock;
	/* 0x0440 */ void* UniqueProcessId;
	/* 0x0448 */ struct _LIST_ENTRY ActiveProcessLinks;
	/* 0x0458 */ struct _EX_RUNDOWN_REF RundownProtect;
}EPROCESS_test, * PEPROCESS_test;


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

typedef struct _CLIENT_ID64     // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     UINT64       UniqueProcess;
	/*0x008*/     UINT64       UniqueThread;
}CLIENT_ID64, * PCLIENT_ID64;

typedef struct _GDI_TEB_BATCH64   // 3 elements, 0x4E8 bytes (sizeof)
{
	/*0x000*/     ULONG32      Offset;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     UINT64       HDC;
	/*0x010*/     ULONG32      Buffer[310];
}GDI_TEB_BATCH64, * PGDI_TEB_BATCH64;

typedef struct _ACTIVATION_CONTEXT_STACK64
{
	/* 0x0000 */ unsigned __int64 ActiveFrame;
	/* 0x0008 */ struct LIST_ENTRY64 FrameListCache;
	/* 0x0018 */ unsigned long Flags;
	/* 0x001c */ unsigned long NextCookieSequenceNumber;
	/* 0x0020 */ unsigned long StackId;
	/* 0x0024 */ long __PADDING__[1];
} ACTIVATION_CONTEXT_STACK64, * PACTIVATION_CONTEXT_STACK64; /* size: 0x0028 */

typedef struct _TEB64
{
	/* 0x0000 */ struct _NT_TIB64 NtTib;
	/* 0x0038 */ unsigned __int64 EnvironmentPointer;
	/* 0x0040 */ struct _CLIENT_ID64 ClientId;
	/* 0x0050 */ unsigned __int64 ActiveRpcHandle;
	/* 0x0058 */ unsigned __int64 ThreadLocalStoragePointer;
	/* 0x0060 */ unsigned __int64 ProcessEnvironmentBlock;
	/* 0x0068 */ unsigned long LastErrorValue;
	/* 0x006c */ unsigned long CountOfOwnedCriticalSections;
	/* 0x0070 */ unsigned __int64 CsrClientThread;
	/* 0x0078 */ unsigned __int64 Win32ThreadInfo;
	/* 0x0080 */ unsigned long User32Reserved[26];
	/* 0x00e8 */ unsigned long UserReserved[5];
	/* 0x00fc */ long Padding_2;
	/* 0x0100 */ unsigned __int64 WOW32Reserved;
	/* 0x0108 */ unsigned long CurrentLocale;
	/* 0x010c */ unsigned long FpSoftwareStatusRegister;
	/* 0x0110 */ unsigned __int64 ReservedForDebuggerInstrumentation[16];
	/* 0x0190 */ unsigned __int64 SystemReserved1[30];
	/* 0x0280 */ char PlaceholderCompatibilityMode;
	/* 0x0281 */ unsigned char PlaceholderHydrationAlwaysExplicit;
	/* 0x0282 */ char PlaceholderReserved[10];
	/* 0x028c */ unsigned long ProxiedProcessId;
	/* 0x0290 */ struct _ACTIVATION_CONTEXT_STACK64 _ActivationStack;
	/* 0x02b8 */ unsigned char WorkingOnBehalfTicket[8];
	/* 0x02c0 */ long ExceptionCode;
	/* 0x02c4 */ unsigned char Padding0[4];
	/* 0x02c8 */ unsigned __int64 ActivationContextStackPointer;
	/* 0x02d0 */ unsigned __int64 InstrumentationCallbackSp;
	/* 0x02d8 */ unsigned __int64 InstrumentationCallbackPreviousPc;
	/* 0x02e0 */ unsigned __int64 InstrumentationCallbackPreviousSp;
	/* 0x02e8 */ unsigned long TxFsContext;
	/* 0x02ec */ unsigned char InstrumentationCallbackDisabled;
	/* 0x02ed */ unsigned char UnalignedLoadStoreExceptions;
	/* 0x02ee */ unsigned char Padding1[2];
	/* 0x02f0 */ struct _GDI_TEB_BATCH64 GdiTebBatch;
	/* 0x07d8 */ struct _CLIENT_ID64 RealClientId;
	/* 0x07e8 */ unsigned __int64 GdiCachedProcessHandle;
	/* 0x07f0 */ unsigned long GdiClientPID;
	/* 0x07f4 */ unsigned long GdiClientTID;
	/* 0x07f8 */ unsigned __int64 GdiThreadLocalInfo;
	/* 0x0800 */ unsigned __int64 Win32ClientInfo[62];
	/* 0x09f0 */ unsigned __int64 glDispatchTable[233];
	/* 0x1138 */ unsigned __int64 glReserved1[29];
	/* 0x1220 */ unsigned __int64 glReserved2;
	/* 0x1228 */ unsigned __int64 glSectionInfo;
	/* 0x1230 */ unsigned __int64 glSection;
	/* 0x1238 */ unsigned __int64 glTable;
	/* 0x1240 */ unsigned __int64 glCurrentRC;
	/* 0x1248 */ unsigned __int64 glContext;
	/* 0x1250 */ unsigned long LastStatusValue;
	/* 0x1254 */ unsigned char Padding2[4];
	/* 0x1258 */ struct _STRING64 StaticUnicodeString;
	/* 0x1268 */ wchar_t StaticUnicodeBuffer[261];
	/* 0x1472 */ unsigned char Padding3[6];
	/* 0x1478 */ unsigned __int64 DeallocationStack;
	/* 0x1480 */ unsigned __int64 TlsSlots[64];
	/* 0x1680 */ struct LIST_ENTRY64 TlsLinks;
	/* 0x1690 */ unsigned __int64 Vdm;
	/* 0x1698 */ unsigned __int64 ReservedForNtRpc;
	/* 0x16a0 */ unsigned __int64 DbgSsReserved[2];
	/* 0x16b0 */ unsigned long HardErrorMode;
	/* 0x16b4 */ unsigned char Padding4[4];
	/* 0x16b8 */ unsigned __int64 Instrumentation[11];
	/* 0x1710 */ struct _GUID ActivityId;
	/* 0x1720 */ unsigned __int64 SubProcessTag;
	/* 0x1728 */ unsigned __int64 PerflibData;
	/* 0x1730 */ unsigned __int64 EtwTraceData;
	/* 0x1738 */ unsigned __int64 WinSockData;
	/* 0x1740 */ unsigned long GdiBatchCount;
	union
	{
		/* 0x1744 */ struct _PROCESSOR_NUMBER CurrentIdealProcessor;
		/* 0x1744 */ unsigned long IdealProcessorValue;
		struct
		{
			/* 0x1744 */ unsigned char ReservedPad0;
			/* 0x1745 */ unsigned char ReservedPad1;
			/* 0x1746 */ unsigned char ReservedPad2;
			/* 0x1747 */ unsigned char IdealProcessor;
		}; /* size: 0x0004 */
	}; /* size: 0x0004 */
	/* 0x1748 */ unsigned long GuaranteedStackBytes;
	/* 0x174c */ unsigned char Padding5[4];
	/* 0x1750 */ unsigned __int64 ReservedForPerf;
	/* 0x1758 */ unsigned __int64 ReservedForOle;
	/* 0x1760 */ unsigned long WaitingOnLoaderLock;
	/* 0x1764 */ unsigned char Padding6[4];
	/* 0x1768 */ unsigned __int64 SavedPriorityState;
	/* 0x1770 */ unsigned __int64 ReservedForCodeCoverage;
	/* 0x1778 */ unsigned __int64 ThreadPoolData;
	/* 0x1780 */ unsigned __int64 TlsExpansionSlots;
	/* 0x1788 */ unsigned __int64 DeallocationBStore;
	/* 0x1790 */ unsigned __int64 BStoreLimit;
	/* 0x1798 */ unsigned long MuiGeneration;
	/* 0x179c */ unsigned long IsImpersonating;
	/* 0x17a0 */ unsigned __int64 NlsCache;
	/* 0x17a8 */ unsigned __int64 pShimData;
	/* 0x17b0 */ unsigned long HeapData;
	/* 0x17b4 */ unsigned char Padding7[4];
	/* 0x17b8 */ unsigned __int64 CurrentTransactionHandle;
	/* 0x17c0 */ unsigned __int64 ActiveFrame;
	/* 0x17c8 */ unsigned __int64 FlsData;
	/* 0x17d0 */ unsigned __int64 PreferredLanguages;
	/* 0x17d8 */ unsigned __int64 UserPrefLanguages;
	/* 0x17e0 */ unsigned __int64 MergedPrefLanguages;
	/* 0x17e8 */ unsigned long MuiImpersonation;
	union
	{
		/* 0x17ec */ volatile unsigned short CrossTebFlags;
		/* 0x17ec */ unsigned short SpareCrossTebBits : 16; /* bit position: 0 */
	}; /* size: 0x0002 */
	union
	{
		/* 0x17ee */ unsigned short SameTebFlags;
		struct /* bitfield */
		{
			/* 0x17ee */ unsigned short SafeThunkCall : 1; /* bit position: 0 */
			/* 0x17ee */ unsigned short InDebugPrint : 1; /* bit position: 1 */
			/* 0x17ee */ unsigned short HasFiberData : 1; /* bit position: 2 */
			/* 0x17ee */ unsigned short SkipThreadAttach : 1; /* bit position: 3 */
			/* 0x17ee */ unsigned short WerInShipAssertCode : 1; /* bit position: 4 */
			/* 0x17ee */ unsigned short RanProcessInit : 1; /* bit position: 5 */
			/* 0x17ee */ unsigned short ClonedThread : 1; /* bit position: 6 */
			/* 0x17ee */ unsigned short SuppressDebugMsg : 1; /* bit position: 7 */
			/* 0x17ee */ unsigned short DisableUserStackWalk : 1; /* bit position: 8 */
			/* 0x17ee */ unsigned short RtlExceptionAttached : 1; /* bit position: 9 */
			/* 0x17ee */ unsigned short InitialThread : 1; /* bit position: 10 */
			/* 0x17ee */ unsigned short SessionAware : 1; /* bit position: 11 */
			/* 0x17ee */ unsigned short LoadOwner : 1; /* bit position: 12 */
			/* 0x17ee */ unsigned short LoaderWorker : 1; /* bit position: 13 */
			/* 0x17ee */ unsigned short SkipLoaderInit : 1; /* bit position: 14 */
			/* 0x17ee */ unsigned short SpareSameTebBits : 1; /* bit position: 15 */
		}; /* bitfield */
	}; /* size: 0x0002 */
	/* 0x17f0 */ unsigned __int64 TxnScopeEnterCallback;
	/* 0x17f8 */ unsigned __int64 TxnScopeExitCallback;
	/* 0x1800 */ unsigned __int64 TxnScopeContext;
	/* 0x1808 */ unsigned long LockCount;
	/* 0x180c */ long WowTebOffset;
	/* 0x1810 */ unsigned __int64 ResourceRetValue;
	/* 0x1818 */ unsigned __int64 ReservedForWdf;
	/* 0x1820 */ unsigned __int64 ReservedForCrt;
	/* 0x1828 */ struct _GUID EffectiveContainerId;
} TEB64, * PTEB64; /* size: 0x1838 */










#define THREAD_TERMINATE						(0x0001)  
#define THREAD_SUSPEND_RESUME					(0x0002)  
#define THREAD_GET_CONTEXT						(0x0008)  
#define THREAD_SET_CONTEXT						(0x0010)  
#define THREAD_QUERY_INFORMATION				(0x0040)  
#define THREAD_SET_INFORMATION					(0x0020)  
#define THREAD_SET_THREAD_TOKEN					(0x0080)
#define THREAD_IMPERSONATE						(0x0100)
#define THREAD_DIRECT_IMPERSONATION				(0x0200)

#define PROCESS_TERMINATE						(0x0001)  
#define PROCESS_CREATE_THREAD					(0x0002)  
#define PROCESS_SET_SESSIONID					(0x0004)  
#define PROCESS_VM_OPERATION					(0x0008)  
#define PROCESS_VM_READ							(0x0010)  
#define PROCESS_VM_WRITE						(0x0020)  
#define PROCESS_DUP_HANDLE						(0x0040)  
#define PROCESS_CREATE_PROCESS					(0x0080)  
#define PROCESS_SET_QUOTA						(0x0100)  
#define PROCESS_SET_INFORMATION					(0x0200)  
#define PROCESS_QUERY_INFORMATION				(0x0400)  
#define PROCESS_SUSPEND_RESUME					(0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION		(0x1000)  

//////////////////////////////////////////////////////////////////////////////////////////////////////////////EPROCESS 
typedef struct _SEP_TOKEN_PRIVILEGES
{
	ULONG64 Present;
	ULONG64 Enabled;
	ULONG64 EnabledByDefault;
}SEP_TOKEN_PRIVILEGES,*PSEP_TOKEN_PRIVILEGES;
typedef struct _SEP_AUDIT_POLICY
{
	UCHAR AdtTokenPolicy[27];
	UCHAR PolicySetStatus;
}SEP_AUDIT_POLICY,*PSEP_AUDIT_POLICY;

typedef struct _TOKEN
{
	TOKEN_SOURCE TokenSource;
	LUID          TokenId;
	LUID          AuthenticationId;
	LUID ParentTokenId;
	LARGE_INTEGER  ExpirationTime;
	ERESOURCE* TokenLock;
	LUID ModifiedId;
	SEP_TOKEN_PRIVILEGES Privileges;
	SEP_AUDIT_POLICY AuditPolicy;
	ULONG32 SessionId;
	ULONG32 UserAndGroupCount;
	ULONG32 RestrictedSidCount;
	ULONG32 VariableLength;
	ULONG32 DynamicCharged;
	ULONG32 DynamicAvailable;
	ULONG32 DefaultOwnerIndex;
	SID_AND_ATTRIBUTES* UserAndGroups;
	SID_AND_ATTRIBUTES* RestrictedSids;
	PVOID PrimaryGroup;
	PULONG32 DynamicPart;
	ACL* DefaultDacl;
	TOKEN_TYPE TokenType;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	ULONG32 TokenFlags;
	UCHAR TokenInUse;
	ULONG32 IntegrityLevelIndex;
	ULONG32 MandatoryPolicy;
	struct  _SEP_LOGON_SESSION_REFERENCES* LogonSession;
	LUID OriginatingLogonSession;
	SID_AND_ATTRIBUTES_HASH SidHash;
	SID_AND_ATTRIBUTES_HASH RestrictedSidHash;
	struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes;
	ULONG64 VariablePart;
}TOKEN,*PTOKEN;

typedef struct _KGDTENTRY                 // 3 elements, 0x8 bytes (sizeof)  
{
	union
	{
		/*0x000*/     UINT16       LimitLow;
		/*0x002*/     UINT16       BaseLow;
		union                                 // 2 elements, 0x4 bytes (sizeof)  
		{
			struct                            // 4 elements, 0x4 bytes (sizeof)  
			{
				/*0x004*/             UINT8        BaseMid;
				/*0x005*/             UINT8        Flags1;
				/*0x006*/             UINT8        Flags2;
				/*0x007*/             UINT8        BaseHi;
			}Bytes;
			struct                            // 10 elements, 0x4 bytes (sizeof) 
			{
				/*0x004*/             ULONG32      BaseMid : 8;     // 0 BitPosition                   
				/*0x004*/             ULONG32      Type : 5;        // 8 BitPosition                   
				/*0x004*/             ULONG32      Dpl : 2;         // 13 BitPosition                  
				/*0x004*/             ULONG32      Pres : 1;        // 15 BitPosition                  
				/*0x004*/             ULONG32      LimitHi : 4;     // 16 BitPosition                  
				/*0x004*/             ULONG32      Sys : 1;         // 20 BitPosition                  
				/*0x004*/             ULONG32      Reserved_0 : 1;  // 21 BitPosition                  
				/*0x004*/             ULONG32      Default_Big : 1; // 22 BitPosition                  
				/*0x004*/             ULONG32      Granularity : 1; // 23 BitPosition                  
				/*0x004*/             ULONG32      BaseHi : 8;      // 24 BitPosition                  
			}Bits;
		}HighWord;

		UINT64 Alignment;
	};

	ULONG32 BaseUpper;
	ULONG32 MustBeZero;
}KGDTENTRY, * PKGDTENTRY;

///////////////////////////////////////////////////////////ETHREAD

typedef struct _KAPC_STATE_S             // 5 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY ApcListHead[2];
	/*0x010*/     struct _KPROCESS_S* Process;
	/*0x014*/     UINT8        KernelApcInProgress;
	/*0x015*/     UINT8        KernelApcPending;
	/*0x016*/     UINT8        UserApcPending;
	/*0x017*/     UINT8        _PADDING0_[0x1];
}KAPC_STATE_S, * PKAPC_STATE_S;

typedef struct _GDI_TEB_BATCH // 3 elements, 0x4E0 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Offset;
	/*0x004*/     ULONG_PTR      HDC;
	/*0x008*/     ULONG32      Buffer[310];
}GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB                                                  // 99 elements, 0xFE4 bytes (sizeof) 
{
	/*0x000*/     struct _NT_TIB NtTib;                                            // 8 elements, 0x1C bytes (sizeof)   
	/*0x01C*/     VOID* EnvironmentPointer;
	/*0x020*/     struct _CLIENT_ID ClientId;                                      // 2 elements, 0x8 bytes (sizeof)    
	/*0x028*/     VOID* ActiveRpcHandle;
	/*0x02C*/     VOID* ThreadLocalStoragePointer;
	/*0x030*/     PEB* ProcessEnvironmentBlock;
	/*0x034*/     ULONG32      LastErrorValue;
	/*0x038*/     ULONG32      CountOfOwnedCriticalSections;
	/*0x03C*/     VOID* CsrClientThread;
	/*0x040*/     VOID* Win32ThreadInfo;
	/*0x044*/     ULONG32      User32Reserved[26];
	/*0x0AC*/     ULONG32      UserReserved[5];
	/*0x0C0*/     VOID* WOW32Reserved;
	/*0x0C4*/     ULONG32      CurrentLocale;
	/*0x0C8*/     ULONG32      FpSoftwareStatusRegister;
	/*0x0CC*/     VOID* SystemReserved1[54];
	/*0x1A4*/     LONG32       ExceptionCode;
	/*0x1A8*/     VOID* ActivationContextStackPointer;
	/*0x1AC*/     UINT8        SpareBytes[24];
	/*0x1D0*/     ULONG32      TxFsContext;
	/*0x1D4*/     struct _GDI_TEB_BATCH GdiTebBatch;                               // 3 elements, 0x4E0 bytes (sizeof)  
	/*0x6B4*/     struct _CLIENT_ID RealClientId;                                  // 2 elements, 0x8 bytes (sizeof)    
	/*0x6BC*/     VOID* GdiCachedProcessHandle;
	/*0x6C0*/     ULONG32      GdiClientPID;
	/*0x6C4*/     ULONG32      GdiClientTID;
	/*0x6C8*/     VOID* GdiThreadLocalInfo;
	/*0x6CC*/     ULONG_PTR      Win32ClientInfo[62];
	/*0x7C4*/     VOID* glDispatchTable[233];
	/*0xB68*/     ULONG_PTR      glReserved1[29];
	/*0xBDC*/     VOID* glReserved2;
	/*0xBE0*/     VOID* glSectionInfo;
	/*0xBE4*/     VOID* glSection;
	/*0xBE8*/     VOID* glTable;
	/*0xBEC*/     VOID* glCurrentRC;
	/*0xBF0*/     VOID* glContext;
	/*0xBF4*/     ULONG32      LastStatusValue;
	/*0xBF8*/     struct _UNICODE_STRING StaticUnicodeString;                      // 3 elements, 0x8 bytes (sizeof)    
	/*0xC00*/     WCHAR        StaticUnicodeBuffer[261];
	/*0xE0C*/     VOID* DeallocationStack;
	/*0xE10*/     VOID* TlsSlots[64];
	/*0xF10*/     struct _LIST_ENTRY TlsLinks;                                     // 2 elements, 0x8 bytes (sizeof)    
	/*0xF18*/     VOID* Vdm;
	/*0xF1C*/     VOID* ReservedForNtRpc;
	/*0xF20*/     VOID* DbgSsReserved[2];
	/*0xF28*/     ULONG32      HardErrorMode;
	/*0xF2C*/     VOID* Instrumentation[11];
	/*0xF50*/     struct _GUID ActivityId;                                         // 4 elements, 0x10 bytes (sizeof)   
	/*0xF60*/     VOID* SubProcessTag;
	/*0xF64*/     VOID* EtwLocalData;
	/*0xF68*/     VOID* EtwTraceData;
	/*0xF6C*/     VOID* WinSockData;
	/*0xF70*/     ULONG32      GdiBatchCount;
	union                                                            // 3 elements, 0x4 bytes (sizeof)    
	{
		/*0xF74*/         struct _PROCESSOR_NUMBER CurrentIdealProcessor;              // 3 elements, 0x4 bytes (sizeof)    
		/*0xF74*/         ULONG32      IdealProcessorValue;
		struct                                                       // 4 elements, 0x4 bytes (sizeof)    
		{
			/*0xF74*/             UINT8        ReservedPad0;
			/*0xF75*/             UINT8        ReservedPad1;
			/*0xF76*/             UINT8        ReservedPad2;
			/*0xF77*/             UINT8        IdealProcessor;
		};
	};
	/*0xF78*/     ULONG32      GuaranteedStackBytes;
	/*0xF7C*/     VOID* ReservedForPerf;
	/*0xF80*/     VOID* ReservedForOle;
	/*0xF84*/     ULONG32      WaitingOnLoaderLock;
	/*0xF88*/     VOID* SavedPriorityState;
	/*0xF8C*/     ULONG_PTR     SoftPatchPtr1;
	/*0xF90*/     VOID* ThreadPoolData;
	/*0xF94*/     VOID** TlsExpansionSlots;
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
	/*0xF98*/     ULONG32      MuiGeneration;
	/*0xF9C*/     ULONG32      IsImpersonating;
	/*0xFA0*/     VOID* NlsCache;
	/*0xFA4*/     VOID* pShimData;
	/*0xFA8*/     ULONG32      HeapVirtualAffinity;
	/*0xFAC*/     VOID* CurrentTransactionHandle;
	/*0xFB0*/     VOID* ActiveFrame;
	/*0xFB4*/     VOID* FlsData;
	/*0xFB8*/     VOID* PreferredLanguages;
	/*0xFBC*/     VOID* UserPrefLanguages;
	/*0xFC0*/     VOID* MergedPrefLanguages;
	/*0xFC4*/     ULONG32      MuiImpersonation;
	union                                                            // 2 elements, 0x2 bytes (sizeof)    
	{
		/*0xFC8*/         UINT16       CrossTebFlags;
		/*0xFC8*/         UINT16       SpareCrossTebBits : 16;                         // 0 BitPosition                     
	};
	union                                                            // 2 elements, 0x2 bytes (sizeof)    
	{
		/*0xFCA*/         UINT16       SameTebFlags;
		struct                                                       // 12 elements, 0x2 bytes (sizeof)   
		{
			/*0xFCA*/             UINT16       SafeThunkCall : 1;                          // 0 BitPosition                     
			/*0xFCA*/             UINT16       InDebugPrint : 1;                           // 1 BitPosition                     
			/*0xFCA*/             UINT16       HasFiberData : 1;                           // 2 BitPosition                     
			/*0xFCA*/             UINT16       SkipThreadAttach : 1;                       // 3 BitPosition                     
			/*0xFCA*/             UINT16       WerInShipAssertCode : 1;                    // 4 BitPosition                     
			/*0xFCA*/             UINT16       RanProcessInit : 1;                         // 5 BitPosition                     
			/*0xFCA*/             UINT16       ClonedThread : 1;                           // 6 BitPosition                     
			/*0xFCA*/             UINT16       SuppressDebugMsg : 1;                       // 7 BitPosition                     
			/*0xFCA*/             UINT16       DisableUserStackWalk : 1;                   // 8 BitPosition                     
			/*0xFCA*/             UINT16       RtlExceptionAttached : 1;                   // 9 BitPosition                     
			/*0xFCA*/             UINT16       InitialThread : 1;                          // 10 BitPosition                    
			/*0xFCA*/             UINT16       SpareSameTebBits : 5;                       // 11 BitPosition                    
		};
	};
	/*0xFCC*/     VOID* TxnScopeEnterCallback;
	/*0xFD0*/     VOID* TxnScopeExitCallback;
	/*0xFD4*/     VOID* TxnScopeContext;
	/*0xFD8*/     ULONG32      LockCount;
	/*0xFDC*/     ULONG32      SpareUlong0;
	/*0xFE0*/     VOID* ResourceRetValue;
}TEB, * PTEB;

//调试对象
typedef struct _DEBUG_OBJECT
{
	KEVENT EventsPresent;
	FAST_MUTEX Mutex;
	LIST_ENTRY EventList;
	union
	{
		ULONG Flags;
		struct
		{
			UCHAR DebuggerInactive : 1;
			UCHAR KillProcessOnExit : 1;
		};
	};
} DEBUG_OBJECT, * PDEBUG_OBJECT;


//异常消息
typedef struct _DBGKM_EXCEPTION {
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, * PDBGKM_EXCEPTION;

//创建线程消息
typedef struct {
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, * PDBGKM_CREATE_THREAD;

//创建进程消息
typedef struct _DBGKM_CREATE_PROCESS {
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, * PDBGKM_CREATE_PROCESS;

//退出线程消息
typedef struct _DBGKM_EXIT_THREAD {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, * PDBGKM_EXIT_THREAD;

//退出进程消息
typedef struct _DBGKM_EXIT_PROCESS {
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, * PDBGKM_EXIT_PROCESS;

//加载模块消息
typedef struct _DBGKM_LOAD_DLL {
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, * PDBGKM_LOAD_DLL;

//卸载模块消息
typedef struct _DBGKM_UNLOAD_DLL {
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, * PDBGKM_UNLOAD_DLL;

//PORT_MESSAGE结构
typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG32 MessageId;
	union
	{
		ULONGLONG ClientViewSize;
		ULONG32 CallbackId;
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

//
// Debug Message API Number
//


typedef enum  _DBGKM_APINUMBER
{
	DbgKmExceptionApi = 0,
	DbgKmCreateThreadApi = 1,
	DbgKmCreateProcessApi = 2,
	DbgKmExitThreadApi = 3,
	DbgKmExitProcessApi = 4,
	DbgKmLoadDllApi = 5,
	DbgKmUnloadDllApi = 6,
	DbgKmErrorReportApi = 7,
	DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;


//
// LPC Debug Message
//
typedef struct _DBGKM_MSG
{
	PORT_MESSAGE h;
	DBGKM_APINUMBER ApiNumber;
	NTSTATUS ReturnedStatus;
	union
	{
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcess;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	};
	UCHAR unknow[0x40];
}DBGKM_MSG, * PDBGKM_MSG;


//消息结构
typedef struct _DBGKM_APIMSG {
	PORT_MESSAGE h;								//+0x0
	DBGKM_APINUMBER ApiNumber;					//+0x28
	NTSTATUS ReturnedStatus;					//+0x1c
	union {
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} u;										//0x20

	//以上这个部分占了0x74个大小，而windows7此结构的大小是A8，下面应该是输入异常相关的信息，为此，我们要凑够0xA8个大小，不然处理异常的时候会蓝屏掉
	UCHAR	ExceptPart[0x40];
} DBGKM_APIMSG, * PDBGKM_APIMSG;


//调试事件
typedef struct _DEBUG_EVENT
{
	LIST_ENTRY EventList;	//+0x0			
	KEVENT ContinueEvent;	//+0x10		
	CLIENT_ID ClientId;		//0x28		
	PEPROCESS_S Process;		//0x38 
	PETHREAD_S Thread;		//0x40			
	NTSTATUS Status;		//0x48	
	ULONG Flags;			//0x4c			
	PETHREAD BackoutThread;	//0x50		
	DBGKM_APIMSG ApiMsg;	//0x58	
} DEBUG_EVENT, * PDEBUG_EVENT;

#ifndef _DBG_STATE_
#define _DBG_STATE_
//
// Debug States
//
typedef enum _DBG_STATE
{
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, * PDBG_STATE;

#endif // !_DBG_STATE_


typedef struct _DBGUI_CREATE_THREAD {
	HANDLE HandleToThread;
	DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, * PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS {
	HANDLE HandleToProcess;
	HANDLE HandleToThread;
	DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, * PDBGUI_CREATE_PROCESS;

//typedef struct _DBGUI_WAIT_STATE_CHANGE {
//	DBG_STATE NewState;
//	CLIENT_ID AppClientId;
//	union {
//		DBGKM_EXCEPTION Exception;
//		DBGUI_CREATE_THREAD CreateThread;
//		DBGUI_CREATE_PROCESS CreateProcessInfo;
//		DBGKM_EXIT_THREAD ExitThread;
//		DBGKM_EXIT_PROCESS ExitProcess;
//		DBGKM_LOAD_DLL LoadDll;
//		DBGKM_UNLOAD_DLL UnloadDll;
//	} StateInfo;
//} DBGUI_WAIT_STATE_CHANGE, * PDBGUI_WAIT_STATE_CHANGE;

//
// User-Mode Debug State Change Structure
//
typedef struct _DBGUI_WAIT_STATE_CHANGE
{
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union
	{
		struct
		{
			HANDLE HandleToThread;
			DBGKM_CREATE_THREAD NewThread;
		} CreateThread;
		struct
		{
			HANDLE HandleToProcess;
			HANDLE HandleToThread;
			DBGKM_CREATE_PROCESS NewProcess;
		} CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_EXCEPTION Exception;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, * PDBGUI_WAIT_STATE_CHANGE;

typedef struct _IMAGE_COMMITMENT
{
	struct _CONTROL_AREA* ControlArea;
	//..........
}IMAGE_COMMITMENT, * PIMAGE_COMMITMENT;

typedef struct _MMSECTION_FLAGS               // 27 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     UINT32       BeingDeleted : 1;            // 0 BitPosition                   
	/*0x000*/     UINT32       BeingCreated : 1;            // 1 BitPosition                   
	/*0x000*/     UINT32       BeingPurged : 1;             // 2 BitPosition                   
	/*0x000*/     UINT32       NoModifiedWriting : 1;       // 3 BitPosition                   
	/*0x000*/     UINT32       FailAllIo : 1;               // 4 BitPosition                   
	/*0x000*/     UINT32       Image : 1;                   // 5 BitPosition                   
	/*0x000*/     UINT32       Based : 1;                   // 6 BitPosition                   
	/*0x000*/     UINT32       File : 1;                    // 7 BitPosition                   
	/*0x000*/     UINT32       Networked : 1;               // 8 BitPosition                   
	/*0x000*/     UINT32       Rom : 1;                     // 9 BitPosition                   
	/*0x000*/     UINT32       PhysicalMemory : 1;          // 10 BitPosition                  
	/*0x000*/     UINT32       CopyOnWrite : 1;             // 11 BitPosition                  
	/*0x000*/     UINT32       Reserve : 1;                 // 12 BitPosition                  
	/*0x000*/     UINT32       Commit : 1;                  // 13 BitPosition                  
	/*0x000*/     UINT32       Accessed : 1;                // 14 BitPosition                  
	/*0x000*/     UINT32       WasPurged : 1;               // 15 BitPosition                  
	/*0x000*/     UINT32       UserReference : 1;           // 16 BitPosition                  
	/*0x000*/     UINT32       GlobalMemory : 1;            // 17 BitPosition                  
	/*0x000*/     UINT32       DeleteOnClose : 1;           // 18 BitPosition                  
	/*0x000*/     UINT32       FilePointerNull : 1;         // 19 BitPosition                  
	/*0x000*/     UINT32       GlobalOnlyPerSession : 1;    // 20 BitPosition                  
	/*0x000*/     UINT32       SetMappedFileIoComplete : 1; // 21 BitPosition                  
	/*0x000*/     UINT32       CollidedFlush : 1;           // 22 BitPosition                  
	/*0x000*/     UINT32       NoChange : 1;                // 23 BitPosition                  
	/*0x000*/     UINT32       Spare : 1;                   // 24 BitPosition                  
	/*0x000*/     UINT32       UserWritable : 1;            // 25 BitPosition                  
	/*0x000*/     UINT32       PreferredNode : 6;           // 26 BitPosition                  
}MMSECTION_FLAGS, * PMMSECTION_FLAGS;

typedef struct _CONTROL_AREA                                      // 16 elements, 0x50 bytes (sizeof) 
{
	/*0x000*/     void* Segment;
	/*0x004*/     struct _LIST_ENTRY DereferenceList;                           // 2 elements, 0x8 bytes (sizeof)   
	/*0x00C*/     ULONG64      NumberOfSectionReferences;
	/*0x010*/     ULONG64      NumberOfPfnReferences;
	/*0x014*/     ULONG64      NumberOfMappedViews;
	/*0x018*/     ULONG64      NumberOfUserReferences;
	union                                                         // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x01C*/         ULONG32      LongFlags;
		/*0x01C*/         ULONG32	   Flags;                            // 27 elements, 0x4 bytes (sizeof)  
	}u;
	/*0x020*/     ULONG32      FlushInProgressCount;
	/*0x024*/     struct _EX_FAST_REF FilePointer;                              // 3 elements, 0x4 bytes (sizeof)   
	/*0x028*/     LONG32       ControlAreaLock;
	union                                                         // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x02C*/         ULONG32      ModifiedWriteCount;
		/*0x02C*/         ULONG32      StartingFrame;
	};
	/*0x030*/     void* WaitingForDeletion;
	union                                                         // 1 elements, 0xC bytes (sizeof)   
	{
		struct                                                    // 9 elements, 0xC bytes (sizeof)   
		{
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x034*/                 ULONG32      NumberOfSystemCacheViews;
				/*0x034*/                 ULONG32      ImageRelocationStartBit;
			};
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x038*/                 LONG32       WritableUserReferences;
				struct                                            // 4 elements, 0x4 bytes (sizeof)   
				{
					/*0x038*/                     ULONG32      ImageRelocationSizeIn64k : 16;   // 0 BitPosition                    
					/*0x038*/                     ULONG32      Unused : 14;                     // 16 BitPosition                   
					/*0x038*/                     ULONG32      BitMap64 : 1;                    // 30 BitPosition                   
					/*0x038*/                     ULONG32      ImageActive : 1;                 // 31 BitPosition                   
				};
			};
			union                                                 // 2 elements, 0x4 bytes (sizeof)   
			{
				/*0x03C*/                 void* SubsectionRoot;
				/*0x03C*/                 void* SeImageStub;
			};
		}e2;
	}u2;
	/*0x040*/     INT64        LockedPages;
	/*0x048*/     struct _LIST_ENTRY ViewList;                                  // 2 elements, 0x8 bytes (sizeof)   
}CONTROL_AREA, * PCONTROL_AREA;

typedef struct _SUBSECTION
{
	CONTROL_AREA* ControlArea;
	PVOID SubsectionBase;
	PVOID NextSubsection;
	ULONG32 PtesInSubsection;
	ULONG32 UnusedPtes;
	PVOID GlobalPerSessionHead;
	union
	{
		ULONG32 x1;
	}u;
	ULONG32 StartingSector;
	ULONG32 NumberOfFullSectors;
}SUBSECTION, * PSUBSECTION;

typedef struct _SEGMENT_OBJECT                     // 9 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     VOID* BaseAddress;
	/*0x004*/     ULONG32      TotalNumberOfPtes;
	/*0x008*/     union _LARGE_INTEGER SizeOfSegment;            // 4 elements, 0x8 bytes (sizeof)  
	/*0x010*/     ULONG32      NonExtendedPtes;
	/*0x014*/     ULONG32 ImageCommitment;		//这个成员经过分析我们重新定义一下                                                   
	/*0x018*/     struct _CONTROL_AREA* ControlArea;
	/*0x01C*/     PSUBSECTION Subsection;
	/*0x020*/     struct _MMSECTION_FLAGS*	MmSectionFlags;
	/*0x024*/     void* MmSubSectionFlags;
}SEGMENT_OBJECT, * PSEGMENT_OBJECT;


//模块相关
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

typedef struct _tagSysModuleList {          //模块链结构
	ULONG ulCount;
	SYSTEM_MODULE_INFORMATION_ENTRY smi[1];
} MODULES, * PMODULES;


//句柄相关
typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		PVOID		Object;
		UINT32		ObAttributes;
		PVOID		InfoTable;
		UINT_PTR		Value;
	};
	union
	{
		union
		{
			UINT32 GrantedAccess;
			struct
			{
				UINT16 GrantedAccessIndex;
				UINT16 CreatorBackTraceIndex;
			};
		};
		UINT32 NextFreeTableEntry;
	};
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;//Win7 x64/x86

typedef struct _HANDLE_TABLE
{
	UINT_PTR			TableCode;			     // +00	4	+00	 8
	PEPROCESS			QuotaProcess;			 // +04	4	+08	 8
	HANDLE				UniqueProcessId;		 // +08	4	+10	 8
	PVOID				HandleLock;			     // +0c	4	+18	 8
	LIST_ENTRY			HandleTableList;		 // +10	4	+20  16
	PVOID				HandleContentionEvent;	 // +18	8	+30  8
	PVOID				DebugInfo;			     // +1c	4	+38  8
	INT32				ExtraInfoPages;		     // +20	4	+40  4
	UINT32				Flags;				     // +24	4	+44  4
	UINT32				FirstFreeHandle;		 // +28	4	+48  4
#ifdef _WIN64
	UINT32				Padding;				 // +4c  4
#endif // _WIN64
	PHANDLE_TABLE_ENTRY	LastFreeHandleEntry;	 // +2c	4	+50  8
	UINT32				HandleCount;			 // +30	4	+58  4
	UINT32				NextHandleNeedingPool;	 // +34	4	+5c  4
	UINT32				HandleCountHighWatermark;// +38	4	+60  4
} HANDLE_TABLE, * PHANDLE_TABLE;//Win7 x64/x86

//SSDT
typedef struct _SERVICE_DESCIPTOR_TABLE {
	PULONG ServiceTableBase;
	PVOID ServiceCounterTableBase; //仅适用于checked build版本
	ULONG_PTR NumberOfServices;
	PVOID ParamTableBase;
} ServiceDescriptorTableEntry_t, * PServiceDescriptorTableEntry_t;

typedef struct _OBJECT_TYPE_INITIALIZER                                                                                                                                      // 25 elements, 0x70 bytes (sizeof)
{
	/*0x000*/     UINT16       Length;
	union                                                                                                                                                                       // 2 elements, 0x1 bytes (sizeof)
	{
		/*0x002*/         UINT8        ObjectTypeFlags;
		struct                                                                                                                                                                  // 7 elements, 0x1 bytes (sizeof)
		{
			/*0x002*/             UINT8        CaseInsensitive : 1;                                                                                                                                   // 0 BitPosition
			/*0x002*/             UINT8        UnnamedObjectsOnly : 1;                                                                                                                                // 1 BitPosition
			/*0x002*/             UINT8        UseDefaultObject : 1;                                                                                                                                  // 2 BitPosition
			/*0x002*/             UINT8        SecurityRequired : 1;                                                                                                                                  // 3 BitPosition
			/*0x002*/             UINT8        MaintainHandleCount : 1;                                                                                                                               // 4 BitPosition
			/*0x002*/             UINT8        MaintainTypeList : 1;                                                                                                                                  // 5 BitPosition
			/*0x002*/             UINT8        SupportsObjectCallbacks : 1;                                                                                                                           // 6 BitPosition
		};
	};
	/*0x004*/     ULONG32      ObjectTypeCode;
	/*0x008*/     ULONG32      InvalidAttributes;
	/*0x00C*/     struct _GENERIC_MAPPING GenericMapping;                                                                                                                                     // 4 elements, 0x10 bytes (sizeof)
	/*0x01C*/     ULONG32      ValidAccessMask;
	/*0x020*/     ULONG32      RetainAccess;
	/*0x024*/     enum _POOL_TYPE PoolType;
	/*0x028*/     ULONG32      DefaultPagedPoolCharge;
	/*0x02C*/     ULONG32      DefaultNonPagedPoolCharge;
	/*0x030*/     PVOID DumpProcedure;
	/*0x038*/     PVOID OpenProcedure;
	/*0x040*/     PVOID CloseProcedure;
	/*0x048*/     PVOID DeleteProcedure;
	/*0x050*/     PVOID ParseProcedure;
	/*0x058*/     PVOID SecurityProcedure;
	/*0x060*/     PVOID QueryNameProcedure;
	/*0x068*/     PVOID OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE                   // 12 elements, 0xD0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)
	/*0x020*/     VOID* DefaultObject;
	/*0x028*/     UINT8        Index;
	/*0x02C*/     ULONG32      TotalNumberOfObjects;
	/*0x030*/     ULONG32      TotalNumberOfHandles;
	/*0x034*/     ULONG32      HighWaterNumberOfObjects;
	/*0x038*/     ULONG32      HighWaterNumberOfHandles;
	/*0x040*/     struct _OBJECT_TYPE_INITIALIZER TypeInfo; // 25 elements, 0x70 bytes (sizeof)
	/*0x0B0*/     struct _EX_PUSH_LOCK TypeLock;            // 7 elements, 0x8 bytes (sizeof)
	/*0x0B8*/     ULONG32      Key;
	/*0x0C0*/     struct _LIST_ENTRY CallbackList;          // 2 elements, 0x10 bytes (sizeof)
}OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _OBJECT_TYPE_INITIALIZER_WIN7
{
	USHORT Length;
	USHORT ObjectTypeFlags;
	ULONG ObjectTypeCode;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG RetainAccess;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER_WIN7, * POBJECT_TYPE_INITIALIZER_WIN7;

typedef struct _OBJECT_TYPE_INITIALIZER_WIN10
{
	UINT16 Length;
	UINT16 ObjectTypeFlags;
	ULONG ObjectTypeCode;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG RetainAccess;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID OpenProcedureEx;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
	ULONG WaitObjectFlagMask;
	ULONG WaitObjectFlagOffset;
	ULONG WaitObjectPointerOffset;
} OBJECT_TYPE_INITIALIZER_WIN10, * POBJECT_TYPE_INITIALIZER_WIN10;


typedef struct _OBJECT_HEADER
{
	INT64 PointerCount;
	union
	{
		INT64 HandleCount;
		PVOID NextToFree;
	};

	EX_PUSH_LOCK Lock;
	UCHAR TypeIndex;
	UCHAR TraceFlags;
	UCHAR InfoMask;
	UCHAR Flags;
	union
	{
		struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};

	PVOID SecurityDescriptor;
}OBJECT_HEADER, * POBJECT_HEADER;


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // 10, not implemented
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q
	SystemVdmBopInformation, // 20, not implemented
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented
	SystemMirrorMemoryInformation, // 30, s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege)
	SystemPerformanceTraceInformation, // s
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // 40, s (requires SeDebugPrivilege)
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented
	SystemRangeStartInformation, // 50, q
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q
	SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q
	SystemComPlusPackage, // q; s
	SystemNumaAvailableMemory, // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation, // q
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s
	SystemObjectSecurityMode, // 70, q
	SystemWatchdogTimerHandler, // s (kernel-mode only)
	SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
	SystemFirmwareTableInformation, // not implemented
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q: SUPERFETCH_INFORMATION; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // 80, q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege)
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // 90, q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION
	SystemHypervisorInformation, // q; s (kernel-mode only)
	SystemVerifierInformationEx, // q; s
	SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
	SystemPrefetchPatchInformation, // not implemented
	SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // 100, q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION
	SystemNumaProximityNodeInformation, // q
	SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s
	SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation, // q; s // SmQueryStoreInformation
	SystemRegistryAppendString, // 110, s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
	SystemNativeBasicInformation, // not implemented
	SystemSpare1, // not implemented
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // 120, q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes)
	SystemNodeDistanceInformation, // q
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // since WIN8
	SystemBootGraphicsInformation,
	SystemScrubPhysicalMemoryInformation,
	SystemBadPageInformation,
	SystemProcessorProfileControlArea,
	SystemCombinePhysicalMemoryInformation, // 130
	SystemEntropyInterruptTimingCallback,
	SystemConsoleInformation,
	SystemPlatformBinaryInformation,
	SystemThrottleNotificationInformation,
	SystemHypervisorProcessorCountInformation,
	SystemDeviceDataInformation,
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation,
	SystemMemoryChannelInformation,
	SystemBootLogoInformation, // 140
	SystemProcessorPerformanceInformationEx, // since WINBLUE
	SystemSpare0,
	SystemSecureBootPolicyInformation,
	SystemPageFileInformationEx,
	SystemSecureBootInformation,
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation,
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx,
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation,
	SystemElamCertificateInformation,
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation,
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	MaxSystemInfoClass,
	SystemKernelDebuggerFlags = 163
} SYSTEM_INFORMATION_CLASS;


