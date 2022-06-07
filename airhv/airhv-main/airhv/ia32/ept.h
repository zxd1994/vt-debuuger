#pragma once
#include "invalidators.h"

#define MASK_EPT_PML1_OFFSET(_VAR_) ((unsigned __int64)_VAR_ & 0xFFFULL)
#define MASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)
#define MASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)
#define MASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)
#define MASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)
#define CPU_BASED_MONITOR_TRAP_FLAG 0x08000000

union __eptp
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 memory_type : 3; 
		unsigned __int64 page_walk_length : 3;
		unsigned __int64 dirty_and_aceess_enabled : 1;
		unsigned __int64 reserved1 : 5; 
		unsigned __int64 pml4_address : 36;
		unsigned __int64 reserved2 : 16;
	};
};


// See Table 28-1. 
union __ept_pml4e
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 read : 1; // bit 0
		unsigned __int64 write : 1; // bit 1
		unsigned __int64 execute : 1; // bit 2
		unsigned __int64 reserved1 : 5; // bit 7:3 (Must be Zero)
		unsigned __int64 accessed : 1; // bit 8
		unsigned __int64 ignored1 : 1; // bit 9
		unsigned __int64 execute_for_usermode : 1; // bit 10
		unsigned __int64 ignored2 : 1; // bit 11
		unsigned __int64 physical_address : 36; // bit (N-1):12 or Page-Frame-Number
		unsigned __int64 reserved2 : 4; // bit 51:N
		unsigned __int64 ignored3 : 12; // bit 63:52
	};
};

// See Table 28-3
union __ept_pdpte
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 read : 1; // bit 0
		unsigned __int64 write : 1; // bit 1
		unsigned __int64 execute : 1; // bit 2
		unsigned __int64 reserved1 : 5; // bit 7:3 (Must be Zero)
		unsigned __int64 accessed : 1; // bit 8
		unsigned __int64 ignored1 : 1; // bit 9
		unsigned __int64 execute_for_usermode : 1; // bit 10
		unsigned __int64 ignored2 : 1; // bit 11
		unsigned __int64 physical_address : 36; // bit (N-1):12 or Page-Frame-Number
		unsigned __int64 reserved2 : 4; // bit 51:N
		unsigned __int64 ignored3 : 12; // bit 63:52
	};
};

// See Table 28-5
union __ept_pde {
	unsigned __int64 all;
	struct
	{
		unsigned __int64 read : 1; // bit 0
		unsigned __int64 write : 1; // bit 1
		unsigned __int64 execute : 1; // bit 2
		unsigned __int64 reserved1 : 5; // bit 7:3 (Must be Zero)
		unsigned __int64 accessed : 1; // bit 8
		unsigned __int64 ignored1 : 1; // bit 9
		unsigned __int64 execute_for_usermode : 1; // bit 10
		unsigned __int64 ignored2 : 1; // bit 11
		unsigned __int64 physical_address : 36; // bit (N-1):12 or Page-Frame-Number
		unsigned __int64 reserved2 : 4; // bit 51:N
		unsigned __int64 ignored3 : 12; // bit 63:52
	}large_page;
	struct
	{
		unsigned __int64 read : 1;
		unsigned __int64 write : 1;
		unsigned __int64 execute : 1;
		unsigned __int64 memory_type : 3;
		unsigned __int64 ignore_pat : 1;
		unsigned __int64 large_page : 1;
		unsigned __int64 accessed : 1;
		unsigned __int64 dirty : 1;
		unsigned __int64 execute_for_usermode : 1;
		unsigned __int64 reserved1 : 10;
		unsigned __int64 physical_address : 27;
		unsigned __int64 reserved2 : 15;
		unsigned __int64 suppressve : 1;
	}page_directory_entry;
};

// See Table 28-6																	 
union __ept_pte {
	unsigned __int64 all;
	struct
	{
		unsigned __int64 read : 1; // bit 0											 
		unsigned __int64 write : 1; // bit 1										 
		unsigned __int64 execute : 1; // bit 2
		unsigned __int64 ept_memory_type : 3; // bit 5:3 (EPT Memory type)
		unsigned __int64 ignore_pat : 1; // bit 6
		unsigned __int64 ignored1 : 1; // bit 7
		unsigned __int64 accessed_flag : 1; // bit 8	
		unsigned __int64 dirty_flag : 1; // bit 9
		unsigned __int64 execute_for_usermode : 1; // bit 10
		unsigned __int64 ignored2 : 1; // bit 11
		unsigned __int64 physical_address : 36; // bit (N-1):12 or Page-Frame-Number
		unsigned __int64 reserved : 4; // bit 51:N
		unsigned __int64 ignored3 : 11; // bit 62:52
		unsigned __int64 suppress_ve : 1; // bit 63
	};
};

struct __ept_dynamic_split
{
	DECLSPEC_ALIGN(PAGE_SIZE) __ept_pte pml1[512];

	__ept_pde* entry;

	LIST_ENTRY dynamic_split_list;
};

struct __vmm_ept_page_table
{
	DECLSPEC_ALIGN(PAGE_SIZE) __ept_pml4e pml4[512];

	DECLSPEC_ALIGN(PAGE_SIZE) __ept_pdpte pml3[512];

	DECLSPEC_ALIGN(PAGE_SIZE) __ept_pde pml2[512][512];
};

struct __ept_hooked_function_info 
{
	//
	// Linked list entires for each function hook.
	//
	LIST_ENTRY hooked_function_list;

	//
	// Pointer to page with our hooked functions
	//
	unsigned __int8* fake_page_contents;

	//
	// Size of hook
	//
	unsigned __int64 hook_size;

	//
	// Virtual address of function
	//
	void* virtual_address;

	//
	// Address to first trampoline used to call original function
	//
	unsigned __int8* first_trampoline_address;

	//
	// Address of code cave which is used to jmp to our hooked function
	//
	void* second_trampoline_address;
};

struct __ept_hooked_page_info
{
	//
	// Page with our hooked functions
	//
	DECLSPEC_ALIGN(PAGE_SIZE) unsigned __int8 fake_page_contents[PAGE_SIZE];

	//
	// Linked list entires for each page hook.
	//
	LIST_ENTRY hooked_page_list;

	//
	// Linked list entries for each function hook
	//
	LIST_ENTRY hooked_functions_list;

	//
	// The base address of the page. Used to find this structure in the list of page hooks
	//
	unsigned __int64 pfn_of_hooked_page;

	//
	// The base address of the page with fake contents. Used to swap page with fake contents
	//
	unsigned __int64 pfn_of_fake_page_contents;

	//
	// The page entry in the page tables that this page is targetting.
	//
	__ept_pte* entry_address;

	//
	// The original page entry
	// 
	__ept_pte original_entry;

	//
	// The changed page entry
	//
	__ept_pte changed_entry;
};

union __ept_violation
{
	unsigned __int64 all;
	struct
	{
		/**
		 * [Bit 0] Set if the access causing the EPT violation was a data read.
		 */
		unsigned __int64 read_access : 1;

		/**
		 * [Bit 1] Set if the access causing the EPT violation was a data write.
		 */
		unsigned __int64 write_access : 1;

		/**
		 * [Bit 2] Set if the access causing the EPT violation was an instruction fetch.
		 */
		unsigned __int64 execute_access : 1;

		/**
		 * [Bit 3] The logical-AND of bit 0 in the EPT paging-structure entries used to translate the guest-physical address of the
		 * access causing the EPT violation (indicates whether the guest-physical address was readable).
		 */
		unsigned __int64 ept_readable : 1;

		/**
		 * [Bit 4] The logical-AND of bit 1 in the EPT paging-structure entries used to translate the guest-physical address of the
		 * access causing the EPT violation (indicates whether the guest-physical address was writeable).
		 */
		unsigned __int64 ept_writeable : 1;

		/**
		 * [Bit 5] The logical-AND of bit 2 in the EPT paging-structure entries used to translate the guest-physical address of the
		 * access causing the EPT violation.
		 * If the "mode-based execute control for EPT" VM-execution control is 0, this indicates whether the guest-physical address
		 * was executable. If that control is 1, this indicates whether the guest-physical address was executable for
		 * supervisor-mode linear addresses.
		 */
		unsigned __int64 ept_executable : 1;

		/**
		 * [Bit 6] If the "mode-based execute control" VM-execution control is 0, the value of this bit is undefined. If that
		 * control is 1, this bit is the logical-AND of bit 10 in the EPT paging-structures entries used to translate the
		 * guest-physical address of the access causing the EPT violation. In this case, it indicates whether the guest-physical
		 * address was executable for user-mode linear addresses.
		 */
		unsigned __int64 ept_executable_for_usermode : 1;

		/**
		 * [Bit 7] Set if the guest linear-address field is valid. The guest linear-address field is valid for all EPT violations
		 * except those resulting from an attempt to load the guest PDPTEs as part of the execution of the MOV CR instruction.
		 */
		unsigned __int64 valid_guest_linear_address : 1;

		/**
		 * [Bit 8] If bit 7 is 1:
		 * - Set if the access causing the EPT violation is to a guest-physical address that is the translation of a linear
		 * address.
		 * - Clear if the access causing the EPT violation is to a paging-structure entry as part of a page walk or the update of
		 * an accessed or dirty bit.
		 * Reserved if bit 7 is 0 (cleared to 0).
		 */
		unsigned __int64 caused_by_translation : 1;

		/**
		 * [Bit 9] This bit is 0 if the linear address is a supervisor-mode linear address and 1 if it is a user-mode linear
		 * address. Otherwise, this bit is undefined.
		 *
		 * @remarks If bit 7 is 1, bit 8 is 1, and the processor supports advanced VM-exit information for EPT violations. (If
		 *          CR0.PG = 0, the translation of every linear address is a user-mode linear address and thus this bit will be 1.)
		 */
		unsigned __int64 usermode_linear_address : 1;

		/**
		 * [Bit 10] This bit is 0 if paging translates the linear address to a read-only page and 1 if it translates to a
		 * read/write page. Otherwise, this bit is undefined
		 *
		 * @remarks If bit 7 is 1, bit 8 is 1, and the processor supports advanced VM-exit information for EPT violations. (If
		 *          CR0.PG = 0, every linear address is read/write and thus this bit will be 1.)
		 */
		unsigned __int64 readable_writable_page : 1;

		/**
		 * [Bit 11] This bit is 0 if paging translates the linear address to an executable page and 1 if it translates to an
		 * execute-disable page. Otherwise, this bit is undefined.
		 *
		 * @remarks If bit 7 is 1, bit 8 is 1, and the processor supports advanced VM-exit information for EPT violations. (If
		 *          CR0.PG = 0, CR4.PAE = 0, or MSR_IA32_EFER.NXE = 0, every linear address is executable and thus this bit will be 0.)
		 */
		unsigned __int64 execute_disable_page : 1;

		/**
		 * [Bit 12] NMI unblocking due to IRET.
		 */
		unsigned __int64 nmi_unblocking : 1;
		unsigned __int64 reserved1 : 51;
	};
};

namespace ept
{
	/// <summary>
	/// Build mtrr map to track physical memory type
	/// </summary>
	void build_mtrr_map();

	/// <summary>
	/// Initialize ept structure
	/// </summary>
	/// <returns></returns>
	bool initialize();

	/// <summary>
	/// Change page physcial frame number and invalidate tlb
	/// </summary>
	/// <param name="entry_address"> Pointer to page table entry which we want to change </param>
	/// <param name="entry_value"> Pointer to page table entry which we want use to change </param>
	/// <param name="invalidate"> If true invalidates tlb after changning pte value </param>
	/// <param name="invalidation_type"> Specifiy if we want to invalidate single context or all contexts  </param>
	void swap_pml1_and_invalidate_tlb(__ept_pte* entry_address, __ept_pte entry_value, invept_type invalidation_type);

	/// <summary>
	/// Unhook all functions and invalidate tlb
	/// </summary>
	void unhook_all_functions();

	/// <summary>
	/// Perfrom a hook
	/// </summary>
	/// <param name="target_address" > Address of function which we want to hook </param>
	/// <param name="hook_function"> Address of hooked version of function which we are hooking </param>
	/// <param name="(Optional) trampoline"> Address of codecave which is located in 2gb range of target function (Use only if you need smaller trampoline)</param>
	/// <param name="origin_function"> Address used to call original function </param>
	/// <returns></returns>
	bool hook_function(void* target_address, void* hook_function, void* trampoline, void** origin_function);

	/// <summary>
	/// Unhook single function
	/// </summary>
	/// <param name="virtual_address"></param>
	/// <returns></returns>
	bool unhook_function(unsigned __int64 virtual_address);

	/// <summary>
	/// Swap physcial pages and invalidate tlb
	/// </summary>
	/// <param name="entry_address"> Pointer to page table entry which we want to change </param>
	/// <param name="entry_value"> Pointer to page table entry which we want use to change </param>
	void swap_pml1(__ept_pte* entry_address, __ept_pte entry_value);

	/// <summary>
	/// Split pml2 into 512 pml1 entries (From one 2MB page to 512 4KB pages)
	/// </summary>
	/// <param name="pre_allocated_buffer"> Pre allocated buffer for split </param>
	/// <param name="physical_address"></param>
	/// <returns> status </returns>
	bool split_pml2(void* pre_allocated_buffer, unsigned __int64 physical_address);
}