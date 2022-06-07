#pragma warning( disable : 4201 4244)
#include <ntddk.h>
#include <intrin.h>
#include <stdlib.h>
#include "common.h"
#include "ia32\msr.h"
#include "ia32\vmcs_encodings.h"
#include "ia32\ept.h"
#include "log.h"
#include "hypervisor_routines.h"
#include "ia32\mtrr.h"
#include "allocators.h"

namespace ept
{
	/// <summary>
	/// Build mtrr map to track physical memory type
	/// </summary>
	void build_mtrr_map()
	{
		__mtrr_cap_reg mtrr_cap = { 0 };
		__mtrr_physbase_reg current_phys_base = { 0 };
		__mtrr_physmask_reg current_phys_mask = { 0 };
		__mtrr_def_type mtrr_def_type = { 0 };
		__mtrr_range_descriptor* descriptor;

		//
		// The memory type range registers (MTRRs) provide a mechanism for associating the memory types (see Section
		// 11.3, “Methods of Caching Available”) with physical - address ranges in system memory.They allow the processor to
		// optimize operations for different types of memory such as RAM, ROM, frame - buffer memory, and memory - mapped
		// I/O devices.They also simplify system hardware design by eliminating the memory control pins used for this func -
		// tion on earlier IA - 32 processors and the external logic needed to drive them.
		//

		mtrr_cap.all = __readmsr(IA32_MTRRCAP);
		mtrr_def_type.all = __readmsr(IA32_MTRR_DEF_TYPE);

		if (mtrr_def_type.mtrr_enabled == false)
		{
			g_vmm_context->ept_state->default_memory_type = MEMORY_TYPE_UNCACHEABLE;
			return;
		}

		g_vmm_context->ept_state->default_memory_type = mtrr_def_type.memory_type;

		if (mtrr_cap.smrr_support == true)
		{
			current_phys_base.all = __readmsr(IA32_SMRR_PHYSBASE);
			current_phys_mask.all = __readmsr(IA32_SMRR_PHYSMASK);

			if (current_phys_mask.valid && current_phys_base.type != mtrr_def_type.memory_type)
			{
				descriptor = &g_vmm_context->ept_state->memory_range[g_vmm_context->ept_state->enabled_memory_ranges++];
				descriptor->physcial_base_address = current_phys_base.physbase << PAGE_SHIFT;

				unsigned long bits_in_mask = 0;
				_BitScanForward64(&bits_in_mask, current_phys_mask.physmask << PAGE_SHIFT);

				descriptor->physcial_end_address = descriptor->physcial_base_address + ((1ULL << bits_in_mask) - 1ULL);
				descriptor->memory_type = (unsigned __int8)current_phys_base.type;
				descriptor->fixed_range = false;
			}
		}

		if (mtrr_cap.fixed_range_support == true && mtrr_def_type.fixed_range_mtrr_enabled)
		{
			constexpr auto k64_base = 0x0;
			constexpr auto k64_size = 0x10000;
			constexpr auto k16_base = 0x80000;
			constexpr auto k16_size = 0x4000;
			constexpr auto k4_base = 0xC0000;
			constexpr auto k4_size = 0x1000;

			__mtrr_fixed_range_type k64_types = { __readmsr(IA32_MTRR_FIX64K_00000) };

			for (unsigned int i = 0; i < 8; i++)
			{
				descriptor = &g_vmm_context->ept_state->memory_range[g_vmm_context->ept_state->enabled_memory_ranges++];
				descriptor->memory_type = k64_types.types[i];
				descriptor->physcial_base_address = k64_base + (k64_size * i);
				descriptor->physcial_end_address = k64_base + (k64_size * i) + (k64_size - 1);
				descriptor->fixed_range = true;
			}

			for (unsigned int i = 0; i < 2; i++)
			{
				__mtrr_fixed_range_type k16_types = { __readmsr(IA32_MTRR_FIX16K_80000 + i) };

				for (unsigned int j = 0; j < 8; j++)
				{
					descriptor = &g_vmm_context->ept_state->memory_range[g_vmm_context->ept_state->enabled_memory_ranges++];
					descriptor->memory_type = k16_types.types[j];
					descriptor->physcial_base_address = (k16_base + (i * k16_size * 8)) + (k16_size * j);
					descriptor->physcial_end_address = (k16_base + (i * k16_size * 8)) + (k16_size * j) + (k16_size - 1);
					descriptor->fixed_range = true;
				}
			}

			for (unsigned int i = 0; i < 8; i++)
			{
				__mtrr_fixed_range_type k4_types = { __readmsr(IA32_MTRR_FIX4K_C0000 + i) };

				for (unsigned int j = 0; j < 8; j++)
				{
					descriptor = &g_vmm_context->ept_state->memory_range[g_vmm_context->ept_state->enabled_memory_ranges++];
					descriptor->memory_type = k4_types.types[j];
					descriptor->physcial_base_address = (k4_base + (i * k4_size * 8)) + (k4_size * j);
					descriptor->physcial_end_address = (k4_base + (i * k4_size * 8)) + (k4_size * j) + (k4_size - 1);
					descriptor->fixed_range = true;
				}
			}
		}

		//
		// Indicates the number of variable ranges
		// implemented on the processor.
		for (int i = 0; i < mtrr_cap.range_register_number; i++)
		{
			//
			// The first entry in each pair (IA32_MTRR_PHYSBASEn) defines the base address and memory type for the range;
			// the second entry(IA32_MTRR_PHYSMASKn) contains a mask used to determine the address range.The “n” suffix
			// is in the range 0 through m–1 and identifies a specific register pair.
			//
			current_phys_base.all = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
			current_phys_mask.all = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

			//
			// If range is enabled
			if (current_phys_mask.valid && current_phys_base.type != mtrr_def_type.memory_type)
			{
				descriptor = &g_vmm_context->ept_state->memory_range[g_vmm_context->ept_state->enabled_memory_ranges++];

				//
				// Calculate base address, physbase is truncated by 12 bits so we have to left shift it by 12
				//
				descriptor->physcial_base_address = current_phys_base.physbase << PAGE_SHIFT;

				//
				// Index of first bit set to one determines how much do we have to bit shift to get size of range
				// physmask is truncated by 12 bits so we have to left shift it by 12
				//
				unsigned long bits_in_mask = 0;
				_BitScanForward64(&bits_in_mask, current_phys_mask.physmask << PAGE_SHIFT);

				//
				// Calculate the end of range specified by mtrr
				//
				descriptor->physcial_end_address = descriptor->physcial_base_address + ((1ULL << bits_in_mask) - 1ULL);

				//
				// Get memory type of range
				//
				descriptor->memory_type = (unsigned __int8)current_phys_base.type;
				descriptor->fixed_range = false;
			}
		}
	}

	/// <summary>
	/// Get page cache memory type
	/// </summary>
	/// <param name="pfn"></param>
	/// <param name="is_large_page"></param>
	/// <returns></returns>
	unsigned __int8 get_memory_type(unsigned __int64 pfn, bool is_large_page)
	{
		unsigned __int64 page_start_address = is_large_page == true ? pfn * LARGE_PAGE_SIZE : pfn * PAGE_SIZE;
		unsigned __int64 page_end_address = is_large_page == true ? (pfn * LARGE_PAGE_SIZE) + (LARGE_PAGE_SIZE - 1) : (pfn * PAGE_SIZE) + (PAGE_SIZE - 1);
		unsigned __int8 memory_type = g_vmm_context->ept_state->default_memory_type;

		for (unsigned int i = 0; i < g_vmm_context->ept_state->enabled_memory_ranges; i++)
		{
			if (page_start_address >= g_vmm_context->ept_state->memory_range[i].physcial_base_address &&
				page_end_address <= g_vmm_context->ept_state->memory_range[i].physcial_end_address)
			{
				memory_type = g_vmm_context->ept_state->memory_range[i].memory_type;

				if (g_vmm_context->ept_state->memory_range[i].fixed_range == true)
					break;

				if (memory_type == MEMORY_TYPE_UNCACHEABLE)
					break;
			}
		}

		return memory_type;
	}

	/// <summary>
	/// Check if potential large page doesn't land on two or more different cache memory types
	/// </summary>
	/// <param name="pfn"></param>
	/// <returns></returns>
	bool is_valid_for_large_page(unsigned __int64 pfn)
	{
		unsigned __int64 page_start_address = pfn * LARGE_PAGE_SIZE;
		unsigned __int64 page_end_address = (pfn * LARGE_PAGE_SIZE) + (LARGE_PAGE_SIZE - 1);

		for (unsigned int i = 0; i < g_vmm_context->ept_state->enabled_memory_ranges; i++)
		{
			if (page_start_address <= g_vmm_context->ept_state->memory_range[i].physcial_end_address &&
				page_end_address > g_vmm_context->ept_state->memory_range[i].physcial_end_address)
				return false;

			else if (page_start_address < g_vmm_context->ept_state->memory_range[i].physcial_base_address &&
					 page_end_address >= g_vmm_context->ept_state->memory_range[i].physcial_base_address)
				return false;
		}

		return true;
	}

	/// <summary> 
	/// Setup page memory type
	/// </summary>
	/// <param name="entry"> Pointer to pml2 entry </param>
	/// <param name="pfn"> Page frame number </param>
	bool setup_pml2_entry(__ept_pde& entry, unsigned __int64 pfn)
	{
		entry.page_directory_entry.physical_address = pfn;
		
		if (is_valid_for_large_page(pfn) == true)
		{
			entry.page_directory_entry.memory_type = get_memory_type(pfn, true);
			return true;
		}

		else
		{
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("Failed to allocate split buffer");
				return false;
			}

			return split_pml2(split_buffer, pfn * LARGE_PAGE_SIZE);
		}
	}

	/// <summary>
	/// Create ept page table
	/// </summary>
	/// <returns> status </returns>
	bool create_ept_page_table()
	{
		PHYSICAL_ADDRESS max_size;
		max_size.QuadPart = MAXULONG64;

		g_vmm_context->ept_state->ept_page_table = allocate_contignous_memory<__vmm_ept_page_table>();
		if (g_vmm_context->ept_state->ept_page_table == NULL)
		{
			LogError("Failed to allocate memory for PageTable");
			return false;
		}

		__vmm_ept_page_table* page_table = g_vmm_context->ept_state->ept_page_table;
		RtlSecureZeroMemory(page_table, sizeof(__vmm_ept_page_table));

		//
		// Set all pages as rwx to prevent unwanted ept violation
		//
		page_table->pml4[0].physical_address = GET_PFN(MmGetPhysicalAddress(&page_table->pml3[0]).QuadPart);
		page_table->pml4[0].read = 1;
		page_table->pml4[0].write = 1;
		page_table->pml4[0].execute = 1;

		__ept_pdpte pdpte_template = { 0 };

		pdpte_template.read = 1;
		pdpte_template.write = 1;
		pdpte_template.execute = 1;

		__stosq((unsigned __int64*)&page_table->pml3[0], pdpte_template.all, 512);

		for (int i = 0; i < 512; i++)
			page_table->pml3[i].physical_address = GET_PFN(MmGetPhysicalAddress(&page_table->pml2[i][0]).QuadPart);

		__ept_pde pde_template = { 0 };

		pde_template.page_directory_entry.read = 1;
		pde_template.page_directory_entry.write = 1;
		pde_template.page_directory_entry.execute = 1;

		pde_template.page_directory_entry.large_page = 1;

		__stosq((unsigned __int64*)&page_table->pml2[0], pde_template.all, 512 * 512);

		for (int i = 0; i < 512; i++)
			for (int j = 0; j < 512; j++)
				if(setup_pml2_entry(page_table->pml2[i][j], (i * 512) + j) == false)
					return false;

		return true;
	}

	/// <summary>
	/// Initialize ept structure
	/// </summary>
	/// <returns></returns>
	bool initialize()
	{
		__eptp* ept_pointer = allocate_pool<__eptp*>(PAGE_SIZE);
		if (ept_pointer == NULL)
			return false;

		RtlSecureZeroMemory(ept_pointer, PAGE_SIZE);

		if (create_ept_page_table() == false)
			return false;

		ept_pointer->memory_type = g_vmm_context->ept_state->default_memory_type;

		// Indicates 4 level paging
		ept_pointer->page_walk_length = 3;

		ept_pointer->pml4_address = GET_PFN(MmGetPhysicalAddress(&g_vmm_context->ept_state->ept_page_table->pml4).QuadPart);

		g_vmm_context->ept_state->ept_pointer = ept_pointer;

		return true;
	}

	/// <summary>
	/// Get pml2 entry
	/// </summary>
	/// <param name="physical_address"></param>
	/// <returns> pointer to pml2 </returns>
	__ept_pde* get_pml2_entry(unsigned __int64 physical_address)
	{
		unsigned __int64 pml4_index = MASK_EPT_PML4_INDEX(physical_address);
		unsigned __int64 pml3_index = MASK_EPT_PML3_INDEX(physical_address);
		unsigned __int64 pml2_index = MASK_EPT_PML2_INDEX(physical_address);

		if (pml4_index > 0)
		{
			LogError("Address above 512GB is invalid");
			return nullptr;
		}

		return &g_vmm_context->ept_state->ept_page_table->pml2[pml3_index][pml2_index];
	}

	/// <summary>
	/// Get pml1 entry
	/// </summary>
	/// <param name="physical_address"></param>
	/// <returns></returns>
	__ept_pte* get_pml1_entry(unsigned __int64 physical_address)
	{
		unsigned __int64 pml4_index = MASK_EPT_PML4_INDEX(physical_address);
		unsigned __int64 pml3_index = MASK_EPT_PML3_INDEX(physical_address);
		unsigned __int64 pml2_index = MASK_EPT_PML2_INDEX(physical_address);

		if (pml4_index > 0)
		{
			LogError("Address above 512GB is invalid");
			return nullptr;
		}

		__ept_pde* pml2 = &g_vmm_context->ept_state->ept_page_table->pml2[pml3_index][pml2_index];
		if (pml2->page_directory_entry.large_page == 1)
		{
			return nullptr;
		}

		PHYSICAL_ADDRESS pfn;
		pfn.QuadPart = pml2->large_page.physical_address << PAGE_SHIFT;
		__ept_pte* pml1 = (__ept_pte*)MmGetVirtualForPhysical(pfn);

		if (pml1 == nullptr)
		{
			return nullptr;
		}

		pml1 = &pml1[MASK_EPT_PML1_INDEX(physical_address)];
		return pml1;
	}

	/// <summary>
	/// Split pml2 into 512 pml1 entries (From one 2MB page to 512 4KB pages)
	/// </summary>
	/// <param name="pre_allocated_buffer"> Pre allocated buffer for split </param>
	/// <param name="physical_address"></param>
	/// <returns> status </returns>
	bool split_pml2(void* pre_allocated_buffer, unsigned __int64 physical_address)
	{
		__ept_pde* entry = get_pml2_entry(physical_address);
		if (entry == NULL)
		{
			LogError("Invalid address passed");
			return false;
		}

		__ept_dynamic_split* new_split = (__ept_dynamic_split*)pre_allocated_buffer;
		RtlSecureZeroMemory(new_split, sizeof(__ept_dynamic_split));

		//
		// Set all pages as rwx to prevent unwanted ept violation
		//
		new_split->entry = entry;

		__ept_pte entry_template = { 0 };
		entry_template.read = 1;
		entry_template.write = 1;
		entry_template.execute = 1;
		entry_template.ept_memory_type = entry->page_directory_entry.memory_type;
		entry_template.ignore_pat = entry->page_directory_entry.ignore_pat;
		entry_template.suppress_ve = entry->page_directory_entry.suppressve;

		__stosq((unsigned __int64*)&new_split->pml1[0], entry_template.all, 512);
		for (int i = 0; i < 512; i++)
		{
			unsigned __int64 pfn = ((entry->page_directory_entry.physical_address * LARGE_PAGE_SIZE) >> PAGE_SHIFT) + i;
			new_split->pml1[i].physical_address = pfn;
			new_split->pml1[i].ept_memory_type = get_memory_type(pfn, false);
		}

		__ept_pde new_entry = { 0 };
		new_entry.large_page.read = 1;
		new_entry.large_page.write = 1;
		new_entry.large_page.execute = 1;

		new_entry.large_page.physical_address = MmGetPhysicalAddress(&new_split->pml1[0]).QuadPart >> PAGE_SHIFT;

		RtlCopyMemory(entry, &new_entry, sizeof(new_entry));

		return true;
	}

	/// <summary>
	/// Swap physcial pages and invalidate tlb
	/// </summary>
	/// <param name="entry_address"> Pointer to page table entry which we want to change </param>
	/// <param name="entry_value"> Pointer to page table entry which we want use to change </param>
	void swap_pml1(__ept_pte* entry_address, __ept_pte entry_value)
	{
		// Acquire the lock
		spinlock::lock(&g_vmm_context->ept_state->pml_lock);

		// Set the value
		entry_address->all = entry_value.all;

		// Release the lock
		spinlock::unlock(&g_vmm_context->ept_state->pml_lock);
	}

	/// <summary>
	/// Swap physcial pages and invalidate tlb
	/// </summary>
	/// <param name="entry_address"> Pointer to page table entry which we want to change </param>
	/// <param name="entry_value"> Pointer to page table entry which we want use to change </param>
	/// <param name="invalidation_type"> Specifiy if we want to invalidate single context or all contexts  </param>
	void swap_pml1_and_invalidate_tlb(__ept_pte* entry_address, __ept_pte entry_value, invept_type invalidation_type)
	{
		// Acquire the lock
		spinlock::lock(&g_vmm_context->ept_state->pml_lock);

		// Set the value
		entry_address->all = entry_value.all;

		// Invalidate the cache
		if (invalidation_type == INVEPT_SINGLE_CONTEXT)
		{
			invept_single_context(g_vmm_context->ept_state->ept_pointer->all);
		}
		else
		{
			invept_all_contexts();
		}
		// Release the lock
		spinlock::unlock(&g_vmm_context->ept_state->pml_lock);
	}

	/// <summary>
	/// Write an absolute jump, We aren't touching any register except stack so it's the most safest trampoline
	/// Size: 14 bytes
	/// </summary>
	/// <param name="target_buffer"> Pointer to trampoline buffer </param>
	/// <param name="destination_address"> Address of place where we want to jump </param>
	void hook_write_absolute_jump(unsigned __int8* target_buffer, unsigned __int64 destination_address)
	{
		// push lower 32 bits of destination address	
		target_buffer[0] = 0x68;
		*((unsigned __int32*)&target_buffer[1]) = (unsigned __int32)destination_address;

		// mov dword ptr [rsp + 4]
		target_buffer[5] = 0xc7;
		target_buffer[6] = 0x44;
		target_buffer[7] = 0x24;
		target_buffer[8] = 0x04;

		// higher 32 bits of destination address	
		*((unsigned __int32*)&target_buffer[9]) = (unsigned __int32)(destination_address >> 32);

		// ret
		target_buffer[13] = 0xc3;
	}

	/// <summary>
	/// Write relative jump,
	/// Size: 5 Bytes
	/// </summary>
	/// <param name="target_buffer"> Pointer to trampoline buffer </param>
	/// <param name="destination_address"> Address where we want to jump </param>
	/// <param name="source_address"> Address from which we want to jump </param>
	void hook_write_relative_jump(unsigned __int8* target_buffer, unsigned __int64 destination_address, unsigned __int64 source_address)
	{
		// destination - (source + sizeof instruction)
		__int32 jmp_value = destination_address - (source_address + 0x5);

		// relative jmp opcode
		target_buffer[0] = 0xe9;

		// set jmp offset
		*((__int32*)&target_buffer[1]) = jmp_value;
	}

	/// <summary>
	/// 
	/// </summary>
	/// <param name="hooked_page"> Pointer to __ept_hooked_page_info structure which holds info about hooked page </param>
	/// <param name="target_function"> Address of function which we want to hook </param>
	/// <param name="hooked_function"> Address of hooked version of function which we are hooking </param>
	/// <param name="origin_function"> Address used to call original function </param>
	/// <returns></returns>
	bool hook_instruction_memory(__ept_hooked_function_info* hooked_function_info, void* target_function, void* hooked_function,void* trampoline, void** origin_function)
	{
		unsigned __int64 hooked_instructions_size = 0;

		// Get offset of hooked function within page
		 unsigned __int64 page_offset = MASK_EPT_PML1_OFFSET((unsigned __int64)target_function);

		if (trampoline != 0)
		{
			hooked_instructions_size = 0;

			// If first 5 bytes of function are on 2 separate pages then return (Hypervisor doesn't support function hooking at page boundaries)
			if ((page_offset + 5) > PAGE_SIZE - 1)
			{
				LogError("Function at page boundary");
				return false;
			}

			while (hooked_instructions_size < 5)
			{
				hooked_instructions_size += LDE((unsigned __int8*)target_function + hooked_instructions_size, 64);
			}

			// If instructions to hook are on two seperate pages then stop hooking (Hypervisor doesn't support function hooking at page boundaries)
			if ((hooked_instructions_size + 5) > PAGE_SIZE - 1)
			{
				LogError("Function at page boundary");
				return false;
			}

			hooked_function_info->hook_size = hooked_instructions_size;

			hook_write_relative_jump(&hooked_function_info->fake_page_contents[page_offset], (unsigned __int64)trampoline, (unsigned __int64)target_function);

			RtlCopyMemory(hooked_function_info->first_trampoline_address, target_function, hooked_instructions_size);

			hook_write_absolute_jump(&hooked_function_info->first_trampoline_address[hooked_instructions_size], (unsigned __int64)target_function + hooked_instructions_size);

			*origin_function = hooked_function_info->first_trampoline_address;

			return hook_function(trampoline, hooked_function, nullptr, nullptr);
		}

		// If first 14 bytes of function are on 2 separate pages then return (Hypervisor doesn't support function hooking at page boundaries)
		if ((page_offset + 14) > PAGE_SIZE - 1)
		{
			LogError("Function at page boundary");
			return false;
		}

		// Get the full size of instructions necessary to copy
		while (hooked_instructions_size < 14)
			hooked_instructions_size += LDE((unsigned __int8*)target_function + hooked_instructions_size, 64);


		// If instructions to hook are on two seperate pages then return (Hypervisor doesn't support function hooking at page boundaries)
		if ((hooked_instructions_size + 14) > PAGE_SIZE - 1)
		{
			LogError("Function at page boundary");
			return false;
		}

		hooked_function_info->hook_size = hooked_instructions_size;

		//
		// Now it's trampoline so we don't have to store origin function
		if (origin_function == nullptr)
		{
			hook_write_absolute_jump(&hooked_function_info->fake_page_contents[page_offset], (unsigned __int64)hooked_function);

			return true;
		}

		// Copy overwritten instructions to trampoline buffer
		RtlCopyMemory(hooked_function_info->first_trampoline_address, target_function, hooked_instructions_size);

		// Add the absolute jump back to the original function.
		hook_write_absolute_jump(&hooked_function_info->first_trampoline_address[hooked_instructions_size], (unsigned __int64)target_function + hooked_instructions_size);

		// Return to user address of trampoline to call original function
		*origin_function = hooked_function_info->first_trampoline_address;

		// Write the absolute jump to our shadow page memory to jump to our hooked_page.
		hook_write_absolute_jump(&hooked_function_info->fake_page_contents[page_offset], (unsigned __int64)hooked_function);

		return true;
	}

	bool is_page_splitted(unsigned __int64 physical_address)
	{
		__ept_pde* entry = get_pml2_entry(physical_address);
		return !entry->page_directory_entry.large_page;
	}

	/// <summary>
	/// Perfrom a hook
	/// </summary>
	/// <param name="target_address" > Address of function which we want to hook </param>
	/// <param name="hook_function"> Address of hooked version of function which we are hooking </param>
	/// <param name="(Optional) trampoline">Address of code cave which is located in 2gb range of target function (Use only if you need smaller trampoline)</param>
	/// <param name="origin_function"> Address used to call original function </param>
	/// <returns></returns>
	bool hook_function(void* target_function, void* hooked_function,void* trampoline, void** origin_function)
	{
		unsigned __int64 physical_address = MmGetPhysicalAddress(target_function).QuadPart;

		//
		// Check if function exist in physical memory
		//
		if (physical_address == NULL)
		{
			LogError("Requested virtual memory doesn't exist in physical one");
			return false;
		}

		//
		// Check if page isn't already hooked
		//
		PLIST_ENTRY current = &g_vmm_context->ept_state->hooked_page_list;
		while (&g_vmm_context->ept_state->hooked_page_list != current->Flink)
		{
			current = current->Flink;
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);

			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				LogInfo("Page already hooked");

				__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, TRUE, sizeof(__ept_hooked_function_info));
				if (hooked_function_info == nullptr)
				{
					LogError("There is no pre-allocated pool for hooked function struct");
					return false;
				}

				//
				// If we are hooking code cave for second trampoline 
				// then origin function in null and we don't have to get pool for trampoline
				//
				if(origin_function != nullptr)
				{
					hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
					if (hooked_function_info->first_trampoline_address == nullptr)
					{
						pool_manager::release_pool(hooked_function_info);
						LogError("There is no pre-allocated pool for trampoline");
						return false;
					}
				}

				hooked_function_info->virtual_address = target_function;

				hooked_function_info->second_trampoline_address = trampoline;

				hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

				if (hook_instruction_memory(hooked_function_info, target_function, hooked_function, trampoline, origin_function) == false)
				{
					if(hooked_function_info->first_trampoline_address != nullptr)
						pool_manager::release_pool(hooked_function_info->first_trampoline_address);
					pool_manager::release_pool(hooked_function_info);
					LogError("Hook failed");
					return false;
				}

				// Track all hooked functions within page
				InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

				return true;
			}
		}

		if (is_page_splitted(physical_address) == false)
		{
			void* split_buffer = pool_manager::request_pool<void*>(pool_manager::INTENTION_SPLIT_PML2, true, sizeof(__ept_dynamic_split));
			if (split_buffer == nullptr)
			{
				LogError("There is no preallocated pool for split");
				return false;
			}

			if (split_pml2(split_buffer, physical_address) == false)
			{
				pool_manager::release_pool(split_buffer);
				LogError("Split failed");
				return false;
			}
		}

		__ept_pte* target_page = get_pml1_entry(physical_address);
		if (target_page == nullptr)
		{
			LogError("Failed to get PML1 entry of the target address");
			return false;
		}

		__ept_hooked_page_info* hooked_page_info = pool_manager::request_pool<__ept_hooked_page_info*>(pool_manager::INTENTION_TRACK_HOOKED_PAGES, true, sizeof(__ept_hooked_page_info));
		if (hooked_page_info == nullptr)
		{
			LogError("There is no preallocated pool for hooked page info");
			return false;
		}

		InitializeListHead(&hooked_page_info->hooked_functions_list);

		__ept_hooked_function_info* hooked_function_info = pool_manager::request_pool<__ept_hooked_function_info*>(pool_manager::INTENTION_TRACK_HOOKED_FUNCTIONS, true, sizeof(__ept_hooked_function_info));
		if (hooked_function_info == nullptr)
		{
			pool_manager::release_pool(hooked_page_info);
			LogError("There is no preallocated pool for hooked function info");
			return false;
		}

		//
		// If we are hooking code cave for second trampoline 
		// then origin function in null and we don't have to get pool for trampoline
		//
		if (origin_function != nullptr)
		{
			hooked_function_info->first_trampoline_address = pool_manager::request_pool<unsigned __int8*>(pool_manager::INTENTION_EXEC_TRAMPOLINE, TRUE, 100);
			if (hooked_function_info->first_trampoline_address == nullptr)
			{
				pool_manager::release_pool(hooked_page_info);
				pool_manager::release_pool(hooked_function_info);
				LogError("There is no pre-allocated pool for trampoline");
				return false;
			}
		}

		hooked_page_info->pfn_of_hooked_page = GET_PFN(physical_address);
		hooked_page_info->pfn_of_fake_page_contents = GET_PFN(MmGetPhysicalAddress(hooked_page_info->fake_page_contents).QuadPart);
		hooked_page_info->entry_address = target_page;

		hooked_page_info->entry_address->execute = 0;
		hooked_page_info->entry_address->read = 1;
		hooked_page_info->entry_address->write = 1;

		hooked_page_info->original_entry = *target_page;
		hooked_page_info->changed_entry = *target_page;

		hooked_page_info->changed_entry.read = 0;
		hooked_page_info->changed_entry.write = 0;
		hooked_page_info->changed_entry.execute = 1;

		hooked_page_info->changed_entry.physical_address = hooked_page_info->pfn_of_fake_page_contents;
		
		RtlCopyMemory(&hooked_page_info->fake_page_contents, PAGE_ALIGN(target_function), PAGE_SIZE);

		hooked_function_info->virtual_address = target_function;

		hooked_function_info->second_trampoline_address = trampoline;

		hooked_function_info->fake_page_contents = hooked_page_info->fake_page_contents;

		if(hook_instruction_memory(hooked_function_info, target_function, hooked_function, trampoline, origin_function) == false)
		{
			if (hooked_function_info->first_trampoline_address != nullptr)
				pool_manager::release_pool(hooked_function_info->first_trampoline_address);
			pool_manager::release_pool(hooked_function_info);
			pool_manager::release_pool(hooked_page_info);
			LogError("Hook failed");
			return false;
		}

		// Track all hooked functions
		InsertHeadList(&hooked_page_info->hooked_functions_list, &hooked_function_info->hooked_function_list);

		// Track all hooked pages
		InsertHeadList(&g_vmm_context->ept_state->hooked_page_list, &hooked_page_info->hooked_page_list);

		invept_single_context(g_vmm_context->ept_state->ept_pointer->all);

		return true;
	}

	/// <summary>
	/// Unhook single function
	/// </summary>
	/// <param name="virtual_address"></param>
	/// <returns></returns>
	bool unhook_function(unsigned __int64 virtual_address)
	{
		//
		// Check if function which we want to unhook exist in physical memory
		unsigned __int64 physical_address = MmGetPhysicalAddress((void*)virtual_address).QuadPart;
		if (physical_address == 0)
			return false;

		PLIST_ENTRY current_hooked_page = &g_vmm_context->ept_state->hooked_page_list;
		while (&g_vmm_context->ept_state->hooked_page_list != current_hooked_page->Flink)
		{
			current_hooked_page = current_hooked_page->Flink;
			__ept_hooked_page_info* hooked_page_info = CONTAINING_RECORD(current_hooked_page, __ept_hooked_page_info, hooked_page_list);

			//
			// Check if function pfn is equal to pfn saved in hooked page info
			if (hooked_page_info->pfn_of_hooked_page == GET_PFN(physical_address))
			{
				PLIST_ENTRY current_hooked_function;
				current_hooked_function = &hooked_page_info->hooked_functions_list;

				while (&hooked_page_info->hooked_functions_list != current_hooked_function->Flink)
				{
					current_hooked_function = current_hooked_function->Flink;
					__ept_hooked_function_info* hooked_function_info = CONTAINING_RECORD(current_hooked_function, __ept_hooked_function_info, hooked_function_list);
					
					unsigned __int64 function_page_offset = MASK_EPT_PML1_OFFSET(virtual_address);

					//
					// Check if the address of function which we want to unhook is 
					// the same as address of function in hooked function info struct
					//
					if (function_page_offset == MASK_EPT_PML1_OFFSET(hooked_function_info->virtual_address))
					{
						// Restore overwritten data
						RtlCopyMemory(&hooked_function_info->fake_page_contents[function_page_offset], hooked_function_info->virtual_address, hooked_function_info->hook_size);
						
						// If hook uses two trampolines unhook second one
						if (hooked_function_info->second_trampoline_address != nullptr)
							unhook_function((unsigned __int64)hooked_function_info->second_trampoline_address);

						RemoveEntryList(current_hooked_function);

						if(hooked_function_info->first_trampoline_address != nullptr)
							pool_manager::release_pool(hooked_function_info->first_trampoline_address);
						pool_manager::release_pool(hooked_function_info);

						//
						// If there is no more function hooks free hooked page info struct
						if (hooked_page_info->hooked_functions_list.Flink == hooked_page_info->hooked_functions_list.Blink)
						{
							hooked_page_info->original_entry.execute = 1;
							swap_pml1_and_invalidate_tlb(hooked_page_info->entry_address, hooked_page_info->original_entry, INVEPT_SINGLE_CONTEXT);

							RemoveEntryList(current_hooked_page);
							pool_manager::release_pool(hooked_page_info);
							return true;
						}

						invept_all_contexts();
						return true;
					}
				}
			}
		}
		return false;
	}

	/// <summary>
	/// Unhook all functions and invalidate tlb
	/// </summary>
	void unhook_all_functions()
	{
		PLIST_ENTRY current_hooked_page = g_vmm_context->ept_state->hooked_page_list.Flink;
		while (&g_vmm_context->ept_state->hooked_page_list != current_hooked_page)
		{
			__ept_hooked_page_info* hooked_entry = CONTAINING_RECORD(current_hooked_page, __ept_hooked_page_info, hooked_page_list);

			PLIST_ENTRY current_hooked_function;

			current_hooked_function = hooked_entry->hooked_functions_list.Flink;
			while (&hooked_entry->hooked_functions_list != current_hooked_function)
			{
				__ept_hooked_function_info* hooked_function_info = CONTAINING_RECORD(current_hooked_function, __ept_hooked_function_info, hooked_function_list);
				
				// If hook uses two trampolines unhook second one
				if (hooked_function_info->first_trampoline_address != nullptr)
					pool_manager::release_pool(hooked_function_info->first_trampoline_address);

				RemoveEntryList(current_hooked_function);

				current_hooked_function = current_hooked_function->Flink;

				pool_manager::release_pool(hooked_function_info);
			}

			// Restore original pte value
			hooked_entry->original_entry.execute = 1;
			swap_pml1_and_invalidate_tlb(hooked_entry->entry_address, hooked_entry->original_entry, INVEPT_SINGLE_CONTEXT);

			RemoveEntryList(current_hooked_page);

			current_hooked_page = current_hooked_page->Flink;

			pool_manager::release_pool(hooked_entry);
		}
	}
}