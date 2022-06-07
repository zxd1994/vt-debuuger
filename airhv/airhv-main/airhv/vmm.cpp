#pragma warning( disable :  4201)

#include <ntddk.h>
#include <intrin.h>
#include "common.h"
#include "ia32\cpuid.h"
#include "asm\vm_context.h"
#include "ia32\cr.h"
#include "ia32\msr.h"
#include "ia32\vmcs.h"
#include "log.h"
#include "ntapi.h"
#include "ia32\vmcs_encodings.h"
#include "allocators.h"

void dpc_broadcast_initialize_guest(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(Dpc);
	vmx_save_state();

	// Wait for all DPCs to synchronize at this point
	KeSignalCallDpcSynchronize(SystemArgument2);

	// Mark the DPC as being complete
	KeSignalCallDpcDone(SystemArgument1);
}


/// <summary>
/// Deallocate all structures
/// </summary>
void free_vmm_context()
{
	if (g_vmm_context != nullptr)
	{
		// POOL MANAGER
		if (g_vmm_context->pool_manager != nullptr)
		{
			pool_manager::uninitialize();
			free_pool(g_vmm_context->pool_manager);
		}

		// EPT STATE
		if (g_vmm_context->ept_state != nullptr)
		{
			// EPT POINTER
			if (g_vmm_context->ept_state->ept_pointer != nullptr)
			{
				free_pool(g_vmm_context->ept_state->ept_pointer);
			}
			// EPT PAGE TABLE
			if (g_vmm_context->ept_state->ept_page_table != nullptr)
			{
				free_contignous_memory(g_vmm_context->ept_state->ept_page_table);

			}
			free_pool(g_vmm_context->ept_state);
		}

		// VCPU TABLE
		if (g_vmm_context->vcpu_table != nullptr)
		{
			for (unsigned int i = 0; i < g_vmm_context->processor_count; i++)
			{
				// VCPU
				if (g_vmm_context->vcpu_table[i] != nullptr)
				{
					// VCPU VMXON REGION
					if (g_vmm_context->vcpu_table[i]->vmxon != nullptr)
					{
						free_contignous_memory(g_vmm_context->vcpu_table[i]->vmxon);
					}

					// VCPU VMCS REGION
					if (g_vmm_context->vcpu_table[i]->vmcs != nullptr)
					{
						free_contignous_memory(g_vmm_context->vcpu_table[i]->vmcs);
					}

					// VCPU VMM STACK
					if (g_vmm_context->vcpu_table[i]->vmm_stack != nullptr)
					{
						free_pool(g_vmm_context->vcpu_table[i]->vmm_stack);
					}

					// MSR BITMAP
					if (g_vmm_context->vcpu_table[i]->vcpu_bitmaps.msr_bitmap != nullptr)
					{
						free_pool(g_vmm_context->vcpu_table[i]->vcpu_bitmaps.msr_bitmap);
					}

					// IO BITMAP A
					if (g_vmm_context->vcpu_table[i]->vcpu_bitmaps.io_bitmap_a != nullptr)
					{
						free_pool(g_vmm_context->vcpu_table[i]->vcpu_bitmaps.io_bitmap_a);
					}

					// IO BITMAP B
					if (g_vmm_context->vcpu_table[i]->vcpu_bitmaps.io_bitmap_b != nullptr)
					{
						free_pool(g_vmm_context->vcpu_table[i]->vcpu_bitmaps.io_bitmap_b);
					}

					free_pool(g_vmm_context->vcpu_table[i]);
				}
			}
			free_pool(g_vmm_context->vcpu_table);
		}

		free_pool(g_vmm_context);
	}

	g_vmm_context = 0;
}


/// <summary>
/// Allocates contiguous memory for vmcs
/// </summary>
/// <param name="vcpu"> Pointer to vcpu </param>
/// <returns> status </returns>
bool init_vmcs(__vcpu* vcpu)
{
	__vmx_basic_msr vmx_basic = { 0 };
	PHYSICAL_ADDRESS physical_max;

	vmx_basic.all = __readmsr(IA32_VMX_BASIC);

	physical_max.QuadPart = ~0ULL;
	vcpu->vmcs = allocate_contignous_memory<__vmcs*>(PAGE_SIZE);
	if (vcpu->vmcs == NULL)
	{
		LogError("Vmcs structure could not be allocated");
		return false;
	}

	vcpu->vmcs_physical = MmGetPhysicalAddress(vcpu->vmcs).QuadPart;
	if (vcpu->vmcs_physical == NULL)
	{
		LogError("Could not get physical address of vmcs");
		return false;
	}

	RtlSecureZeroMemory(vcpu->vmcs, PAGE_SIZE);
	vcpu->vmcs->header.revision_identifier = vmx_basic.vmcs_revision_identifier;

	// Indicates if it's shadow vmcs or not
	vcpu->vmcs->header.shadow_vmcs_indicator = 0;

	return true;
}

/// <summary>
/// Allocate whole vmm context, build mtrr map, initalize pool manager and initialize ept structure 
/// </summary>
/// <returns> status </returns>
bool allocate_vmm_context()
{
	__cpuid_info cpuid_reg = { 0 };

	//
	// Allocate Nonpaged memory for vm global context structure
	//
	g_vmm_context = allocate_pool<__vmm_context>();
	if (g_vmm_context == nullptr) {
		LogError("g_vmm_context could not be allocated");
		return false;
	}
	RtlSecureZeroMemory(g_vmm_context, sizeof(__vmm_context));

	//
	// Allocate virtual cpu context for every logical core
	//
	g_vmm_context->processor_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	g_vmm_context->vcpu_table = allocate_pool<__vcpu**>(sizeof(__vcpu*) * (g_vmm_context->processor_count));
	if (g_vmm_context->vcpu_table == nullptr)
	{
		LogError("vcpu_table could not be allocated");
		return false;
	}
	RtlSecureZeroMemory(g_vmm_context->vcpu_table, sizeof(__vcpu*) * (g_vmm_context->processor_count));

	//
	// Allocate ept state structure
	//
	g_vmm_context->ept_state = allocate_pool<__ept_state>();
	if (g_vmm_context->ept_state == nullptr)
	{
		LogError("ept state could not be allocated");
		return false;
	}
	RtlSecureZeroMemory(g_vmm_context->ept_state, sizeof(__ept_state));

	InitializeListHead(&g_vmm_context->ept_state->hooked_page_list);

	//
	// Build mtrr map for physcial memory caching informations
	//
	ept::build_mtrr_map();

	if (pool_manager::initialize() == false)
	{
		return false;
	}

	//
	// Initialize ept structure
	//
	if (ept::initialize() == false)
	{
		return false;
	}

	g_vmm_context->hv_presence = true;

	__cpuid((int*)&cpuid_reg.eax, 0);
	g_vmm_context->highest_basic_leaf = cpuid_reg.eax;

	return true;
}

/// <summary>
/// Allocate whole vcpu context and bitmaps
/// </summary>
/// <returns> Pointer to vcpu </returns>
bool init_vcpu(__vcpu*& vcpu)
{
	vcpu = allocate_pool<__vcpu>();
	if (vcpu == nullptr)
	{
		LogError("vcpu structure could not be allocated");
		return false;
	}
	RtlSecureZeroMemory(vcpu, sizeof(__vcpu));

	vcpu->vmm_stack = allocate_pool<void*>(VMM_STACK_SIZE);
	if (vcpu->vmm_stack == nullptr)
	{
		LogError("vmm stack could not be allocated");
		return false;
	}
	RtlSecureZeroMemory(vcpu->vmm_stack, VMM_STACK_SIZE);

	vcpu->vcpu_bitmaps.msr_bitmap = allocate_pool<unsigned __int8*>(PAGE_SIZE);
	if (vcpu->vcpu_bitmaps.msr_bitmap == nullptr)
	{
		LogError("msr bitmap could not be allocated");
		return false;
	}
	RtlSecureZeroMemory(vcpu->vcpu_bitmaps.msr_bitmap, PAGE_SIZE);
	vcpu->vcpu_bitmaps.msr_bitmap_physical = MmGetPhysicalAddress(vcpu->vcpu_bitmaps.msr_bitmap).QuadPart;

	vcpu->vcpu_bitmaps.io_bitmap_a = allocate_pool<unsigned __int8*>(PAGE_SIZE);
	if (vcpu->vcpu_bitmaps.io_bitmap_a == nullptr)
	{
		LogError("io bitmap a could not be allocated");
		return false;
	}
	RtlSecureZeroMemory(vcpu->vcpu_bitmaps.io_bitmap_a, PAGE_SIZE);
	vcpu->vcpu_bitmaps.io_bitmap_a_physical = MmGetPhysicalAddress(vcpu->vcpu_bitmaps.io_bitmap_a).QuadPart;

	vcpu->vcpu_bitmaps.io_bitmap_b = allocate_pool<unsigned __int8*>(PAGE_SIZE);
	if (vcpu->vcpu_bitmaps.io_bitmap_b == nullptr)
	{
		LogError("io bitmap b could not be allocated");
		return false;
	}
	RtlSecureZeroMemory(vcpu->vcpu_bitmaps.io_bitmap_b, PAGE_SIZE);
	vcpu->vcpu_bitmaps.io_bitmap_b_physical = MmGetPhysicalAddress(vcpu->vcpu_bitmaps.io_bitmap_b).QuadPart;

	LogInfo("vcpu entry allocated successfully at %llX", vcpu);

	return true;
}

/// <summary>
/// Initialize vmxon structure
/// </summary>
/// <param name="vcpu"> Pointer to vcpu </param>
/// <returns> status </returns>
bool init_vmxon(__vcpu* vcpu)
{
	__vmx_basic_msr vmx_basic = { 0 };

	vmx_basic.all = __readmsr(IA32_VMX_BASIC);

	if (vmx_basic.vmxon_region_size > PAGE_SIZE)
		vcpu->vmxon = allocate_contignous_memory<__vmcs*>(PAGE_SIZE);

	else
		vcpu->vmxon = allocate_contignous_memory<__vmcs*>(vmx_basic.vmxon_region_size);

	if (vcpu->vmxon == nullptr)
	{
		LogError("vmxon could not be allocated");
		return false;
	}

	vcpu->vmxon_physical = MmGetPhysicalAddress(vcpu->vmxon).QuadPart;
	if (vcpu->vmxon_physical == 0)
	{
		LogError("Could not get vmxon physical address");
		return false;
	}

	RtlSecureZeroMemory(vcpu->vmxon, PAGE_SIZE);
	vcpu->vmxon->header.all = vmx_basic.vmcs_revision_identifier;
	vcpu->vmxon->header.shadow_vmcs_indicator = 0;

	return true;
}

/// <summary>
/// Adjust cr4 and cr0 for turning on vmx
/// </summary>
void adjust_control_registers()
{
	__cr4 cr4;
	__cr0 cr0;
	__cr_fixed cr_fixed;

	cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED0);
	cr0.all = __readcr0();
	cr0.all |= cr_fixed.split.low;
	cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED1);
	cr0.all &= cr_fixed.split.low;
	__writecr0(cr0.all);
	cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED0);
	cr4.all = __readcr4();
	cr4.all |= cr_fixed.split.low;
	cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED1);
	cr4.all &= cr_fixed.split.low;
	__writecr4(cr4.all);

	__ia32_feature_control_msr feature_msr = { 0 };
	feature_msr.all = __readmsr(IA32_FEATURE_CONTROL);

	if (feature_msr.lock == 0) 
	{
		feature_msr.vmxon_outside_smx = 1;
		feature_msr.lock = 1;

		__writemsr(IA32_FEATURE_CONTROL, feature_msr.all);
	}
}


/// <summary>
/// Initialize logical core and launch virtual machine managed by current vmcs
/// </summary>
/// <param name="guest_rsp"></param>
void init_logical_processor(void* guest_rsp)
{
	unsigned __int64 processor_number = KeGetCurrentProcessorNumber();

	__vcpu* vcpu = g_vmm_context->vcpu_table[processor_number];

	adjust_control_registers();

	if (__vmx_on(&vcpu->vmxon_physical)) 
	{
		LogError("Failed to put vcpu %d into VMX operation.\n", processor_number);
		return;
	}

	vcpu->vcpu_status.vmx_on = true;
	LogInfo("vcpu %d is now in VMX operation.\n", processor_number);

	fill_vmcs(vcpu, guest_rsp);
	vcpu->vcpu_status.vmm_launched = true;

	__vmx_vmlaunch();

	// We should never get here
	
	LogError("Vmlaunch failed");
	ASSERT(FALSE);
	vcpu->vcpu_status.vmm_launched = false;
	vcpu->vcpu_status.vmx_on = false;
	__vmx_off();
}

/// <summary>
/// Initialize and launch vmm
/// </summary>
/// <returns> status </returns>
bool vmm_init()
{
	if (allocate_vmm_context() == false)
		return false;

	//
	// Initalize vcpu for each logical core
	for (unsigned int iter = 0; iter < g_vmm_context->processor_count; iter++) 
	{
		if (init_vcpu(g_vmm_context->vcpu_table[iter]) == false)
			return false;

		if (init_vmxon(g_vmm_context->vcpu_table[iter]) == false)
			return false;

		if (init_vmcs(g_vmm_context->vcpu_table[iter]) == false)
			return false;
	}

	//
	// Call derefered procedure call (DPC) to fill vmcs and launch vmm for every logical core
	KeGenericCallDpc(dpc_broadcast_initialize_guest, 0);
	return true;
}