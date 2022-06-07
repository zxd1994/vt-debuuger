#pragma warning( disable : 4201 4244 4065)

#include <ntddk.h>
#include <intrin.h>
#include "hypervisor_routines.h"
#include "common.h"
#include "vmexit_handler.h"
#include "ia32\cpuid.h"
#include "ia32\vmcs_encodings.h"
#include "ia32\msr.h"
#include "log.h"
#include "vmcall_handler.h"
#include "interrupt.h"
#include "asm\vm_intrin.h"
#include "ia32\cr.h"
#include "ia32\rflags.h"
#include "ia32\dr.h"
#include "invalidators.h"
#include "xsave.h"
#include "ia32\segment.h"
#include "ia32\vmcs.h"

void vmexit_ept_violation_handler(__vcpu* vcpu);
void vmexit_unimplemented(__vcpu* vcpu);
void vmexit_exception_handler(__vcpu* vcpu);
void vmexit_ept_violation_handler(__vcpu* vcpu);
void vmexit_cr_handler(__vcpu* vcpu);
void vmexit_vm_instruction(__vcpu* vcpu);
void vmexit_triple_fault_handler(__vcpu* vcpu);
void vmexit_failed(__vcpu* vcpu);
void vmexit_invd_handler(__vcpu* vcpu);
void vmexit_rdtscp_handler(__vcpu* vcpu);
void vmexit_xsetbv_handler(__vcpu* vcpu);
void vmexit_rdtsc_handler(__vcpu* vcpu);
void vmexit_rdrand_handler(__vcpu* vcpu);
void vmexit_rdseed_handler(__vcpu* vcpu);
void vmexit_io_handler(__vcpu* vcpu);
void vmexit_mov_dr_handler(__vcpu* vcpu);
void vmexit_cpuid_handler(__vcpu* vcpu);
void vmexit_msr_read_handler(__vcpu* vcpu);
void vmexit_msr_write_handler(__vcpu* vcpu);
void vmexit_invpcid_handler(__vcpu* vcpu);
void vmexit_invlpg_handler(__vcpu* vcpu);
void vmexit_ldtr_access_handler(__vcpu* vcpu);
void vmexit_gdtr_access_handler(__vcpu* vcpu);

void (*exit_handlers[EXIT_REASON_LAST])(__vcpu* guest_registers) =
{
	vmexit_exception_handler,						// 00 EXIT_REASON_EXCEPTION_NMI
	vmexit_unimplemented,							// 01 EXIT_REASON_EXTERNAL_INTERRUPT
	vmexit_triple_fault_handler,					// 02 EXIT_REASON_TRIPLE_FAULT
	vmexit_unimplemented,							// 03 EXIT_REASON_INIT_SIGNAL
	vmexit_unimplemented,							// 04 EXIT_REASON_SIPI
	vmexit_unimplemented,							// 05 EXIT_REASON_IO_SMI
	vmexit_unimplemented,							// 06 EXIT_REASON_OTHER_SMI
	vmexit_unimplemented,							// 07 EXIT_REASON_PENDING_INTERRUPT
	vmexit_unimplemented,							// 08 EXIT_REASON_NMI_WINDOW
	vmexit_unimplemented,							// 09 EXIT_REASON_TASK_SWITCH
	vmexit_cpuid_handler,							// 10 EXIT_REASON_CPUID
	vmexit_unimplemented,							// 11 EXIT_REASON_GETSEC
	vmexit_unimplemented,							// 12 EXIT_REASON_HLT
	vmexit_invd_handler,							// 13 EXIT_REASON_INVD
	vmexit_invlpg_handler,							// 14 EXIT_REASON_INVLPG
	vmexit_unimplemented,							// 15 EXIT_REASON_RDPMC
	vmexit_rdtsc_handler,							// 16 EXIT_REASON_RDTSC
	vmexit_unimplemented,							// 17 EXIT_REASON_RSM
	vmexit_vmcall_handler,							// 18 EXIT_REASON_VMCALL
	vmexit_vm_instruction,							// 19 EXIT_REASON_VMCLEAR
	vmexit_vm_instruction,							// 20 EXIT_REASON_VMLAUNCH
	vmexit_vm_instruction,							// 21 EXIT_REASON_VMPTRLD
	vmexit_vm_instruction,							// 22 EXIT_REASON_VMPTRST
	vmexit_vm_instruction,							// 23 EXIT_REASON_VMREAD
	vmexit_vm_instruction,							// 24 EXIT_REASON_VMRESUME
	vmexit_vm_instruction,							// 25 EXIT_REASON_VMWRITE
	vmexit_vm_instruction,							// 26 EXIT_REASON_VMXOFF
	vmexit_vm_instruction,							// 27 EXIT_REASON_VMXON
	vmexit_cr_handler,								// 28 EXIT_REASON_CR_ACCESSES
	vmexit_mov_dr_handler,							// 29 EXIT_REASON_MOV_DR
	vmexit_io_handler,								// 30 EXIT_REASON_IO_INSTRUCTION
	vmexit_msr_read_handler,						// 31 EXIT_REASON_MSR_READ
	vmexit_msr_write_handler,						// 32 EXIT_REASON_MSR_WRITE
	vmexit_failed,									// 33 EXIT_REASON_INVALID_GUEST_STATE
	vmexit_failed,									// 34 EXIT_REASON_MSR_LOADING
	vmexit_unimplemented,							// 35 EXIT_REASON_RESERVED1
	vmexit_unimplemented,							// 36 EXIT_REASON_MWAIT
	vmexit_unimplemented,						    // 37 EXIT_REASON_MONITOR_TRAP_FLAG
	vmexit_unimplemented,							// 38 EXIT_REASON_RESERVED2
	vmexit_unimplemented,							// 39 EXIT_REASON_MONITOR
	vmexit_unimplemented,							// 40 EXIT_REASON_PAUSE
	vmexit_failed,									// 41 EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT
	vmexit_unimplemented,							// 42 EXIT_REASON_RESERVED3
	vmexit_unimplemented,							// 43 EXIT_REASON_TPR_BELOW_THRESHOLD
	vmexit_unimplemented,							// 44 EXIT_REASON_APIC_ACCESS 
	vmexit_unimplemented,							// 45 EXIT_REASON_VIRTUALIZED_EIO
	vmexit_gdtr_access_handler,						// 46 EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR
	vmexit_ldtr_access_handler,						// 47 EXIT_REASON_ACCESS_TO_LDTR_OR_TR
	vmexit_ept_violation_handler,					// 48 EXIT_REASON_EPT_VIOLATION
	vmexit_failed,									// 49 EXIT_REASON_EPT_MISCONFIGURATION
	vmexit_vm_instruction,							// 50 EXIT_REASON_INVEPT
	vmexit_rdtscp_handler,							// 51 EXIT_REASON_RDTSCP
	vmexit_unimplemented,							// 52 EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED
	vmexit_vm_instruction,							// 53 EXIT_REASON_INVVPID
	vmexit_invd_handler,							// 54 EXIT_REASON_WBINVD
	vmexit_xsetbv_handler,							// 55 EXIT_REASON_XSETBV
	vmexit_unimplemented,							// 56 EXIT_REASON_APIC_WRITE
	vmexit_rdrand_handler,							// 57 EXIT_REASON_RDRAND
	vmexit_invpcid_handler,							// 58 EXIT_REASON_INVPCID
	vmexit_vm_instruction,							// 59 EXIT_REASON_VMFUNC
	vmexit_unimplemented,							// 60 EXIT_REASON_ENCLS
	vmexit_rdseed_handler,							// 61 EXIT_REASON_RDSEED
	vmexit_unimplemented,							// 62 EXIT_REASON_PAGE_MODIFICATION_LOG_FULL
	vmexit_unimplemented,							// 63 EXIT_REASON_XSAVES
	vmexit_unimplemented,							// 64 EXIT_REASON_XRSTORS
	vmexit_unimplemented,							// 65 EXIT_REASON_RESERVED4
	vmexit_unimplemented,							// 66 EXIT_REASON_SPP_RELATED_EVENT
	vmexit_unimplemented,							// 67 EXIT_REASON_UMWAIT
	vmexit_unimplemented							// 68 EXIT_REASON_TPAUSE
};

/// <summary>
/// sgdt,sidt,lgdt,lidt handler
/// </summary>
/// <param name="guest_regs"></param>
void vmexit_gdtr_access_handler(__vcpu* vcpu)
{
	__vmexit_instruction_information3 instruction_information = { vcpu->vmexit_info.instruction_information };

	union __tmp_desc
	{
		__pseudo_descriptor64 desc64;
		__pseudo_descriptor32 desc32;
	};

	__tmp_desc* tmp_desc = (__tmp_desc*)hv::get_guest_address(vcpu);

	unsigned __int64 old_cr3 = hv::swap_context();

	switch (instruction_information.instruction_identity)
	{
		// SGDT
		case 0:
		{
			__segment_selector selector;
			selector.all = hv::vmread(GUEST_CS_SELECTOR);

			__segment_descriptor* segment_desc = (__segment_descriptor*)(hv::vmread(GUEST_GDTR_BASE) + selector.index * 8);

			if (segment_desc->long_mode == 1)
			{
				tmp_desc->desc64.base_address = hv::vmread(GUEST_GDTR_BASE);
				tmp_desc->desc64.limit = hv::vmread(GUEST_GDTR_LIMIT);
			}

			else 
			{
				tmp_desc->desc32.base_address = hv::vmread(GUEST_GDTR_BASE);
				tmp_desc->desc32.limit = hv::vmread(GUEST_GDTR_LIMIT);
			}

			break;
		}

		// SIDT
		case 1:
		{
			__segment_selector selector;
			selector.all = hv::vmread(GUEST_CS_SELECTOR);

			__segment_descriptor* segment_desc = (__segment_descriptor*)(hv::vmread(GUEST_GDTR_BASE) + selector.index * 8);

			if (segment_desc->long_mode == 1)
			{
				tmp_desc->desc64.base_address = hv::vmread(GUEST_IDTR_BASE);
				tmp_desc->desc64.limit = hv::vmread(GUEST_IDTR_LIMIT);
			}

			else
			{
				tmp_desc->desc32.base_address = hv::vmread(GUEST_IDTR_BASE);
				tmp_desc->desc32.limit = hv::vmread(GUEST_IDTR_LIMIT);
			}

			break;
		}

		// LGDT
		case 2:
		{
			hv::vmwrite(GUEST_GDTR_BASE, tmp_desc->desc64.base_address);
			hv::vmwrite(GUEST_GDTR_LIMIT, tmp_desc->desc64.limit);

			break;
		}

		// LIDT
		case 3:
		{
			hv::vmwrite(GUEST_IDTR_BASE, tmp_desc->desc64.base_address);
			hv::vmwrite(GUEST_IDTR_LIMIT, tmp_desc->desc64.limit);

			break;
		}
	}

	hv::restore_context(old_cr3);

	adjust_rip(vcpu);
}

/// <summary>
/// sldt,str,lldt,ltr handler
/// </summary>
/// <param name="guest_regs"></param>
void vmexit_ldtr_access_handler(__vcpu* vcpu)
{
	__vmexit_instruction_information4 instruction_information = { vcpu->vmexit_info.instruction_information };
	unsigned __int64* linear_address = 
		instruction_information.mem_reg ? 
		&vcpu->vmexit_info.guest_registers->rax - instruction_information.reg1 : 
		(unsigned __int64*)hv::get_guest_address(vcpu);

	unsigned __int64 old_cr3 = hv::swap_context();

	switch (instruction_information.instruction_identity)
	{
		// SLDT
		case 0:
		{
			*linear_address = hv::vmread(GUEST_LDTR_SELECTOR);

			break;
		}

		// STR
		case 1:
		{
			*linear_address = hv::vmread(GUEST_TR_SELECTOR);

			break;
		}

		// LLDT
		case 2:
		{
			hv::vmwrite(GUEST_LDTR_SELECTOR, *linear_address);

			break;
		}

		// LTR
		case 3:
		{
			hv::vmwrite(GUEST_TR_SELECTOR, *linear_address);

			__segment_selector selector;
			selector.all = *linear_address;
			__segment_descriptor* segment_desc = (__segment_descriptor*)(hv::vmread(GUEST_GDTR_BASE) + selector.index * 8);
			segment_desc->type |= 2;

			break;
		}
	}

	hv::restore_context(old_cr3);

	adjust_rip(vcpu);
}

/// <summary>
/// Msr read handler
/// </summary>
/// <param name="guest_regs"></param>
void vmexit_msr_read_handler(__vcpu* vcpu)
{
	__msr msr;
	unsigned __int64 msr_index = vcpu->vmexit_info.guest_registers->rcx;

	switch (msr_index)
	{
		case IA32_INTERRUPT_SSP_TABLE_ADDR:
			msr.all = hv::vmread(GUEST_INTERRUPT_SSP_TABLE_ADDR);
			break;

		case IA32_SYSENTER_CS:
			msr.all = hv::vmread(GUEST_SYSENTER_CS);
			break;

		case IA32_SYSENTER_EIP:
			msr.all = hv::vmread(GUEST_SYSENTER_EIP);
			break;

		case IA32_SYSENTER_ESP:
			msr.all = hv::vmread(GUEST_SYSENTER_ESP);
			break;

		case IA32_S_CET:
			msr.all = hv::vmread(GUEST_S_CET);
			break;

		case IA32_PERF_GLOBAL_CTRL:
			msr.all = hv::vmread(GUEST_PERF_GLOBAL_CONTROL);
			break;

		case IA32_PKRS:
			msr.all = hv::vmread(GUEST_PKRS);
			break;

		case IA32_RTIT_CTL:
			msr.all = hv::vmread(GUEST_RTIT_CTL);
			break;

		case IA32_BNDCFGS:
			msr.all = hv::vmread(GUEST_BNDCFGS);
			break;

		case IA32_PAT:
			msr.all = hv::vmread(GUEST_PAT);
			break;

		case IA32_EFER:
			msr.all = hv::vmread(GUEST_EFER);
			break;

		case IA32_GS_BASE:
			msr.all = hv::vmread(GUEST_GS_BASE);
			break;

		case IA32_FS_BASE:
			msr.all = hv::vmread(GUEST_FS_BASE);
			break;

		default:
			msr.all = __readmsr(msr_index);
			break;
	}

	vcpu->vmexit_info.guest_registers->rdx = msr.high;
	vcpu->vmexit_info.guest_registers->rax = msr.low;

	adjust_rip(vcpu);
}

/// <summary>
/// Msr write handler
/// </summary>
/// <param name="guest_regs"></param>
void vmexit_msr_write_handler(__vcpu* vcpu)
{
	unsigned __int64 msr_index = vcpu->vmexit_info.guest_registers->rcx;

	__msr msr;
	msr.high = vcpu->vmexit_info.guest_registers->rdx;
	msr.low = vcpu->vmexit_info.guest_registers->rax;

	switch (msr_index)
	{
		case IA32_INTERRUPT_SSP_TABLE_ADDR:
			hv::vmwrite(GUEST_INTERRUPT_SSP_TABLE_ADDR, msr.all);
			break;

		case IA32_SYSENTER_CS:
			hv::vmwrite(GUEST_SYSENTER_CS, msr.all);
			break;

		case IA32_SYSENTER_EIP:
			hv::vmwrite(GUEST_SYSENTER_EIP, msr.all);
			break;

		case IA32_SYSENTER_ESP:
			hv::vmwrite(GUEST_SYSENTER_ESP, msr.all);
			break;

		case IA32_S_CET:
			hv::vmwrite(GUEST_S_CET, msr.all);
			break;

		case IA32_PERF_GLOBAL_CTRL:
			hv::vmwrite(GUEST_PERF_GLOBAL_CONTROL, msr.all);
			break;

		case IA32_PKRS:
			hv::vmwrite(GUEST_PKRS, msr.all);
			break;

		case IA32_RTIT_CTL:
			hv::vmwrite(GUEST_RTIT_CTL, msr.all);
			break;

		case IA32_BNDCFGS:
			hv::vmwrite(GUEST_BNDCFGS, msr.all);
			break;

		case IA32_PAT:
			hv::vmwrite(GUEST_PAT, msr.all);
			break;

		case IA32_EFER:
			hv::vmwrite(GUEST_EFER, msr.all);
			break;

		case IA32_GS_BASE:
			hv::vmwrite(GUEST_GS_BASE, msr.all);
			break;

		case IA32_FS_BASE:
			hv::vmwrite(GUEST_FS_BASE, msr.all);
			break;

		default:
			__writemsr(msr_index, msr.all);
			break;
	}

	adjust_rip(vcpu);
}

/// <summary>
/// Ept violation handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_ept_violation_handler(__vcpu* vcpu)
{
	__ept_violation ept_violation;

	ept_violation.all = vcpu->vmexit_info.qualification;
	unsigned __int64 guest_physical_adddress = hv::vmread(GUEST_PHYSICAL_ADDRESS);

	PLIST_ENTRY current = &g_vmm_context->ept_state->hooked_page_list;
	while (&g_vmm_context->ept_state->hooked_page_list != current->Flink)
	{
		current = current->Flink;
		__ept_hooked_page_info* hooked_entry = CONTAINING_RECORD(current, __ept_hooked_page_info, hooked_page_list);
		if (hooked_entry->pfn_of_hooked_page == GET_PFN(guest_physical_adddress))
		{
			if ((ept_violation.read_access || ept_violation.write_access) && (!ept_violation.ept_readable || !ept_violation.ept_writeable)) 
				ept::swap_pml1(hooked_entry->entry_address, hooked_entry->original_entry);

			else if (ept_violation.execute_access && (ept_violation.ept_readable || ept_violation.ept_writeable))
				ept::swap_pml1(hooked_entry->entry_address, hooked_entry->changed_entry);

			break;
		}
	}
}

/// <summary>
/// Exception handler
/// </summary>
/// <param name="guest_reg"></param>
void vmexit_exception_handler(__vcpu* vcpu)
{
	__vmexit_interrupt_info interrupt_info;
	interrupt_info.all = hv::vmread(VM_EXIT_INTERRUPTION_INFORMATION);
	
	unsigned __int32 error_code = hv::vmread(VM_EXIT_INTERRUPTION_ERROR_CODE);

	// Exit Qualification contain the linear address which caused page fault
	if (interrupt_info.vector == EXCEPTION_VECTOR_PAGE_FAULT)
		__writecr2(vcpu->vmexit_info.qualification);

	hv::inject_interruption(interrupt_info.vector, interrupt_info.interruption_type, error_code, interrupt_info.error_code_valid);
}

/// <summary>
/// Cpuid handler
/// </summary>
/// <param name="guest_regs"></param>
void vmexit_cpuid_handler(__vcpu* vcpu)
{
	__cpuid_info cpuid_reg = { 0 };

	if (g_vmm_context->hv_presence == false &&
		vcpu->vmexit_info.guest_registers->rax >= 0x40000000 &&
		vcpu->vmexit_info.guest_registers->rax <= 0x4FFFFFFF)
		__cpuidex((int*)&cpuid_reg.eax, g_vmm_context->highest_basic_leaf, 0);

	else 
		__cpuidex((int*)&cpuid_reg.eax, vcpu->vmexit_info.guest_registers->rax, vcpu->vmexit_info.guest_registers->rcx);


	switch (vcpu->vmexit_info.guest_registers->rax)
	{
		case CPUID_PROCESSOR_FEATURES:
			cpuid_reg.cpuid_eax_01.feature_information_ecx.hypervisor_present = g_vmm_context->hv_presence; // Hypervisor present bit
			break;
		
		case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
			if (g_vmm_context->hv_presence == true)
			{
				cpuid_reg.eax = CPUID_HV_INTERFACE;
				cpuid_reg.ebx = 'hria';  // airhv
				cpuid_reg.ecx = 'v\x00\x00\x00';
				cpuid_reg.edx = 0;
			}
			break;

		case CPUID_HV_INTERFACE:
			if (g_vmm_context->hv_presence == true)
			{
				//
				// This indicates that our hypervisor doesn't conform to microsoft hyperv interaface
				//
				cpuid_reg.eax = '0#vH';
				cpuid_reg.ebx = cpuid_reg.ecx = cpuid_reg.edx = 0;
			}
			break;

		case CPUID_EXTENDED_FEATURES:
			if (vcpu->vmexit_info.guest_registers->rcx == 0)
				CLR_CPUID_BIT(cpuid_reg.ecx, 5); // TPAUSE UMONITOR and UWAIT are not supported
			break;
	}

	vcpu->vmexit_info.guest_registers->rax = cpuid_reg.eax;
	vcpu->vmexit_info.guest_registers->rbx = cpuid_reg.ebx;
	vcpu->vmexit_info.guest_registers->rcx = cpuid_reg.ecx;
	vcpu->vmexit_info.guest_registers->rdx = cpuid_reg.edx;

	adjust_rip(vcpu);
}

/// <summary>
/// Invpcid handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_invpcid_handler(__vcpu* vcpu) 
{
	__vmexit_instruction_information2 instruction_information = { vcpu->vmexit_info.instruction_information };

	unsigned __int64* type = &vcpu->vmexit_info.guest_registers->rax - instruction_information.reg2;

	if (*type > INVPCID_ALL_CONTEXTS_EXCEPT_GLOBAL_TRANSLATIONS)
	{
		hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
		return;
	}

	unsigned __int64 guest_address = hv::get_guest_address(vcpu);

	unsigned __int64 old_cr3 = hv::swap_context();

	if (MmGetPhysicalAddress((void*)guest_address).QuadPart == 0) 
	{
		__writecr2(guest_address);
		hv::inject_interruption(EXCEPTION_VECTOR_PAGE_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
		hv::restore_context(old_cr3);
		return;
	}

	__invpcid_descriptor descriptor;
	memcpy(&descriptor, (void*)guest_address, sizeof(descriptor));

	hv::restore_context(old_cr3);

	if(descriptor.reserved != 0)
	{
		hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
		return;
	}

	__cr4 cr4 = { __readcr4() };

	if ((*type == INVPCID_INVIDUAL_ADDRESS || *type == INVPCID_SINGLE_CONTEXT) && descriptor.pcid != 0 && cr4.pcid_enable == false)
	{
		hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
		return;
	}

	if (*type == INVPCID_INVIDUAL_ADDRESS && !hv::is_address_canonical(descriptor.linear_address))
	{
		hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
		return;
	}

	if (*type == INVPCID_INVIDUAL_ADDRESS)
		invvpid_invidual_address(descriptor.linear_address, 1);

	else if (*type == INVPCID_SINGLE_CONTEXT)
		invvpid_single_context(1);

	else if (*type == INVPCID_ALL_CONTEXTS)
		invvpid_single_context(1);

	else if (*type == INVPCID_ALL_CONTEXTS_EXCEPT_GLOBAL_TRANSLATIONS)
		invvpid_single_context_except_global_translations(1);

	adjust_rip(vcpu);
}

void vmexit_invlpg_handler(__vcpu* vcpu)
{
	invvpid_invidual_address(vcpu->vmexit_info.qualification, 1);

	adjust_rip(vcpu);
}

/// <summary>
/// Mov dr handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_mov_dr_handler(__vcpu* vcpu) 
{
	//
	// Moves the contents of a debug register (DR0, DR1, DR2, DR3, DR4, DR5, DR6, or DR7) to a general-purpose register or vice versa.
	// The operand size for these instructions is always 32 bits in non-64-bit modes, regardless of the operand-size attribute. 
	// (See Section 17.2, “Debug Registers”, of the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3A, 
	// for a detailed description of the flags and fields in the debug registers.)
	//

	//
	// Accessing dr registers from non ring 0 is forbidden
	// and cause #GP exception
	//
	if (hv::get_guest_cpl() != 0) 
	{
		hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
		return;
	}

	__exit_qualification_dr operation;
	operation.all = vcpu->vmexit_info.qualification;
	unsigned __int64* gp_register = &vcpu->vmexit_info.guest_registers->rax - operation.gp_register;

	//
	// Accessing dr register 4 or 5 when debugging extension in cr4 is on cause #UD exception
	// When debug extension is off then it's algined to dr 6 and 7
	//
	if (operation.debug_register_number == 4 || operation.debug_register_number == 5) 
	{
		__cr4 cr4;
		cr4.all = hv::vmread(GUEST_CR4);

		if (cr4.debugging_extensions == true) 
		{
			hv::inject_interruption(EXCEPTION_VECTOR_UNDEFINED_OPCODE, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, false);
			return;
		}

		operation.debug_register_number += 2;
	}

	//
	// Trying to write to 32 upper bits of dr6 or dr7 cause a #GP exception 
	//
	if ((operation.debug_register_number == 6 || operation.debug_register_number == 7) && operation.access_direction == 0 && (*gp_register >> 32) != 0) 
	{
		hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
		return;
	}

	//
	// While dr7 bit general detect is set any access to any dr register cause #DB exception
	//
	__dr7 dr7;
	dr7.all = hv::vmread(GUEST_DR7);
	if (dr7.general_detect == 1) 
	{
		__dr6 dr6;
		dr6.all = __readdr(6);
		dr6.breakpoint_condition = 0;
		dr6.debug_register_access_detected = 1;

		__writedr(6, dr6.all);

		dr7.general_detect = 0;

		hv::vmwrite<unsigned __int64>(GUEST_DR7, dr7.all);

		hv::inject_interruption(EXCEPTION_VECTOR_SINGLE_STEP, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, false);
		return;
	}

	//
	// Mov to dr
	//
	if (operation.access_direction == 0) 
	{
		switch (operation.debug_register_number)
		{
			case 0:
				__writedr(0, *gp_register);
				break;

			case 1:
				__writedr(1, *gp_register);
				break;

			case 2:
				__writedr(2, *gp_register);
				break;

			case 3:
				__writedr(3, *gp_register);
				break;

			case 6:
				__writedr(6, *gp_register);
				break;

			case 7:
				hv::vmwrite<unsigned __int64>(GUEST_DR7, *gp_register);
				break;
		}
	}

	//
	// Mov from dr
	//
	else 
	{
		switch (operation.debug_register_number)
		{
			case 0:
				*gp_register = __readdr(0);
				break;

			case 1:
				*gp_register = __readdr(1);
				break;

			case 2:
				*gp_register = __readdr(2);
				break;

			case 3:
				*gp_register = __readdr(3);
				break;

			case 6:
				*gp_register = __readdr(6);
				break;

			case 7:
				*gp_register = hv::vmread(GUEST_DR7);
				break;
		}
	}

	adjust_rip(vcpu);
}

/// <summary>
/// IO access handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_io(__vcpu* vcpu)
{
	__exit_qualification_io io_information;
	__rflags rflags = vcpu->vmexit_info.guest_rflags;

	io_information.all = vcpu->vmexit_info.qualification;

	union
	{
		unsigned __int8* byte_ptr;
		unsigned __int16* word_ptr;
		unsigned long* dword_ptr;
		unsigned __int64* qword_ptr;

		unsigned __int64 qword;
	}port_value;

	if (io_information.string_instruction == 0)
		port_value.qword_ptr = &vcpu->vmexit_info.guest_registers->rax;

	//
	// If it's ins/outs instruction we have to check if passed buffer address exists and if not inject #PF
	//
	else 
	{
		port_value.qword = io_information.direction == 0 ? vcpu->vmexit_info.guest_registers->rsi : vcpu->vmexit_info.guest_registers->rdi;
		unsigned __int64 physcial_address = MmGetPhysicalAddress((void*)port_value.qword).QuadPart;

		if (physcial_address == 0)
		{
			__writecr2(port_value.qword);
			hv::inject_interruption(EXCEPTION_VECTOR_PAGE_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
			return;
		}
	}

	unsigned __int32 count = io_information.rep == 0 ? 1 : MASK_GET_LOWER_32BITS(vcpu->vmexit_info.guest_registers->rax);

	// OUT
	if (io_information.direction == 0)
	{
		// Not string
		if (io_information.string_instruction == 0)
		{
			switch (io_information.access_size)
			{
				// 1 Byte size
			case 0:
				__outbyte(io_information.port_number, *port_value.byte_ptr);
				break;

				// 2 Byte size
			case 1:
				__outword(io_information.port_number, *port_value.word_ptr);
				break;

				// 4 Byte size
			case 3:
				__outdword(io_information.port_number, *port_value.dword_ptr);
				break;
			}
		}

		// String
		else
		{
			switch (io_information.access_size)
			{
				// 1 Byte size
			case 0:
				__outbytestring(io_information.port_number, port_value.byte_ptr, count);
				break;

				// 2 Byte size
			case 1:
				__outwordstring(io_information.port_number, port_value.word_ptr, count);
				break;

				// 4 Byte size
			case 3:
				__outdwordstring(io_information.port_number, port_value.dword_ptr, count);
				break;
			}
		}
	}

	// IN
	else
	{
		// Not string
		if (io_information.string_instruction == 0)
		{
			switch (io_information.access_size)
			{
				// 1 Byte size
			case 0:
				*port_value.byte_ptr = __inbyte(io_information.port_number);
				break;

				// 2 Byte size
			case 1:
				*port_value.word_ptr = __inword(io_information.port_number);
				break;

				// 4 Byte size
			case 3:
				*port_value.dword_ptr = __indword(io_information.port_number);
				break;
			}
		}

		// String
		else
		{
			switch (io_information.access_size)
			{
				// 1 Byte size
			case 0:
				__inbytestring(io_information.port_number, port_value.byte_ptr, count);
				break;

				// 2 Byte size
			case 1:
				__inwordstring(io_information.port_number, port_value.word_ptr, count);
				break;

				// 4 Byte size
			case 3:
				__indwordstring(io_information.port_number, port_value.dword_ptr, count);
				break;
			}
		}
	}

	if (io_information.string_instruction == 1)
	{
		if (rflags.direction_flag == 1)
			*port_value.qword_ptr -= count * io_information.access_size;

		else
			*port_value.qword_ptr += count * io_information.access_size;

		if (io_information.rep == 1)
			vcpu->vmexit_info.guest_registers->rcx = 0;
	}

	adjust_rip(vcpu);
}

/// <summary>
/// IO access handler wraper
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_io_handler(__vcpu* vcpu) 
{
	unsigned __int64 old_cr3 = hv::swap_context();
	vmexit_io(vcpu);
	hv::restore_context(old_cr3);
}

/// <summary>
/// Rdrand handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_rdrand_handler(__vcpu* vcpu)
{
	__rflags rflags = vcpu->vmexit_info.guest_rflags;
	__vmexit_instruction_information5 instruction_information;

	instruction_information.all = vcpu->vmexit_info.instruction_information;

	unsigned __int64* register_pointer = &vcpu->vmexit_info.guest_registers->rax - instruction_information.operand_register;

	//
	// Loads a hardware generated random value and store it in the destination register.
	// The size of the random value is determined by the destination register size and operating mode.
	// The Carry Flag indicates whether a random value is available at the time the instruction is executed.
	// CF=1 indicates that the data in the destination is valid. Otherwise CF=0 and the data in the destination operand 
	// will be returned as zeros for the specified width. All other flags are forced to 0 in either situation. 
	// Software must check the state of CF=1 for determining if a valid random value has been returned, 
	// otherwise it is expected to loop and retry execution of RDRAND 
	// (see Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1, Section 7.3.17, “Random Number Generator Instructions”).
	// This instruction is available at all privilege levels.
	//
	switch (instruction_information.operand_size)
	{
		case 0:
		{
			rflags.carry_flag = _rdrand16_step((unsigned __int16*)register_pointer);
			break;
		}

		case 1:
		{
			rflags.carry_flag = _rdrand32_step((unsigned __int32*)register_pointer);
			break;
		}

		case 2:
		{
			rflags.carry_flag = _rdrand64_step(register_pointer);
			break;
		}
	}

	hv::vmwrite<unsigned __int64>(GUEST_RFLAGS, rflags.all);

	adjust_rip(vcpu);
}

/// <summary>
/// Rdseed handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_rdseed_handler(__vcpu* vcpu)
{
	__rflags rflags = vcpu->vmexit_info.guest_rflags;
	__vmexit_instruction_information5 instruction_information;
	
	instruction_information.all = vcpu->vmexit_info.instruction_information;

	unsigned __int64*  register_pointer = &vcpu->vmexit_info.guest_registers->rax - instruction_information.operand_register;

	//
	// Loads a hardware generated random value and store it in the destination register.
	// The random value is generated from an Enhanced NRBG (Non Deterministic Random Bit Generator)
	// that is compliant to NIST SP800-90B and NIST SP800-90C in the XOR construction mode.
	// The size of the random value is determined by the destination register size and operating mode.
	// The Carry Flag indicates whether a random value is available at the time the instruction is executed. 
	// CF=1 indicates that the data in the destination is valid. Otherwise CF=0 and the data in the destination operand 
	// will be returned as zeros for the specified width. All other flags are forced to 0 in either situation.
	// Software must check the state of CF=1 for determining if a valid random seed value has been returned, 
	// otherwise it is expected to loop and retry execution of RDSEED (see Section 1.2).
	// The RDSEED instruction is available at all privilege levels.The RDSEED instruction executes normally either
	// inside or outside a transaction region.
	//
	switch (instruction_information.operand_size)
	{
		case 0:
		{
			rflags.carry_flag = _rdseed16_step((unsigned __int16*)register_pointer);
			break;
		}

		case 1:
		{
			rflags.carry_flag = _rdseed32_step((unsigned __int32*)register_pointer);
			break;
		}

		case 2:
		{
			rflags.carry_flag = _rdseed64_step(register_pointer);
			break;
		}
	}

	hv::vmwrite<unsigned __int64>(GUEST_RFLAGS, rflags.all);

	adjust_rip(vcpu);
}

/// <summary>
/// Handler for failed vmexit
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_failed(__vcpu* vcpu)
{
	ASSERT(FALSE);
	hv::dump_vmcs();
	KeBugCheckEx(HYPERVISOR_ERROR, 1, vcpu->vmexit_info.reason, vcpu->vmexit_info.qualification, 0);
}

/// <summary>
/// Xsetbv handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_xsetbv_handler(__vcpu* vcpu)
{
	__xcr0 new_xcr0;
	__xcr0 current_xcr0;

	unsigned __int64 xcr_number = vcpu->vmexit_info.guest_registers->rcx;

	new_xcr0.all = vcpu->vmexit_info.guest_registers->rdx << 32 | MASK_GET_LOWER_32BITS(vcpu->vmexit_info.guest_registers->rax);

	current_xcr0.all = _xgetbv(0);

	//
	// If xcr_number is higher than 0 then inject #GP
	// If value in edx:eax sets bits that are reserved in the xcr specified by ecx then inject #GP
	// If an attempt is made to clear bit 0 of xcr0 then inject #GP
	// If an attempt is made to set new_xcr0[2:1] = 0 then inject #GP
	//
	if (xcr_number > 0 || new_xcr0.x87 == 0 || 
		new_xcr0.reserved1 != current_xcr0.reserved1 || 
		new_xcr0.reserved2 != current_xcr0.reserved2 || 
		new_xcr0.reserved3 != current_xcr0.reserved3 || 
		(new_xcr0.avx == 1 && new_xcr0.sse == 0))
	{
		hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
		return;
	}

	//
	// Writes the contents of registers EDX:EAX into the 64-bit extended control register (XCR) specified in the ECX register.
	// (On processors that support the Intel 64 architecture, the high-order 32 bits of RCX are ignored.) 
	// The contents of the EDX register are copied to high-order 32 bits of the selected XCR and the contents of the EAX register are copied
	// to low-order 32 bits of the XCR. (On processors that support the Intel 64 architecture,
	// the high-order 32 bits of each of RAX and RDX are ignored.) Undefined or reserved bits in an XCR should be set to values previously read.
	// This instruction must be executed at privilege level 0 or in real - address mode; otherwise, a general protection exception #GP(0)
	// is generated.Specifying a reserved or unimplemented XCR in ECX will also cause a general protection exception.
	// The processor will also generate a general protection exception if software attempts to write to reserved bits in an XCR.
	// Currently, only XCR0 is supported.Thus, all other values of ECX are reservedand will cause a #GP(0).
	//
	_xsetbv(xcr_number, new_xcr0.all);
	adjust_rip(vcpu);
}

/// <summary>
/// Invd handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_invd_handler(__vcpu* vcpu)
{
	//
	// Invalidates (flushes) the processor’s internal caches and issues a special-function bus cycle that directs 
	// external caches to also flush themselves. Data held in internal caches is not written back to main memory.
	// After executing this instruction, the processor does not wait for the external caches to complete their flushing operation before 
	// proceeding with instruction execution.It is the responsibility of hardware to respond to the cache flush signal.
	// The INVD instruction is a privileged instruction.When the processor is running in protected mode,
	// the CPL of a program or procedure must be 0 to execute this instruction.
	// The INVD instruction may be used when the cache is used as temporary memory and the cache contents
	// need to be invalidated rather than written back to memory.When the cache is used as temporary memory,
	// no external device should be actively writing data to main memory.
	// Use this instruction with care.Data cached internally and not written back to main memory will be lost.
	// Note that any data from an external device to main memory(for example, via a PCIWrite) can be temporarily stored in the caches;
	// these data can be lost when an INVD instruction is executed.Unless there is a specific requirement or 
	// benefit to flushing caches without writing back modified cache lines(for example, temporary memory, 
	// testing, or fault recovery where cache coherency with main memory is not a concern), software should instead use the WBINVD instruction.
	//
	// tldr: We use wbinvd cause it's safer
	//
	__wbinvd();
	adjust_rip(vcpu);
}

/// <summary>
/// Rdtscp handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_rdtscp_handler(__vcpu* vcpu)
{
	//
	// Reads the current value of the processor’s time-stamp counter (a 64-bit MSR) into the EDX:EAX registers
	// and also reads the value of the IA32_TSC_AUX MSR (address C0000103H) into the ECX register.
	// The EDX register is loaded with the high-order 32 bits of the IA32_TSC MSR; 
	// the EAX register is loaded with the low-order 32 bits of the IA32_TSC MSR; 
	// and the ECX register is loaded with the low-order 32-bits of IA32_TSC_AUX MSR.
	// On processors that support the Intel 64 architecture, the high-order 32 bits of each of RAX, RDX, and RCX are cleared.
	//

	unsigned __int32 processor_id;
	unsigned __int64 tsc = __rdtscp(&processor_id);
	vcpu->vmexit_info.guest_registers->rcx = processor_id;
	vcpu->vmexit_info.guest_registers->rdx = MASK_GET_HIGHER_32BITS(tsc) >> 32;
	vcpu->vmexit_info.guest_registers->rax = MASK_GET_LOWER_32BITS(tsc);

	adjust_rip(vcpu);
}

/// <summary>
/// Handler for unimplemented cases
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_unimplemented(__vcpu* vcpu)
{
	LogError("Not implemented vmexit reason %llu, qualificaton %llu, guest rip 0x%llX", vcpu->vmexit_info.reason, vcpu->vmexit_info.qualification, vcpu->vmexit_info.guest_rip);
}

/// <summary>
/// VT-x instructions handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_vm_instruction(__vcpu* vcpu)
{
	UNREFERENCED_PARAMETER(vcpu);
	hv::inject_interruption(EXCEPTION_VECTOR_UNDEFINED_OPCODE, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, false);
}

/// <summary>
/// Triple fault handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_triple_fault_handler(__vcpu* vcpu) 
{
	//
	// Dump whole vmcs state before hard reset
	//
	UNREFERENCED_PARAMETER(vcpu);
	hv::dump_vmcs();
	ASSERT(FALSE);
	hv::hard_reset();
}

/// <summary>
/// Rdtsc handler
/// </summary>
/// <param name="guest_registers"></param>
void vmexit_rdtsc_handler(__vcpu* vcpu) 
{
	//
	// Loads the current value of the processor's time-stamp counter into the EDX:EAX registers.
	// The time-stamp counter is contained in a 64-bit MSR.
	// The high-order 32 bits of the MSR are loaded into the EDX register, and the low-order 32 bits are loaded into the EAX register.
	// The processor monotonically increments the time-stamp counter MSR every clock cycle and resets it to 0 whenever the processor is reset.
	// See "Time Stamp Counter" in Chapter 15 of the IA-32 Intel Architecture Software Developer's Manual, 
	// Volume 3 for specific details of the time stamp counter behavior.
	//

	unsigned __int64 tsc = __rdtsc();

	vcpu->vmexit_info.guest_registers->rdx = MASK_GET_HIGHER_32BITS(tsc) >> 32;
	vcpu->vmexit_info.guest_registers->rax = MASK_GET_LOWER_32BITS(tsc);

	adjust_rip(vcpu);
}

/// <summary>
/// Get rsp for leaving vmx operation
/// </summary>
/// <returns></returns>
unsigned __int64 return_rsp_for_vmxoff()
{
	return g_vmm_context->vcpu_table[KeGetCurrentProcessorNumber()]->vmx_off_state.guest_rsp;
}

/// <summary>
/// Get rip for leaving vmx operation
/// </summary>
/// <returns></returns>
unsigned __int64 return_rip_for_vmxoff()
{
	return g_vmm_context->vcpu_table[KeGetCurrentProcessorNumber()]->vmx_off_state.guest_rip;
}

void vmexit_cr_handler(__vcpu* vcpu)
{
	__cr0 guest_cr0;
	__cr3 guest_cr3;
	__cr_access_qualification operation;
	operation.all = vcpu->vmexit_info.qualification;

	unsigned __int64* register_pointer = &vcpu->vmexit_info.guest_registers->rax - operation.register_type;

	union
	{
		__cr0 cr0;
		__cr3 cr3;
		__cr4 cr4;
		unsigned __int64 all;
	}cr_registers;

	cr_registers.all = *register_pointer;

	//
	// Moves the contents of a control register (CR0, CR2, CR3, CR4, or CR8) 
	// to a general-purpose register or the contents of a general purpose register to a control register.
	// The operand size for these instructions is always 32 bits in non-64-bit modes, regardless of the operand-size attribute.
	// (See “Control Registers” in Chapter 2 of the Intel® 64 and IA-32 Architectures Software Developer’s Manual,
	// Volume 3A, for a detailed description of the flags and fields in the control registers.) 
	// This instruction can be executed only when the current privilege level is 0. 
	//
	// (We don't have to check cpl because cpu prioritizes fault based on privilege level over vm exit)
	//
	switch (operation.access_type)
	{
		case CR_ACCESS_MOV_TO_CR:
		{
			switch (operation.cr_number)
			{
				case 0:
				{
					// Any attempt to clear cr0 PG bit cause #GP
					if (cr_registers.cr0.paging_enable == 0)
					{
						hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
						return;
					}

					hv::vmwrite<unsigned __int64>(GUEST_CR0, *register_pointer);
					hv::vmwrite<unsigned __int64>(CONTROL_CR0_READ_SHADOW, *register_pointer);

					break;
				}

				case 3:
				{
					//
					// Any attempt to write a 1 to any reserved bit cause #GP
					//
					if (cr_registers.cr3.reserved_1 != 0 || cr_registers.cr3.reserved_2 != 0) 
					{
						hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
						return;
					}

					hv::vmwrite<unsigned __int64>(GUEST_CR3, (*register_pointer & ~(1ULL << 63)));

					invvpid_single_context_except_global_translations(1);
					break;
				}

				case 4:
				{
					guest_cr3.all = hv::vmread(GUEST_CR3);

					//
					// Any attempt to write a 1 to any reserved bit cause #GP or 
					// Trying to leave IA-32e mode by clearing cr pae bit cause #GP
					// Trying to change cr4 pcide from 0 to 1 while cr3[11:0] != 0 cause #GP
					//
					if (cr_registers.cr4.reserved_1 != 0 || cr_registers.cr4.reserved_2 != 0 || 
						cr_registers.cr4.reserved_3 != 0 || cr_registers.cr4.physical_address_extension == 0 ||
						(cr_registers.cr4.pcid_enable == 1 && guest_cr3.pcid != 0))
					{
						hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, true);
						return;
					}

					hv::vmwrite<unsigned __int64>(GUEST_CR4, *register_pointer);
					hv::vmwrite<unsigned __int64>(CONTROL_CR4_READ_SHADOW, *register_pointer);
					break;
				}

				default:
				{
					// We should never get here
					ASSERT(FALSE);
					break;
				}
			}

			break;
		}

		case CR_ACCESS_MOV_FROM_CR:
		{
			switch (operation.cr_number)
			{
				case 0:
				{
					*register_pointer = hv::vmread(GUEST_CR0);
					break;
				}

				case 3:
				{
					*register_pointer = hv::vmread(GUEST_CR3);
					break;
				}

				case 4:
				{
					*register_pointer = hv::vmread(GUEST_CR4);
					break;
				}

				default:
				{
					// We should never get here
					ASSERT(FALSE);
					break;
				}
			}

			break;
		}

		//
		// Clears the task-switched (TS) flag in the CR0 register. This instruction is intended for use in operating-system procedures. 
		// It is a privileged instruction that can only be executed at a CPL of 0. 
		// It is allowed to be executed in real-address mode to allow initialization for protected mode.
		// The processor sets the TS flag every time a task switch occurs.
		// The flag is used to synchronize the saving of FPU context in multitasking applications.
		// See the description of the TS flag in the section titled “Control Registers” 
		// in Chapter 2 of the Intel® 64 and IA - 32 Architectures Software Developer’s Manual, Volume 3A, for more information about this flag.
		//
		case CR_ACCESS_CLTS:
		{
			guest_cr0.all = hv::vmread(GUEST_CR0);

			guest_cr0.task_switched = 0;

			hv::vmwrite<unsigned __int64>(GUEST_CR0, guest_cr0.all);
			hv::vmwrite<unsigned __int64>(CONTROL_CR0_READ_SHADOW, guest_cr0.all);

			break;
		}

		//
		// Loads the source operand into the machine status word, bits 0 through 15 of register CR0.
		// The source operand can be a 16-bit general-purpose register or a memory location. 
		// Only the low-order 4 bits of the source operand (which contains the PE, MP, EM, and TS flags) are loaded into CR0. 
		// The PG, CD, NW, AM, WP, NE, and ET flags of CR0 are not affected. The operand-size attribute has no effect on this instruction.
		// If the PE flag of the source operand(bit 0) is set to 1, the instruction causes the processor to switch to protected mode.
		// While in protected mode, the LMSW instruction cannot be used to clear the PE flagand force a switch back to real - address mode.
		// The LMSW instruction is provided for use in operating - system software; it should not be used in application programs.
		// In protected or virtual - 8086 mode, it can only be executed at CPL 0.
		// This instruction is provided for compatibility with the Intel 286 processor
		// programs and procedures intended to run on IA - 32 and Intel 64 processors beginning with Intel386 processors should use
		// the MOV(control registers) instruction to load the whole CR0 register.The MOV CR0 instruction can be used to set and clear the PE flag
		// in CR0, allowing a procedure or program to switch between protectedand real - address modes.
		//
		case CR_ACCESS_LMSW:
		{
			// Register operand type
			if (operation.operand_type == 0) 
			{
				guest_cr0.all = hv::vmread(GUEST_CR0);

				guest_cr0.protection_enable = cr_registers.cr0.protection_enable;
				guest_cr0.monitor_coprocessor = cr_registers.cr0.monitor_coprocessor;
				guest_cr0.emulate_fpu = cr_registers.cr0.emulate_fpu;
				guest_cr0.task_switched = cr_registers.cr0.task_switched;

				hv::vmwrite<unsigned __int64>(GUEST_CR0, guest_cr0.all);
				hv::vmwrite<unsigned __int64>(CONTROL_CR0_READ_SHADOW, guest_cr0.all);
			}

			// Memory operand type
			else if (operation.operand_type == 1) 
			{
				guest_cr0.all = hv::vmread(GUEST_CR0);

				cr_registers.all = operation.source_data;

				guest_cr0.protection_enable = cr_registers.cr0.protection_enable;
				guest_cr0.monitor_coprocessor = cr_registers.cr0.monitor_coprocessor;
				guest_cr0.emulate_fpu = cr_registers.cr0.emulate_fpu;
				guest_cr0.task_switched = cr_registers.cr0.task_switched;

				hv::vmwrite<unsigned __int64>(GUEST_CR0, guest_cr0.all);
				hv::vmwrite<unsigned __int64>(CONTROL_CR0_READ_SHADOW, guest_cr0.all);
			}

			else 
			{
				// We should never get here
				ASSERT(FALSE);
			}

			break;
		}

		default: 
		{
			// We should never get here
			ASSERT(FALSE);
			break;
		}

	}

	adjust_rip(vcpu);
}

/// <summary>
/// Vm exit dispatcher
/// </summary>
/// <param name="guest_registers"></param>
/// <returns> status </returns>
bool vmexit_handler(__vmexit_guest_registers* guest_registers)
{
	__vcpu* vcpu = g_vmm_context->vcpu_table[KeGetCurrentProcessorNumber()];

	guest_registers->rsp = hv::vmread(GUEST_RSP);

	vcpu->vmexit_info.reason = hv::vmread(EXIT_REASON) & 0xffff;
	vcpu->vmexit_info.qualification = hv::vmread(EXIT_QUALIFICATION);
	vcpu->vmexit_info.guest_rflags.all = hv::vmread(GUEST_RFLAGS);
	vcpu->vmexit_info.guest_rip = hv::vmread(GUEST_RIP);
	vcpu->vmexit_info.instruction_length = hv::vmread(VM_EXIT_INSTRUCTION_LENGTH);
	vcpu->vmexit_info.instruction_information = hv::vmread(VM_EXIT_INSTRUCTION_INFORMATION);
	vcpu->vmexit_info.guest_registers = guest_registers;

	//
	//  Instructions That Cause VM Exits Unconditionally
	//  The following instructions cause VM exits when they are executed in VMX non - root operation : CPUID, GETSEC,
	//  INVD, and XSETBV.This is also true of instructions introduced with VMX, which include : INVEPT, INVVPID,
	//  VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
	//
	exit_handlers[vcpu->vmexit_info.reason](vcpu);

	if (vcpu->vmx_off_state.vmx_off_executed == 1)
	{
		vcpu->vcpu_status.vmm_launched = 0;
		return false;
	}

	return true;
}

/// <summary>
/// Add to guest rip size of instruction which he executed
/// </summary>
void adjust_rip(__vcpu* vcpu)
{
	hv::vmwrite(GUEST_RIP, vcpu->vmexit_info.guest_rip + vcpu->vmexit_info.instruction_length);
	if (vcpu->vmexit_info.guest_rflags.trap_flag)
	{
		__vmx_pending_debug_exceptions pending_debug = { hv::vmread(GUEST_PENDING_DEBUG_EXCEPTION) };
		__vmx_interruptibility_state interruptibility = { hv::vmread(GUEST_INTERRUPTIBILITY_STATE) };

		pending_debug.bs = true;
		hv::vmwrite(GUEST_PENDING_DEBUG_EXCEPTION, pending_debug.all);

		interruptibility.blocking_by_sti = false;
		interruptibility.blocking_by_mov_ss = false;
		hv::vmwrite(GUEST_INTERRUPTIBILITY_STATE, interruptibility.all);
	}
}