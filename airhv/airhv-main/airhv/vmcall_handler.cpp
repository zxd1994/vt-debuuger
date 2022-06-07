#pragma warning( disable : 4201 4244 4805 4189)

#include <intrin.h>
#include "common.h"
#include "vmcall_handler.h"
#include "asm\vm_intrin.h"
#include "vmcall_reason.h"
#include "ia32\vmcs_encodings.h"
#include "ia32\msr.h"
#include "ia32\cr.h"
#include "vmexit_handler.h"
#include "hypervisor_routines.h"
#include "interrupt.h"

void restore_segment_registers()
{
	__writemsr(IA32_FS_BASE, hv::vmread(GUEST_FS_BASE));
	__writemsr(IA32_GS_BASE, hv::vmread(GUEST_GS_BASE));
	__reload_gdtr(hv::vmread(GUEST_GDTR_BASE), hv::vmread(GUEST_GDTR_LIMIT));
	__reload_idtr(hv::vmread(GUEST_IDTR_BASE), hv::vmread(GUEST_IDTR_LIMIT));
}

void call_vmxoff(__vcpu* vcpu)
{
	__writecr3(hv::vmread(GUEST_CR3));

	vcpu->vmx_off_state.guest_rip = vcpu->vmexit_info.guest_rip + vcpu->vmexit_info.instruction_length;
	vcpu->vmx_off_state.guest_rsp = vcpu->vmexit_info.guest_registers->rsp;
	vcpu->vmx_off_state.vmx_off_executed = true;

	restore_segment_registers();

	__vmx_off();

	__writecr4(__readcr4() & (~0x2000));
}

void vmexit_vmcall_handler(__vcpu* vcpu) 
{
	bool status = true;
	unsigned __int64 vmcall_reason = vcpu->vmexit_info.guest_registers->rcx;
	unsigned __int64 vmcall_parameter1 = vcpu->vmexit_info.guest_registers->rdx;
	unsigned __int64 vmcall_parameter2 = vcpu->vmexit_info.guest_registers->r8;
	unsigned __int64 vmcall_parameter3 = vcpu->vmexit_info.guest_registers->r9;

	//
	// These only if __vmcall_ex was called
	//
	unsigned __int64 vmcall_parameter4 = vcpu->vmexit_info.guest_registers->r10;
	unsigned __int64 vmcall_parameter5 = vcpu->vmexit_info.guest_registers->r11;
	unsigned __int64 vmcall_parameter6 = vcpu->vmexit_info.guest_registers->r12;
	unsigned __int64 vmcall_parameter7 = vcpu->vmexit_info.guest_registers->r13;
	unsigned __int64 vmcall_parameter8 = vcpu->vmexit_info.guest_registers->r14;
	unsigned __int64 vmcall_parameter9 = vcpu->vmexit_info.guest_registers->r15;

	//
	// Check if this vmcall belongs to us
	//
	if (vcpu->vmexit_info.guest_registers->rax != VMCALL_IDENTIFIER)
	{
		vcpu->vmexit_info.guest_registers->rax = __hyperv_vm_call(vcpu->vmexit_info.guest_registers->rcx, vcpu->vmexit_info.guest_registers->rdx, vcpu->vmexit_info.guest_registers->r8);
		return;
	}

	if (hv::get_guest_cpl() != 0) 
	{
		hv::inject_interruption(EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT, INTERRUPT_TYPE_HARDWARE_EXCEPTION, 0, 1);
		return;
	}

	switch (vmcall_reason)
	{
		case VMCALL_TEST:
		{
			adjust_rip(vcpu);
			break;
		}

		case VMCALL_VMXOFF:
		{
			call_vmxoff(vcpu);
			break;
		}

		case VMCALL_EPT_HOOK_FUNCTION:
		{
			 unsigned __int64 old_cr3 = hv::swap_context();

			status = ept::hook_function((void*)vmcall_parameter1, (void*)vmcall_parameter2, (void*)vmcall_parameter3, (void**)vmcall_parameter4);

			hv::restore_context(old_cr3);

			adjust_rip(vcpu);
			break;
		}

		case VMCALL_EPT_UNHOOK_FUNCTION:
		{
			unsigned __int64 old_cr3 = hv::swap_context();

			// If set unhook all pages
			if (vmcall_parameter1 == true)
			{
				ept::unhook_all_functions();
			}

			else
			{
				// Page physciall address
				status = ept::unhook_function(vmcall_parameter2);
			}

			hv::restore_context(old_cr3);

			adjust_rip(vcpu);
			break;
		}

		case VMCALL_INVEPT_CONTEXT:
		{
			// If set invept all contexts
			if (vmcall_parameter1 == true)
			{
				invept_all_contexts();
			}

			else 
			{
				invept_single_context(g_vmm_context->ept_state->ept_pointer->all);
			}

			adjust_rip(vcpu);
			break;
		}

		case VMCALL_DUMP_POOL_MANAGER:
		{
			pool_manager::dump_pools_info();
			adjust_rip(vcpu);
			break;
		}

		case VMCALL_DUMP_VMCS_STATE:
		{
			hv::dump_vmcs();
			adjust_rip(vcpu);
			break;
		}

		case VMCALL_HIDE_HV_PRESENCE:
		{
			g_vmm_context->hv_presence = false;
			adjust_rip(vcpu);
			break;
		}

		case VMCALL_UNHIDE_HV_PRESENCE:
		{
			g_vmm_context->hv_presence = true;
			adjust_rip(vcpu);
			break;
		}
	}

	vcpu->vmexit_info.guest_registers->rax = status;
}