#pragma warning( disable : 4201 4244)
#include <intrin.h>
#include "ia32\segment.h"
#include "common.h"
#include "ia32\vmcs.h"
#include "ia32\vmcs_encodings.h"
#include "ia32\msr.h"
#include "asm\vm_intrin.h"
#include "asm\vm_context.h"
#include "ia32\cr.h"
#include "log.h"
#include "hypervisor_routines.h"
/// <summary>
/// Derived from Intel Manuals Voulme 3 Section 24.6.2 Table 24-6. Definitions of Primary Processor-Based VM-Execution Controls
/// </summary>
/// <param name="primary_controls"></param>
void set_primary_controls(__vmx_primary_processor_based_control& primary_controls) 
{
	/**
	* If this control is 1, a VM exit occurs at the beginning of any instruction if RFLAGS.IF = 1 and
	* there are no other blocking of interrupts (see Section 24.4.2).
	*/
	primary_controls.interrupt_window_exiting = false;

	/**
	* This control determines whether executions of RDTSC, executions of RDTSCP, and executions
	* of RDMSR that read from the IA32_TIME_STAMP_COUNTER MSR return a value modified by
	* the TSC offset field (see Section 24.6.5 and Section 25.3).
	*/
	primary_controls.use_tsc_offsetting = false;

	/**
	* This control determines whether executions of HLT cause VM exits.
	*/
	primary_controls.hlt_exiting = false;

	/**
	* This determines whether executions of INVLPG cause VM exits.
	*/

#ifdef _MINIMAL
	primary_controls.invldpg_exiting = false;
#else
	primary_controls.invldpg_exiting = true;
#endif

	/**
	* This control determines whether executions of MWAIT cause VM exits.
	*/
	primary_controls.mwait_exiting = false;

	/**
	* This control determines whether executions of RDPMC cause VM exits.
	*/
	primary_controls.rdpmc_exiting = false;

	/**
	* This control determines whether executions of RDTSC and RDTSCP cause VM exits.
	*/
#ifdef _MINIMAL
	primary_controls.rdtsc_exiting = false;
#else
	primary_controls.rdtsc_exiting = true;
#endif

	/**
	* In conjunction with the CR3-target controls (see Section 24.6.7), this control determines
	* whether executions of MOV to CR3 cause VM exits. See Section 25.1.3.
	* The first processors to support the virtual-machine extensions supported only the 1-setting
	* of this control.
	*/
#ifdef _MINIMAL
	primary_controls.cr3_load_exiting = false;
#else
	primary_controls.cr3_load_exiting = true;
#endif

	/**
	* This control determines whether executions of MOV from CR3 cause VM exits.
	* The first processors to support the virtual-machine extensions supported only the 1-setting
	* of this control.
	*/
#ifdef _MINIMAL
	primary_controls.cr3_store_exiting = false;
#else
	primary_controls.cr3_store_exiting = true;
#endif

	/**
	* This control determines whether executions of MOV to CR8 cause VM exits.
	*/
	primary_controls.cr8_load_exiting = false;

	/**
	* This control determines whether executions of MOV from CR8 cause VM exits.
	*/
	primary_controls.cr8_store_exiting = false;

	/**
	* Setting this control to 1 enables TPR virtualization and other APIC-virtualization features. See
	* Chapter 29.
	*/
	primary_controls.use_tpr_shadow = false;

	/**
	* If this control is 1, a VM exit occurs at the beginning of any instruction if there is no virtual-
	* NMI blocking (see Section 24.4.2).
	*/
	primary_controls.nmi_window_exiting = false;

	/**
	* This control determines whether executions of MOV DR cause VM exits.
	*/
#ifdef _MINIMAL
	primary_controls.mov_dr_exiting = false;
#else
	primary_controls.mov_dr_exiting = true;
#endif

	/**
	* This control determines whether executions of I/O instructions (IN, INS/INSB/INSW/INSD, OUT,
	* and OUTS/OUTSB/OUTSW/OUTSD) cause VM exits.
	*/
	primary_controls.unconditional_io_exiting = false;

	/**
	* This control determines whether I/O bitmaps are used to restrict executions of I/O instructions
	(see Section 24.6.4 and Section 25.1.3).
	For this control, “0” means “do not use I/O bitmaps” and “1” means “use I/O bitmaps.” If the I/O
	bitmaps are used, the setting of the “unconditional I/O exiting” control is ignored
	*/
#ifdef _MINIMAL
	primary_controls.use_io_bitmaps = false;
#else
	primary_controls.use_io_bitmaps = true;
#endif

	/**
	* If this control is 1, the monitor trap flag debugging feature is enabled. See Section 25.5.2.
	*/
	primary_controls.monitor_trap_flag = false;

	/**
	* This control determines whether MSR bitmaps are used to control execution of the RDMSR
	* and WRMSR instructions (see Section 24.6.9 and Section 25.1.3).
	* For this control, “0” means “do not use MSR bitmaps” and “1” means “use MSR bitmaps.” If the
	* MSR bitmaps are not used, all executions of the RDMSR and WRMSR instructions cause
	* VM exits.
	*/
	primary_controls.use_msr_bitmaps = true;

	/**
	* This control determines whether executions of MONITOR cause VM exits.
	*/
	primary_controls.monitor_exiting = false;

	/**
	* This control determines whether executions of PAUSE cause VM exits.
	*/
	primary_controls.pause_exiting = false;

	/**
	* This control determines whether the secondary processor-based VM-execution controls are
	* used. If this control is 0, the logical processor operates as if all the secondary processor-based
	* VM-execution controls were also 0.
	*/
	primary_controls.active_secondary_controls = true;
}

/// <summary>
/// Derived from Intel Manuals Voulme 3 Section 24.6.2 Table 24-7. Definitions of Secondary Processor-Based VM-Execution Controls
/// </summary>
/// <param name="secondary_controls"></param>
void set_secondary_controls(__vmx_secondary_processor_based_control& secondary_controls) 
{
	/**
	* If this control is 1, the logical processor treats specially accesses to the page with the APIC-
	* access address. See Section 29.4.
	*/
	secondary_controls.virtualize_apic_accesses = false;

	/**
	* If this control is 1, extended page tables (EPT) are enabled. See Section 28.2.
	*/
	secondary_controls.enable_ept = true;

	/**
	* This control determines whether executions of LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, and
	* STR cause VM exits.
	*/
#ifdef _MINIMAL
	secondary_controls.descriptor_table_exiting = false;
#else
	secondary_controls.descriptor_table_exiting = true;
#endif

	/**
	* If this control is 0, any execution of RDTSCP causes an invalid-opcode exception (#UD).
	*/
	secondary_controls.enable_rdtscp = true;

	/**
	* If this control is 1, the logical processor treats specially RDMSR and WRMSR to APIC MSRs (in
	* the range 800H–8FFH). See Section 29.5.
	*/
	secondary_controls.virtualize_x2apic = false;

	/**
	* If this control is 1, cached translations of linear addresses are associated with a virtual-
	* processor identifier (VPID). See Section 28.1.
	*/
	secondary_controls.enable_vpid = true;

	/**
	* This control determines whether executions of WBINVD cause VM exits.
	*/
#ifdef _MINIMAL
	secondary_controls.wbinvd_exiting = false;
#else
	secondary_controls.wbinvd_exiting = true;
#endif

	/**
	* This control determines whether guest software may run in unpaged protected mode or in real-
	* address mode.
	*/
	secondary_controls.unrestricted_guest = false;

	/**
	* If this control is 1, the logical processor virtualizes certain APIC accesses. See Section 29.4 and
	* Section 29.5.
	*/
	secondary_controls.apic_register_virtualization = false;

	/**
	* This controls enables the evaluation and delivery of pending virtual interrupts as well as the
	* emulation of writes to the APIC registers that control interrupt prioritization.
	*/
	secondary_controls.virtual_interrupt_delivery = false;

	/**
	* This control determines whether a series of executions of PAUSE can cause a VM exit (see
	* Section 24.6.13 and Section 25.1.3).
	*/
	secondary_controls.pause_loop_exiting = false;

	/**
	* This control determines whether executions of RDRAND cause VM exits.
	*/
#ifdef _MINIMAL
	secondary_controls.rdrand_exiting = false;
#else
	secondary_controls.rdrand_exiting = true;
#endif

	/**
	* If this control is 0, any execution of INVPCID causes a #UD.
	*/
	secondary_controls.enable_invpcid = true;

	/**
	* Setting this control to 1 enables use of the VMFUNC instruction in VMX non-root operation. See
	* Section 25.5.6.
	*/
	secondary_controls.enable_vmfunc = false;

	/**
	* If this control is 1, executions of VMREAD and VMWRITE in VMX non-root operation may access
	* a shadow VMCS (instead of causing VM exits). See Section 24.10 and Section 30.3.
	*/
	secondary_controls.vmcs_shadowing = false;

	/**
	* If this control is 1, executions of ENCLS consult the ENCLS-exiting bitmap to determine whether
	* the instruction causes a VM exit. See Section 24.6.16 and Section 25.1.3.
	*/
	secondary_controls.enable_encls_exiting = false;

	/**
	* This control determines whether executions of RDSEED cause VM exits.
	*/
#ifdef _MINIMAL
	secondary_controls.rdseed_exiting = false;
#else
	secondary_controls.rdseed_exiting = true;
#endif

	/**
	* If this control is 1, an access to a guest-physical address that sets an EPT dirty bit first adds an
	* entry to the page-modification log. See Section 28.2.6.
	*/
	secondary_controls.enable_pml = false;

	/**
	* If this control is 1, EPT violations may cause virtualization exceptions (#VE) instead of VM exits.
	* See Section 25.5.7.
	*/
	secondary_controls.use_virtualization_exception = false;

	/**
	* If this control is 1, Intel Processor Trace suppresses from PIPs an indication that the processor
	* was in VMX non-root operation and omits a VMCS packet from any PSB+ produced in VMX non-
	* root operation (see Chapter 35).
	*/
	secondary_controls.conceal_vmx_from_pt = true;

	/**
	* If this control is 0, any execution of XSAVES or XRSTORS causes a #UD.
	*/
	secondary_controls.enable_xsave_xrstor = true;

	/**
	* If this control is 1, EPT execute permissions are based on whether the linear address being
	* accessed is supervisor mode or user mode. See Chapter 28.
	*/
	secondary_controls.mode_based_execute_control_ept = false;

	/**
	* This control determines whether executions of RDTSC, executions of RDTSCP, and executions
	* of RDMSR that read from the IA32_TIME_STAMP_COUNTER MSR return a value modified by the
	* TSC multiplier field (see Section 24.6.5 and Section 25.3).
	*/
	secondary_controls.sub_page_write_permission_for_ept = false;

	/**
	* This control determines whether executions of RDTSC, executions of RDTSCP, and executions
	* of RDMSR that read from the IA32_TIME_STAMP_COUNTER MSR return a value modified by the
	* TSC multiplier field (see Section 24.6.5 and Section 25.3).
	*/
	secondary_controls.intel_pt_uses_guest_physical_address = false;

	/**
	* This control determines whether executions of RDTSC, executions of RDTSCP, and executions
	* of RDMSR that read from the IA32_TIME_STAMP_COUNTER MSR return a value modified by the
	* TSC multiplier field (see Section 24.6.5 and Section 25.3).
	*/
	secondary_controls.use_tsc_scaling = false;

	/**
	* If this control is 0, any execution of TPAUSE, UMONITOR, or UMWAIT causes a #UD.
	*/
	secondary_controls.enable_user_wait_and_pause = false;

	/**
	* If this control is 1, executions of ENCLV consult the ENCLV-exiting bitmap to determine whether
	* the instruction causes a VM exit. See Section 24.6.17 and Section 25.1.3.
	*/
	secondary_controls.enable_enclv_exiting = false;
}

/// <summary>
/// Derived from Intel Manuals Voulme 3 Section 24.8.1 Table 24-13. Definitions of VM-Entry Controls
/// </summary>
/// <param name="entry_control"></param>
void set_entry_control(__vmx_entry_control& entry_control) 
{
	/**
	* This control determines whether DR7 and the IA32_DEBUGCTL MSR are loaded on VM entry.
	* The first processors to support the virtual-machine extensions supported only the 1-setting of
	* this control.
	*/
	entry_control.load_dbg_controls = true;

	/**
	* On processors that support Intel 64 architecture, this control determines whether the logical
	* processor is in IA-32e mode after VM entry. Its value is loaded into IA32_EFER.LMA as part of
	* VM entry. 1
	* This control must be 0 on processors that do not support Intel 64 architecture.
	*/
	entry_control.ia32e_mode_guest = true;

	/**
	* This control determines whether the logical processor is in system-management mode (SMM)
	* after VM entry. This control must be 0 for any VM entry from outside SMM.
	*/
	entry_control.entry_to_smm = false;

	/**
	* If set to 1, the default treatment of SMIs and SMM is in effect after the VM entry (see Section
	* 34.15.7). This control must be 0 for any VM entry from outside SMM.
	*/
	entry_control.deactivate_dual_monitor_treament = false;

	/**
	* This control determines whether the IA32_PERF_GLOBAL_CTRL MSR is loaded on VM entry.
	*/
	entry_control.load_ia32_perf_global_control = false;

	/**
	* This control determines whether the IA32_PAT MSR is loaded on VM entry.
	*/
	entry_control.load_ia32_pat = false;

	/**
	* This control determines whether the IA32_EFER MSR is loaded on VM entry.
	*/
	entry_control.load_ia32_efer = false;

	/**
	* This control determines whether the IA32_BNDCFGS MSR is loaded on VM entry.
	*/
	entry_control.load_ia32_bndcfgs = false;

	/**
	* If this control is 1, Intel Processor Trace does not produce a paging information packet (PIP) on
	* a VM entry or a VMCS packet on a VM entry that returns from SMM (see Chapter 35).
	*/
	entry_control.conceal_vmx_from_pt = true;

	/**
	* This control determines whether the IA32_RTIT_CTL MSR is loaded on VM entry.
	*/
	entry_control.load_ia32_rtit_ctl = false;

	/**
	* This control determines whether CET-related MSRs and SPP are loaded on VM entry.
	*/
	entry_control.load_cet_state = false;

	/**
	* This control determines whether CET-related MSRs and SPP are loaded on VM entry.
	*/
	entry_control.load_pkrs = false;
}

/// <summary>
/// Derived from Intel Manuals Voulme 3 Section 24.7.1 Table 24-11. Definitions of VM-Exit Controls
/// </summary>
/// <param name="exit_control"></param>
void set_exit_control(__vmx_exit_control& exit_control) 
{
	/**
	* This control determines whether DR7 and the IA32_DEBUGCTL MSR are saved on VM exit.
	* The first processors to support the virtual-machine extensions supported only the 1-
	* setting of this control.
	*/
	exit_control.save_dbg_controls = true;

	/**
	* On processors that support Intel 64 architecture, this control determines whether a logical
	* processor is in 64-bit mode after the next VM exit. Its value is loaded into CS.L,
	* IA32_EFER.LME, and IA32_EFER.LMA on every VM exit. 1
	* This control must be 0 on processors that do not support Intel 64 architecture.
	*/
	exit_control.host_address_space_size = true;

	/**
	* This control determines whether the IA32_PERF_GLOBAL_CTRL MSR is loaded on VM exit.
	*/
	exit_control.load_ia32_perf_global_control = false;

	/**
	* This control affects VM exits due to external interrupts:
	* • If such a VM exit occurs and this control is 1, the logical processor acknowledges the
	*   interrupt controller, acquiring the interrupt’s vector. The vector is stored in the VM-exit
	*   interruption-information field, which is marked valid.
	* • If such a VM exit occurs and this control is 0, the interrupt is not acknowledged and the
	*   VM-exit interruption-information field is marked invalid.
	*/
	exit_control.ack_interrupt_on_exit = true;

	/**
	* This control determines whether the IA32_PAT MSR is saved on VM exit.
	*/
	exit_control.save_ia32_pat = false;

	/**
	* This control determines whether the IA32_PAT MSR is loaded on VM exit.
	*/
	exit_control.load_ia32_pat = false;

	/**
	* This control determines whether the IA32_EFER MSR is saved on VM exit.
	*/
	exit_control.save_ia32_efer = false;	

	/**
	* This control determines whether the IA32_EFER MSR is loaded on VM exit.
	*/
	exit_control.load_ia32_efer = false;

	/**
	* This control determines whether the value of the VMX-preemption timer is saved on
	* VM exit.
	*/
	exit_control.save_vmx_preemption_timer_value = false;

	/**
	* This control determines whether the IA32_BNDCFGS MSR is cleared on VM exit.
	*/
	exit_control.clear_ia32_bndcfgs = false;

	/**
	* If this control is 1, Intel Processor Trace does not produce a paging information packet (PIP)
	* on a VM exit or a VMCS packet on an SMM VM exit (see Chapter 35).
	*/
	exit_control.conceal_vmx_from_pt = true;

	/**
	* This control determines whether the IA32_RTIT_CTL MSR is cleared on VM exit.
	*/
	exit_control.load_ia32_rtit_ctl = false;

	/**
	* This control determines whether CET-related MSRs and SPP are loaded on VM exit.
	*/
	exit_control.load_cet_state = false;

	/**
	* This control determines whether the IA32_PKRS MSR is loaded on VM exit.
	*/
	exit_control.load_pkrs = false;
}

/// <summary>
/// Derived from Intel Manuals Voulme 3 Section 24.6.1 Table 24-5. Definitions of Pin-Based VM-Execution Controls
/// </summary>
/// <param name="pinbased_controls"></param>
void set_pinbased_control_msr(__vmx_pinbased_control_msr& pinbased_controls) 
{
	/**
	* If this control is 1, external interrupts cause VM exits. Otherwise, they are delivered normally
	* through the guest interrupt-descriptor table (IDT). If this control is 1, the value of RFLAGS.IF
	* does not affect interrupt blocking.
	*/
	pinbased_controls.external_interrupt_exiting = false;

	/**
	* If this control is 1, non-maskable interrupts (NMIs) cause VM exits. Otherwise, they are
	* delivered normally using descriptor 2 of the IDT. This control also determines interactions
	* between IRET and blocking by NMI (see Section 25.3).
	*/
	pinbased_controls.nmi_exiting = false;

	/**
	* If this control is 1, NMIs are never blocked and the “blocking by NMI” bit (bit 3) in the
	* interruptibility-state field indicates “virtual-NMI blocking” (see Table 24-3). This control also
	* interacts with the “NMI-window exiting” VM-execution control (see Section 24.6.2).
	*/
	pinbased_controls.virtual_nmis = false;

	/**
	* If this control is 1, the VMX-preemption timer counts down in VMX non-root operation; see
	* Section 25.5.1. A VM exit occurs when the timer counts down to zero; see Section 25.2.
	*/
	pinbased_controls.vmx_preemption_timer = false;

	/**
	* If this control is 1, the processor treats interrupts with the posted-interrupt notification vector
	* (see Section 24.6.8) specially, updating the virtual-APIC page with posted-interrupt requests
	* (see Section 29.6).
	*/
	pinbased_controls.process_posted_interrupts = false;
}

/// <summary>
/// Set which exception cause vmexit
/// </summary>
/// <param name="exception_bitmap"></param>
void set_exception_bitmap(__exception_bitmap& exception_bitmap)
{
	exception_bitmap.divide_error = false;

	exception_bitmap.debug = false;

	exception_bitmap.nmi_interrupt = false;

	exception_bitmap.breakpoint = false;

	exception_bitmap.overflow = false;

	exception_bitmap.bound = false;

	exception_bitmap.invalid_opcode = false;

	exception_bitmap.coprocessor_segment_overrun = false;

	exception_bitmap.invalid_tss = false;

	exception_bitmap.segment_not_present = false;

	exception_bitmap.stack_segment_fault = false;

	exception_bitmap.general_protection = false;

	exception_bitmap.page_fault = false;

	exception_bitmap.x87_floating_point_error = false;

	exception_bitmap.alignment_check = false;

	exception_bitmap.machine_check = false;

	exception_bitmap.simd_floating_point_error = false;

	exception_bitmap.virtualization_exception = false;
}


/// <summary>
/// Get segment base
/// </summary>
/// <param name="selector"></param>
/// <param name="gdt_base"></param>
/// <returns></returns>
unsigned __int64 get_segment_base(unsigned __int16 selector, unsigned __int8* gdt_base)
{
	__segment_descriptor* segment_descriptor;

	segment_descriptor = (__segment_descriptor*)(gdt_base + (selector & ~0x7));

	unsigned __int64 segment_base = segment_descriptor->base_low | segment_descriptor->base_middle << 16 | segment_descriptor->base_high << 24;

	if (segment_descriptor->descriptor_type == false)
		segment_base = (segment_base & MASK_32BITS) | (unsigned __int64)segment_descriptor->base_upper << 32;

	return segment_base;
}

/// <summary>
/// Fill the guest's selector data
/// </summary>
/// <param name="gdt_base"></param>
/// <param name="segment_register"></param>
/// <param name="selector"></param>
void fill_guest_selector_data(void* gdt_base, unsigned __int32 segment_register, unsigned __int16 selector)
{
	__segment_access_rights segment_access_rights;
	__segment_descriptor* segment_descriptor;

	if (selector & 0x4)
		return;

	segment_descriptor = (__segment_descriptor*)((unsigned __int8*)gdt_base + (selector & ~0x7));

	unsigned __int64 segment_base = segment_descriptor->base_low | segment_descriptor->base_middle << 16 | segment_descriptor->base_high << 24;

	unsigned __int32 segment_limit = segment_descriptor->limit_low | (segment_descriptor->segment_limit_high << 16);

	//
	// Load ar get access rights of descriptor specified by selector
	// Lower 8 bits are zeroed so we have to bit shift it to right by 8
	//
	segment_access_rights.all = __load_ar(selector) >> 8;
	segment_access_rights.unusable = 0;
	segment_access_rights.reserved0 = 0;
	segment_access_rights.reserved1 = 0;

	// This is a TSS or callgate etc, save the base high part
	if (segment_descriptor->descriptor_type == false)
		segment_base = (segment_base & MASK_32BITS) | (unsigned __int64)segment_descriptor->base_upper << 32;

	if (segment_descriptor->granularity == true)
		segment_limit = (segment_limit << 12) + 0xfff;

	if (selector == 0)
		segment_access_rights.all |= 0x10000;

	hv::vmwrite<unsigned __int64>(GUEST_ES_SELECTOR + segment_register * 2, selector);
	hv::vmwrite<unsigned __int64>(GUEST_ES_LIMIT + segment_register * 2, segment_limit);
	hv::vmwrite<unsigned __int64>(GUEST_ES_BASE + segment_register * 2, segment_base);
	hv::vmwrite<unsigned __int64>(GUEST_ES_ACCESS_RIGHTS + segment_register * 2, segment_access_rights.all);
}

unsigned __int32 ajdust_controls(unsigned __int32 ctl, unsigned __int32 msr)
{
	__msr msr_value = { 0 };
	msr_value.all = __readmsr(msr);
	ctl &= msr_value.high;
	ctl |= msr_value.low;
	return ctl;
}

/// <summary>
/// Set the vmcs structure
/// </summary>
/// <param name="vcpu"></param>
/// <param name="guest_rsp"></param>
void fill_vmcs(__vcpu* vcpu, void* guest_rsp)
{
	__pseudo_descriptor64 gdtr = { 0 };
	__pseudo_descriptor64 idtr = { 0 };
	__exception_bitmap exception_bitmap = { 0 };
	__vmx_basic_msr vmx_basic = { 0 };
	__vmx_entry_control entry_controls = { 0 };
	__vmx_exit_control exit_controls = { 0 };
	__vmx_pinbased_control_msr pinbased_controls = { 0 };
	__vmx_primary_processor_based_control primary_controls = { 0 };
	__vmx_secondary_processor_based_control secondary_controls = { 0 };

	const unsigned __int8 selector_mask = 7;

	vmx_basic.all = __readmsr(IA32_VMX_BASIC);

	set_entry_control(entry_controls);

	set_exit_control(exit_controls);

	set_primary_controls(primary_controls);

	set_secondary_controls(secondary_controls);

	set_exception_bitmap(exception_bitmap);

	set_pinbased_control_msr(pinbased_controls);

	//
	// We want to vmexit on every io and msr access
	memset(vcpu->vcpu_bitmaps.io_bitmap_a, 0xff, PAGE_SIZE);
	memset(vcpu->vcpu_bitmaps.io_bitmap_b, 0xff, PAGE_SIZE);

#ifndef _MINIMAL
	memset(vcpu->vcpu_bitmaps.msr_bitmap, 0xff, PAGE_SIZE);
#endif

	//
	// Msr bitmap controls which operation on which msr
	// in range of 0x00000000 to 0x00001FFF or 
	// in range of 0xC0000000 to 0xC0001FFF cause a vmexit

	//
	// Set single msr
	//hv::set_msr_bitmap(0xC0000000, vcpu, true, true, true);

	//
	// Only if your upper hypervisor is vmware
	// Because Vmware tools use ports 0x5655,0x5656,0x5657,0x5658,0x5659,0x565a,0x565b,0x1090,0x1094 as I/O backdoor
	hv::set_io_bitmap(0x5655, vcpu, false);
	hv::set_io_bitmap(0x5656, vcpu, false);
	hv::set_io_bitmap(0x5657, vcpu, false);
	hv::set_io_bitmap(0x5658, vcpu, false);
	hv::set_io_bitmap(0x5659, vcpu, false);
	hv::set_io_bitmap(0x565a, vcpu, false);
	hv::set_io_bitmap(0x565b, vcpu, false);
	hv::set_io_bitmap(0x1094, vcpu, false);
	hv::set_io_bitmap(0x1090, vcpu, false);

	__vmx_vmclear((unsigned __int64*)&vcpu->vmcs_physical);
	__vmx_vmptrld((unsigned __int64*)&vcpu->vmcs_physical);

	__sgdt(&gdtr);
	__sidt(&idtr);

	// Global descriptor table and local one
	hv::vmwrite<unsigned __int64>(GUEST_GDTR_LIMIT, gdtr.limit);
	hv::vmwrite<unsigned __int64>(GUEST_IDTR_LIMIT, idtr.limit);
	hv::vmwrite<unsigned __int64>(GUEST_GDTR_BASE, gdtr.base_address);
	hv::vmwrite<unsigned __int64>(GUEST_IDTR_BASE, idtr.base_address);
	hv::vmwrite<unsigned __int64>(HOST_GDTR_BASE, gdtr.base_address);
	hv::vmwrite<unsigned __int64>(HOST_IDTR_BASE, idtr.base_address);

	// Hypervisor features
	hv::vmwrite<unsigned __int64>(CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS, ajdust_controls(pinbased_controls.all, vmx_basic.true_controls ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS));
	hv::vmwrite<unsigned __int64>(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ajdust_controls(primary_controls.all, vmx_basic.true_controls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS));
	hv::vmwrite<unsigned __int64>(CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ajdust_controls(secondary_controls.all, IA32_VMX_PROCBASED_CTLS2));
	hv::vmwrite<unsigned __int64>(CONTROL_VM_EXIT_CONTROLS, ajdust_controls(exit_controls.all, vmx_basic.true_controls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS));
	hv::vmwrite<unsigned __int64>(CONTROL_VM_ENTRY_CONTROLS, ajdust_controls(entry_controls.all, vmx_basic.true_controls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS));

	// Segments
	fill_guest_selector_data((void*)gdtr.base_address, ES, __read_es());
	fill_guest_selector_data((void*)gdtr.base_address, CS, __read_cs());
	fill_guest_selector_data((void*)gdtr.base_address, SS, __read_ss());
	fill_guest_selector_data((void*)gdtr.base_address, DS, __read_ds());
	fill_guest_selector_data((void*)gdtr.base_address, FS, __read_fs());
	fill_guest_selector_data((void*)gdtr.base_address, GS, __read_gs());
	fill_guest_selector_data((void*)gdtr.base_address, LDTR, __read_ldtr());
	fill_guest_selector_data((void*)gdtr.base_address, TR, __read_tr());
	hv::vmwrite<unsigned __int64>(GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	hv::vmwrite<unsigned __int64>(GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
	hv::vmwrite<unsigned __int64>(HOST_CS_SELECTOR, __read_cs() & ~selector_mask);
	hv::vmwrite<unsigned __int64>(HOST_SS_SELECTOR, __read_ss() & ~selector_mask);
	hv::vmwrite<unsigned __int64>(HOST_DS_SELECTOR, __read_ds() & ~selector_mask);
	hv::vmwrite<unsigned __int64>(HOST_ES_SELECTOR, __read_es() & ~selector_mask);
	hv::vmwrite<unsigned __int64>(HOST_FS_SELECTOR, __read_fs() & ~selector_mask);
	hv::vmwrite<unsigned __int64>(HOST_GS_SELECTOR, __read_gs() & ~selector_mask);
	hv::vmwrite<unsigned __int64>(HOST_TR_SELECTOR, __read_tr() & ~selector_mask);
	hv::vmwrite<unsigned __int64>(HOST_FS_BASE, __readmsr(IA32_FS_BASE));
	hv::vmwrite<unsigned __int64>(HOST_GS_BASE, __readmsr(IA32_GS_BASE));
	hv::vmwrite<unsigned __int64>(HOST_TR_BASE, get_segment_base(__read_tr(),(unsigned char*)gdtr.base_address));

	// Cr registers
	hv::vmwrite<unsigned __int64>(GUEST_CR0, __readcr0());
	hv::vmwrite<unsigned __int64>(HOST_CR0, __readcr0());
	hv::vmwrite<unsigned __int64>(CONTROL_CR0_READ_SHADOW, __readcr0());	

	hv::vmwrite<unsigned __int64>(GUEST_CR3, __readcr3());
	hv::vmwrite<unsigned __int64>(HOST_CR3, hv::get_system_directory_table_base());
	hv::vmwrite<unsigned __int64>(CONTROL_CR3_TARGET_COUNT, 0);

	hv::vmwrite<unsigned __int64>(GUEST_CR4, __readcr4());
	hv::vmwrite<unsigned __int64>(HOST_CR4, __readcr4());
	hv::vmwrite<unsigned __int64>(CONTROL_CR4_READ_SHADOW, __readcr4() & ~0x2000);
	hv::vmwrite<unsigned __int64>(CONTROL_CR4_GUEST_HOST_MASK, 0x2000); // Virtual Machine Extensions Enable	

	// Debug register
	hv::vmwrite<unsigned __int64>(GUEST_DR7, __readdr(7));

	// RFLAGS
	hv::vmwrite<unsigned __int64>(GUEST_RFLAGS, __readeflags());

	// RSP and RIP
	hv::vmwrite<void*>(GUEST_RSP, guest_rsp);
	hv::vmwrite<void*>(GUEST_RIP, vmx_restore_state);
	hv::vmwrite<unsigned __int64>(HOST_RSP, (unsigned __int64)vcpu->vmm_stack + VMM_STACK_SIZE);
	hv::vmwrite<void*>(HOST_RIP, vmm_entrypoint);

	// MSRS Guest
	hv::vmwrite<unsigned __int64>(GUEST_DEBUG_CONTROL, __readmsr(IA32_DEBUGCTL));
	hv::vmwrite<unsigned __int64>(GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
	hv::vmwrite<unsigned __int64>(GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
	hv::vmwrite<unsigned __int64>(GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
	hv::vmwrite<unsigned __int64>(GUEST_EFER, __readmsr(IA32_EFER));

	// MSRS Host
	hv::vmwrite<unsigned __int64>(HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
	hv::vmwrite<unsigned __int64>(HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
	hv::vmwrite<unsigned __int64>(HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
	hv::vmwrite<unsigned __int64>(HOST_EFER, __readmsr(IA32_EFER));

	// Features
	hv::vmwrite<unsigned __int64>(GUEST_VMCS_LINK_POINTER, ~0ULL);

	hv::vmwrite<unsigned __int64>(CONTROL_EXCEPTION_BITMAP, exception_bitmap.all);

	if (primary_controls.use_msr_bitmaps == true)
		hv::vmwrite<unsigned __int64>(CONTROL_MSR_BITMAPS_ADDRESS, vcpu->vcpu_bitmaps.msr_bitmap_physical);

	if (primary_controls.use_io_bitmaps == true)
	{
		hv::vmwrite<unsigned __int64>(CONTROL_BITMAP_IO_A_ADDRESS, vcpu->vcpu_bitmaps.io_bitmap_a_physical);
		hv::vmwrite<unsigned __int64>(CONTROL_BITMAP_IO_B_ADDRESS, vcpu->vcpu_bitmaps.io_bitmap_b_physical);
	}

	if(secondary_controls.enable_vpid == true)
		hv::vmwrite<unsigned __int64>(CONTROL_VIRTUAL_PROCESSOR_IDENTIFIER, 1);

	if(secondary_controls.enable_ept == true && secondary_controls.enable_vpid == true)
		hv::vmwrite<unsigned __int64>(CONTROL_EPT_POINTER, g_vmm_context->ept_state->ept_pointer->all);
}