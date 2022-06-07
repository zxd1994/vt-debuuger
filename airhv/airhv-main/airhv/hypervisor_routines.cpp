#pragma warning( disable : 4201 4244)

#include <ntddk.h>
#include <intrin.h>
#include "hypervisor_routines.h"
#include "ia32\cpuid.h"
#include "asm\vm_context.h"
#include "ia32\cr.h"
#include "ia32\msr.h"
#include "ia32\vmcs.h"
#include "log.h"
#include "ntapi.h"
#include "ia32\vmcs_encodings.h"
#include "vmcall_handler.h"
#include "interrupt.h"
#include "allocators.h"
#include "asm/vm_intrin.h"

#define NON_CANONICIAL_ADDRESS_END 0xFFFF800000000000
#define NON_CANONICIAL_ADDRESS_START 0x0000800000000000

namespace hv 
{
	volatile long vmcs_dump_lock = 0;

	/// <summary>
	/// Inject interrupt/exception to guest system
	/// </summary>
	/// <param name="vector"></param>
	/// <param name="type"></param>
	/// <param name="error_code"></param>
	/// <param name="deliver_error_code"></param>
	void inject_interruption(unsigned __int32 vector, unsigned __int32 type, unsigned __int32 error_code, bool deliver_error_code)
	{
		__vmentry_interrupt_info interrupt = { 0 };

		interrupt.interruption_type = type;
		interrupt.interrupt_vector = vector;
		interrupt.deliver_error_code = deliver_error_code;
		interrupt.valid = 1;

		if(type == INTERRUPT_TYPE_SOFTWARE_EXCEPTION || type == INTERRUPT_TYPE_PRIVILEGED_SOFTWARE_INTERRUPT || type == INTERRUPT_TYPE_SOFTWARE_INTERRUPT)
			hv::vmwrite<unsigned __int64>(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH, hv::vmread(VM_EXIT_INSTRUCTION_LENGTH));

		if (deliver_error_code == true)
			hv::vmwrite<unsigned __int64>(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);

		hv::vmwrite<unsigned __int64>(CONTROL_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD, interrupt.all);
	}

	/// <summary>
	/// Write to reset io port to perform hard reset
	/// </summary>
	void hard_reset()
	{
		__reset_control_register reset_register;
		reset_register.all = __inbyte(RESET_IO_PORT);

		//
		// Reset CPU bit set, determines type of reset based on:
		//        - System Reset = 0; soft reset by activating INIT# for 16 PCI clocks.
		//        - System Reset = 1; then hard reset by activating PLTRST# and SUS_STAT#.
		//        - System Reset = 1; main power well reset.
		//

		reset_register.reset_cpu = 1;
		reset_register.system_reset = 1;

		__outbyte(RESET_IO_PORT, reset_register.all);
	}

	/// <summary>
	/// Swap cr3 with current process dtb
	/// </summary>
	/// <returns> old cr3 </returns>
	unsigned __int64 swap_context()
	{
		__nt_kprocess* current_process;

		current_process = (__nt_kprocess*)IoGetCurrentProcess();
		unsigned __int64 current_cr3 = __readcr3();
		unsigned __int64 guest_cr3 = current_process->DirectoryTableBase;

		__writecr3(guest_cr3);
		return current_cr3;
	}

	/// <summary>
	/// Restore cr3
	/// </summary>
	/// <param name="old_cr3"></param>
	void restore_context(unsigned __int64 old_cr3)
	{
		__writecr3(old_cr3);
	}

	/// <summary>
	/// Get system directory table base
	/// </summary>
	/// <returns></returns>
	unsigned __int64 get_system_directory_table_base()
	{
		return ((__nt_kprocess*)PsInitialSystemProcess)->DirectoryTableBase;
	}

	/// <summary>
	/// Read vmcs field
	/// </summary>
	/// <param name="vmcs_field"></param>
	/// <returns></returns>
	unsigned __int64 vmread(unsigned __int64 vmcs_field)
	{
		unsigned __int64 value;
		__vmx_vmread(vmcs_field, &value);
		return value;
	}

	/// <summary>
	/// Check if address is canonicial (level 4 paging)
	/// </summary>
	/// <param name="address"></param>
	/// <returns></returns>
	bool is_address_canonical(unsigned __int64 address)
	{
		if (address < NON_CANONICIAL_ADDRESS_END && address > NON_CANONICIAL_ADDRESS_START)
			return false;
		return true;
	}

	/// <summary>
	/// 
	/// </summary>
	/// <returns> Return current guest privilage level</returns>
	unsigned __int8 get_guest_cpl()
	{
		return vmread(GUEST_CS_SELECTOR) & 3;
	}

	/// <summary>
	/// Set 1 msr in msr bitmap
	/// </summary>
	/// <param name="msr"> Msr number </param>
	/// <param name="vcpu"> Pointer to current vcpu </param>
	/// <param name="read"> If set vmexit occur on reading this msr </param>
	/// <param name="write"> If set vmexit occur on writing to this msr </param>
	/// <param name="value"> If true set msr bit else clear </param>
	void set_msr_bitmap(unsigned __int32 msr, __vcpu* vcpu, bool read, bool write, bool value)
	{
		unsigned __int16 bitmap_position;
		unsigned __int8 bitmap_bit;

		if (msr <= 0x1FFF)
		{
			bitmap_position = msr / 8;
			bitmap_bit = msr % 8;

			//
			// Read access for msr 0x0 to 0x1FFF located at the MSR-bitmap address
			if (read == true)
			{
				if (value == true)
					*(vcpu->vcpu_bitmaps.msr_bitmap + bitmap_position) |= (1 << bitmap_bit);

				else
					*(vcpu->vcpu_bitmaps.msr_bitmap + bitmap_position) &= ~(1 << bitmap_bit);
			}

			//
			// Write access for msr 0x0 to 0x1FFF located at the MSR-bitmap address plus 1024
			else if (write == true)
			{
				if (value == true)
					*(vcpu->vcpu_bitmaps.msr_bitmap + bitmap_position + 1024) |= (1 << bitmap_bit);

				else
					*(vcpu->vcpu_bitmaps.msr_bitmap + bitmap_position + 1024) &= ~(1 << bitmap_bit);
			}
		}

		else if (msr >= 0xC0000000 && msr <= 0xC0001FFF)
		{
			msr -= 0xC0000000;
			bitmap_position = msr / 8;
			bitmap_bit = msr % 8;

			//
			// Read access for msr 0xC0000000 to 0xC0001FFF located at the MSR-bitmap address plus 2048
			if (read == true)
			{
				if (value == true)
					*(vcpu->vcpu_bitmaps.msr_bitmap + bitmap_position + 2048) |= (1 << bitmap_bit);

				else
					*(vcpu->vcpu_bitmaps.msr_bitmap + bitmap_position + 2048) &= ~(1 << bitmap_bit);
			}

			//
			// Write access for msr 0xC0000000 to 0xC0001FFF located at the MSR-bitmap address plus 2048
			else if (write == true)
			{
				if (value == true)
					*(vcpu->vcpu_bitmaps.msr_bitmap + bitmap_position + 3072) |= (1 << bitmap_bit);
				else
					*(vcpu->vcpu_bitmaps.msr_bitmap + bitmap_position + 3072) &= ~(1 << bitmap_bit);
			}
		}

		else
		{
			LogError("Bad msr number");
			return;
		}
	}


	/// <summary>
	/// Set or unset bit in io port bitmap
	/// </summary>
	/// <param name="io_port"> IO port which you want to set</param>
	/// <param name="vcpu"> Pointer to current vcpu </param>
	/// <param name="value"> If true then set bit else unset bit</param>
	void set_io_bitmap(unsigned __int16 io_port, __vcpu* vcpu, bool value)
	{
		unsigned __int16 bitmap_position;
		unsigned __int8 bitmap_bit;

		//
		// IO ports from 0x8000 to 0xFFFF are encoded in io bitmap b
		if (io_port >= 0x8000)
		{
			io_port -= 0x8000;
			bitmap_position = io_port / 8;
			bitmap_bit = io_port % 8;

			if (value == true)
				*(vcpu->vcpu_bitmaps.io_bitmap_b + bitmap_position) |= (1 << bitmap_bit);
			else
				*(vcpu->vcpu_bitmaps.io_bitmap_b + bitmap_position) &= ~(1 << bitmap_bit);
		}

		//
		// IO ports from 0 to 0x7fff are encoded in io bitmap b
		else
		{
			bitmap_position = io_port / 8;
			bitmap_bit = io_port % 8;

			if (value == true)
				*(vcpu->vcpu_bitmaps.io_bitmap_a + bitmap_position) |= (1 << bitmap_bit);
			else
				*(vcpu->vcpu_bitmaps.io_bitmap_a + bitmap_position) &= ~(1 << bitmap_bit);
		}
	}

	/// <summary>
	/// Used to get address passed by user in inpvcid
	/// </summary>
	/// <param name="guest_registers"></param>
	/// <returns></returns>
	unsigned __int64 get_guest_address(__vcpu* vcpu)
	{
		__vmexit_instruction_information2 instruction_information;

		instruction_information.all = vcpu->vmexit_info.instruction_information;

		unsigned __int64 displacement = vcpu->vmexit_info.qualification;

		unsigned __int64 base_value = !instruction_information.base_reg_invalid ? *(&vcpu->vmexit_info.guest_registers->rax - instruction_information.base_reg) : 0;

		unsigned __int64 index_value = !instruction_information.index_reg_invalid ? *(&vcpu->vmexit_info.guest_registers->rax - instruction_information.index_reg) : 0;

		index_value = index_value * (1ULL << instruction_information.scaling);

		unsigned __int64 segment_base = hv::vmread(GUEST_ES_BASE + (instruction_information.segment_register << 1));

		unsigned __int64 guest_address = displacement + base_value + index_value + segment_base;

		return guest_address;
	}

	/// <summary>
	/// Check if cpu support virtualization
	/// </summary>
	/// <returns></returns>
	bool virtualization_support()
	{
		__cpuid_info cpuid = { 0 };
		__cpuid(&cpuid.cpu_info[0], 1);
		return cpuid.cpuid_eax_01.feature_information_ecx.virtual_machine_extensions;
	}

	/// <summary>
	/// Disable vmx operation
	/// </summary>
	/// <returns></returns>
	void disable_vmx_operation()
	{
		__cr4 cr4 = { 0 };
		__ia32_feature_control_msr feature_msr = { 0 };
		cr4.all = __readcr4();
		cr4.vmx_enable = 0;
		__writecr4(cr4.all);
	}

	/// <summary>
	/// Dump whole vmcs structure
	/// </summary>
	void dump_vmcs()
	{
		spinlock::lock(&vmcs_dump_lock);

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"-----------------------------------VMCS CORE %u DUMP-----------------------------------\r\n",KeGetCurrentProcessorIndex());

		// Natural Guest Register State Fields
		LogDump("GUEST_CR0: 0x%llX", vmread(GUEST_CR0));
		LogDump("GUEST_CR3: 0x%llX", vmread(GUEST_CR3));
		LogDump("GUEST_CR4: 0x%llX", vmread(GUEST_CR4));
		LogDump("GUEST_ES_BASE: 0x%llX", vmread(GUEST_ES_BASE));
		LogDump("GUEST_CS_BASE: 0x%llX", vmread(GUEST_CS_BASE));
		LogDump("GUEST_SS_BASE: 0x%llX", vmread(GUEST_SS_BASE));
		LogDump("GUEST_DS_BASE: 0x%llX", vmread(GUEST_DS_BASE));
		LogDump("GUEST_FS_BASE: 0x%llX", vmread(GUEST_FS_BASE));
		LogDump("GUEST_GS_BASE: 0x%llX", vmread(GUEST_GS_BASE));
		LogDump("GUEST_LDTR_BASE: 0x%llX", vmread(GUEST_LDTR_BASE));
		LogDump("GUEST_TR_BASE: 0x%llX", vmread(GUEST_TR_BASE));
		LogDump("GUEST_GDTR_BASE: 0x%llX", vmread(GUEST_GDTR_BASE));
		LogDump("GUEST_IDTR_BASE: 0x%llX", vmread(GUEST_IDTR_BASE));
		LogDump("GUEST_DR7: 0x%llX", vmread(GUEST_DR7));
		LogDump("GUEST_RSP: 0x%llX", vmread(GUEST_RSP));
		LogDump("GUEST_RIP: 0x%llX", vmread(GUEST_RIP));
		LogDump("GUEST_RFLAGS: 0x%llX", vmread(GUEST_RFLAGS));
		LogDump("GUEST_SYSENTER_ESP: 0x%llX", vmread(GUEST_SYSENTER_ESP));
		LogDump("GUEST_SYSENTER_EIP: 0x%llX", vmread(GUEST_SYSENTER_EIP));
		LogDump("GUEST_S_CET: 0x%llX", vmread(GUEST_S_CET));
		LogDump("GUEST_SSP: 0x%llX", vmread(GUEST_SSP));
		LogDump("GUEST_INTERRUPT_SSP_TABLE_ADDR: 0x%llX", vmread(GUEST_INTERRUPT_SSP_TABLE_ADDR));

		// 64-bit Guest Register State Fields
		LogDump("GUEST_VMCS_LINK_POINTER: 0x%llX", vmread(GUEST_VMCS_LINK_POINTER));
		LogDump("GUEST_DEBUG_CONTROL: 0x%llX", vmread(GUEST_DEBUG_CONTROL));
		LogDump("GUEST_PAT: 0x%llX", vmread(GUEST_PAT));
		LogDump("GUEST_EFER: 0x%llX", vmread(GUEST_EFER));
		LogDump("GUEST_PERF_GLOBAL_CONTROL: 0x%llX", vmread(GUEST_PERF_GLOBAL_CONTROL));
		LogDump("GUEST_PDPTE0: 0x%llX", vmread(GUEST_PDPTE0));
		LogDump("GUEST_PDPTE1: 0x%llX", vmread(GUEST_PDPTE1));
		LogDump("GUEST_PDPTE2: 0x%llX", vmread(GUEST_PDPTE2));
		LogDump("GUEST_PDPTE3: 0x%llX", vmread(GUEST_PDPTE3));
		LogDump("GUEST_BNDCFGS: 0x%llX", vmread(GUEST_BNDCFGS));
		LogDump("GUEST_RTIT_CTL: 0x%llX", vmread(GUEST_RTIT_CTL));
		LogDump("GUEST_PKRS: 0x%llX", vmread(GUEST_PKRS));

		// 32-Bit Guest Register State Fields
		LogDump("GUEST_ES_LIMIT: 0x%llX", vmread(GUEST_ES_LIMIT));
		LogDump("GUEST_CS_LIMIT: 0x%llX", vmread(GUEST_CS_LIMIT));
		LogDump("GUEST_SS_LIMIT: 0x%llX", vmread(GUEST_SS_LIMIT));
		LogDump("GUEST_DS_LIMIT: 0x%llX", vmread(GUEST_DS_LIMIT));
		LogDump("GUEST_FS_LIMIT: 0x%llX", vmread(GUEST_FS_LIMIT));
		LogDump("GUEST_GS_LIMIT: 0x%llX", vmread(GUEST_GS_LIMIT));
		LogDump("GUEST_LDTR_LIMIT: 0x%llX", vmread(GUEST_LDTR_LIMIT));
		LogDump("GUEST_TR_LIMIT: 0x%llX", vmread(GUEST_TR_LIMIT));
		LogDump("GUEST_GDTR_LIMIT: 0x%llX", vmread(GUEST_GDTR_LIMIT));
		LogDump("GUEST_IDTR_LIMIT: 0x%llX", vmread(GUEST_IDTR_LIMIT));
		LogDump("GUEST_ES_ACCESS_RIGHTS: 0x%llX", vmread(GUEST_ES_ACCESS_RIGHTS));
		LogDump("GUEST_CS_ACCESS_RIGHTS: 0x%llX", vmread(GUEST_CS_ACCESS_RIGHTS));
		LogDump("GUEST_SS_ACCESS_RIGHTS: 0x%llX", vmread(GUEST_SS_ACCESS_RIGHTS));
		LogDump("GUEST_DS_ACCESS_RIGHTS: 0x%llX", vmread(GUEST_DS_ACCESS_RIGHTS));
		LogDump("GUEST_FS_ACCESS_RIGHTS: 0x%llX", vmread(GUEST_FS_ACCESS_RIGHTS));
		LogDump("GUEST_GS_ACCESS_RIGHTS: 0x%llX", vmread(GUEST_GS_ACCESS_RIGHTS));
		LogDump("GUEST_LDTR_ACCESS_RIGHTS: 0x%llX", vmread(GUEST_LDTR_ACCESS_RIGHTS));
		LogDump("GUEST_TR_ACCESS_RIGHTS: 0x%llX", vmread(GUEST_TR_ACCESS_RIGHTS));
		LogDump("GUEST_INTERRUPTIBILITY_STATE: 0x%llX", vmread(GUEST_INTERRUPTIBILITY_STATE));
		LogDump("GUEST_ACTIVITY_STATE: 0x%llX", vmread(GUEST_ACTIVITY_STATE));
		LogDump("GUEST_SMBASE: 0x%llX", vmread(GUEST_SMBASE));
		LogDump("GUEST_SYSENTER_CS: 0x%llX", vmread(GUEST_SYSENTER_CS));
		LogDump("GUEST_VMX_PREEMPTION_TIMER_VALUE: 0x%llX", vmread(GUEST_VMX_PREEMPTION_TIMER_VALUE));

		// 16-Bit Guest Register State Fields
		LogDump("GUEST_ES_SELECTOR: 0x%llX", vmread(GUEST_ES_SELECTOR));
		LogDump("GUEST_CS_SELECTOR: 0x%llX", vmread(GUEST_CS_SELECTOR));
		LogDump("GUEST_SS_SELECTOR: 0x%llX", vmread(GUEST_SS_SELECTOR));
		LogDump("GUEST_DS_SELECTOR: 0x%llX", vmread(GUEST_DS_SELECTOR));
		LogDump("GUEST_FS_SELECTOR: 0x%llX", vmread(GUEST_FS_SELECTOR));
		LogDump("GUEST_GS_SELECTOR: 0x%llX", vmread(GUEST_GS_SELECTOR));
		LogDump("GUEST_LDTR_SELECTOR: 0x%llX", vmread(GUEST_LDTR_SELECTOR));
		LogDump("GUEST_TR_SELECTOR: 0x%llX", vmread(GUEST_TR_SELECTOR));
		LogDump("GUEST_GUEST_INTERRUPT_STATUS: 0x%llX", vmread(GUEST_GUEST_INTERRUPT_STATUS));
		LogDump("GUEST_PML_INDEX: 0x%llX", vmread(GUEST_PML_INDEX));

		// Natural Host Register State Fields
		LogDump("HOST_CR0: 0x%llX", vmread(HOST_CR0));
		LogDump("HOST_CR3: 0x%llX", vmread(HOST_CR3));
		LogDump("HOST_CR4: 0x%llX", vmread(HOST_CR4));
		LogDump("HOST_FS_BASE: 0x%llX", vmread(HOST_FS_BASE));
		LogDump("HOST_GS_BASE: 0x%llX", vmread(HOST_GS_BASE));
		LogDump("HOST_TR_BASE: 0x%llX", vmread(HOST_TR_BASE));
		LogDump("HOST_GDTR_BASE: 0x%llX", vmread(HOST_GDTR_BASE));
		LogDump("HOST_IDTR_BASE: 0x%llX", vmread(HOST_IDTR_BASE));
		LogDump("HOST_SYSENTER_ESP: 0x%llX", vmread(HOST_SYSENTER_ESP));
		LogDump("HOST_SYSENTER_EIP: 0x%llX", vmread(HOST_SYSENTER_EIP));
		LogDump("HOST_RSP: 0x%llX", vmread(HOST_RSP));
		LogDump("HOST_RIP: 0x%llX", vmread(HOST_RIP));
		LogDump("HOST_S_CET: 0x%llX", vmread(HOST_S_CET));
		LogDump("HOST_SSP: 0x%llX", vmread(HOST_SSP));
		LogDump("HOST_INTERRUPT_SSP_TABLE_ADDR: 0x%llX", vmread(HOST_INTERRUPT_SSP_TABLE_ADDR));

		// 64-bit Host Register State Fields
		LogDump("HOST_PAT: 0x%llX", vmread(HOST_PAT));
		LogDump("HOST_EFER: 0x%llX", vmread(HOST_EFER));
		LogDump("HOST_PERF_GLOBAL_CTRL: 0x%llX", vmread(HOST_PERF_GLOBAL_CTRL));
		LogDump("HOST_PKRS: 0x%llX", vmread(HOST_PKRS));

		// 32-bit Host Register State Fields
		LogDump("HOST_SYSENTER_CS: 0x%llX", vmread(HOST_SYSENTER_CS));

		// 16-bit Host Register State Fields
		LogDump("HOST_ES_SELECTOR: 0x%llX", vmread(HOST_ES_SELECTOR));
		LogDump("HOST_CS_SELECTOR: 0x%llX", vmread(HOST_CS_SELECTOR));
		LogDump("HOST_SS_SELECTOR: 0x%llX", vmread(HOST_SS_SELECTOR));
		LogDump("HOST_DS_SELECTOR: 0x%llX", vmread(HOST_DS_SELECTOR));
		LogDump("HOST_FS_SELECTOR: 0x%llX", vmread(HOST_FS_SELECTOR));
		LogDump("HOST_GS_SELECTOR: 0x%llX", vmread(HOST_GS_SELECTOR));
		LogDump("HOST_TR_SELECTOR: 0x%llX", vmread(HOST_TR_SELECTOR));

		// Natural Control Register State Fields
		LogDump("CONTROL_CR0_GUEST_HOST_MASK: 0x%llX", vmread(CONTROL_CR0_GUEST_HOST_MASK));
		LogDump("CONTROL_CR4_GUEST_HOST_MASK: 0x%llX", vmread(CONTROL_CR4_GUEST_HOST_MASK));
		LogDump("CONTROL_CR0_READ_SHADOW: 0x%llX", vmread(CONTROL_CR0_READ_SHADOW));
		LogDump("CONTROL_CR4_READ_SHADOW: 0x%llX", vmread(CONTROL_CR4_READ_SHADOW));
		LogDump("CONTROL_CR3_TARGET_VALUE_0: 0x%llX", vmread(CONTROL_CR3_TARGET_VALUE_0));
		LogDump("CONTROL_CR3_TARGET_VALUE_1: 0x%llX", vmread(CONTROL_CR3_TARGET_VALUE_1));
		LogDump("CONTROL_CR3_TARGET_VALUE_2: 0x%llX", vmread(CONTROL_CR3_TARGET_VALUE_2));
		LogDump("CONTROL_CR3_TARGET_VALUE_3: 0x%llX", vmread(CONTROL_CR3_TARGET_VALUE_3));

		// 64-bit Control Register State Fields
		LogDump("CONTROL_BITMAP_IO_A_ADDRESS: 0x%llX", vmread(CONTROL_BITMAP_IO_A_ADDRESS));
		LogDump("CONTROL_BITMAP_IO_B_ADDRESS: 0x%llX", vmread(CONTROL_BITMAP_IO_B_ADDRESS));
		LogDump("CONTROL_MSR_BITMAPS_ADDRESS: 0x%llX", vmread(CONTROL_MSR_BITMAPS_ADDRESS));
		LogDump("CONTROL_VMEXIT_MSR_STORE_ADDRESS: 0x%llX", vmread(CONTROL_VMEXIT_MSR_STORE_ADDRESS));
		LogDump("CONTROL_VMEXIT_MSR_LOAD_ADDRESS: 0x%llX", vmread(CONTROL_VMEXIT_MSR_LOAD_ADDRESS));
		LogDump("CONTROL_VMENTER_MSR_LOAD_ADDRESS: 0x%llX", vmread(CONTROL_VMENTER_MSR_LOAD_ADDRESS));
		LogDump("CONTROL_VMCS_EXECUTIVE_POINTER: 0x%llX", vmread(CONTROL_VMCS_EXECUTIVE_POINTER));
		LogDump("CONTROL_PML_ADDRESS: 0x%llX", vmread(CONTROL_PML_ADDRESS));
		LogDump("CONTROL_TSC_OFFSET: 0x%llX", vmread(CONTROL_TSC_OFFSET));
		LogDump("CONTROL_VIRTUAL_APIC_ADDRESS: 0x%llX", vmread(CONTROL_VIRTUAL_APIC_ADDRESS));
		LogDump("CONTROL_APIC_ACCESS_ADDRESS: 0x%llX", vmread(CONTROL_APIC_ACCESS_ADDRESS));
		LogDump("CONTROL_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS: 0x%llX", vmread(CONTROL_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS));
		LogDump("CONTROL_VM_FUNCTION_CONTROLS: 0x%llX", vmread(CONTROL_VM_FUNCTION_CONTROLS));
		LogDump("CONTROL_EPT_POINTER: 0x%llX", vmread(CONTROL_EPT_POINTER));
		LogDump("CONTROL_EOI_EXIT_BITMAP_0: 0x%llX", vmread(CONTROL_EOI_EXIT_BITMAP_0));
		LogDump("CONTROL_EOI_EXIT_BITMAP_1: 0x%llX", vmread(CONTROL_EOI_EXIT_BITMAP_1));
		LogDump("CONTROL_EOI_EXIT_BITMAP_2: 0x%llX", vmread(CONTROL_EOI_EXIT_BITMAP_2));
		LogDump("CONTROL_EOI_EXIT_BITMAP_3: 0x%llX", vmread(CONTROL_EOI_EXIT_BITMAP_3));
		LogDump("CONTROL_EPTP_LIST_ADDRESS: 0x%llX", vmread(CONTROL_EPTP_LIST_ADDRESS));
		LogDump("CONTROL_VMREAD_BITMAP_ADDRESS: 0x%llX", vmread(CONTROL_VMREAD_BITMAP_ADDRESS));
		LogDump("CONTROL_VMWRITE_BITMAP_ADDRESS: 0x%llX", vmread(CONTROL_VMWRITE_BITMAP_ADDRESS));
		LogDump("CONTROL_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS: 0x%llX", vmread(CONTROL_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS));
		LogDump("CONTROL_XSS_EXITING_BITMAP: 0x%llX", vmread(CONTROL_XSS_EXITING_BITMAP));
		LogDump("CONTROL_ENCLS_EXITING_BITMAP: 0x%llX", vmread(CONTROL_ENCLS_EXITING_BITMAP));
		LogDump("CONTROL_SUB_PAGE_PERMISSION_TABLE_POINTER: 0x%llX", vmread(CONTROL_SUB_PAGE_PERMISSION_TABLE_POINTER));
		LogDump("CONTROL_TSC_MULTIPLIER: 0x%llX", vmread(CONTROL_TSC_MULTIPLIER));
		LogDump("CONTROL_ENCLV_EXITING_BITMAP: 0x%llX", vmread(CONTROL_ENCLV_EXITING_BITMAP));

		// 32-bit Control Register State Fields
		LogDump("CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS: 0x%llX", vmread(CONTROL_PIN_BASED_VM_EXECUTION_CONTROLS));
		LogDump("CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS: 0x%llX", vmread(CONTROL_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS));
		LogDump("CONTROL_EXCEPTION_BITMAP: 0x%llX", vmread(CONTROL_EXCEPTION_BITMAP));
		LogDump("CONTROL_PAGE_FAULT_ERROR_CODE_MASK: 0x%llX", vmread(CONTROL_PAGE_FAULT_ERROR_CODE_MASK));
		LogDump("CONTROL_PAGE_FAULT_ERROR_CODE_MATCH: 0x%llX", vmread(CONTROL_PAGE_FAULT_ERROR_CODE_MATCH));
		LogDump("CONTROL_CR3_TARGET_COUNT: 0x%llX", vmread(CONTROL_CR3_TARGET_COUNT));
		LogDump("CONTROL_VM_EXIT_CONTROLS: 0x%llX", vmread(CONTROL_VM_EXIT_CONTROLS));
		LogDump("CONTROL_VM_EXIT_MSR_STORE_COUNT: 0x%llX", vmread(CONTROL_VM_EXIT_MSR_STORE_COUNT));
		LogDump("CONTROL_VM_EXIT_MSR_LOAD_COUNT: 0x%llX", vmread(CONTROL_VM_EXIT_MSR_LOAD_COUNT));
		LogDump("CONTROL_VM_ENTRY_CONTROLS: 0x%llX", vmread(CONTROL_VM_ENTRY_CONTROLS));
		LogDump("CONTROL_VM_ENTRY_MSR_LOAD_COUNT: 0x%llX", vmread(CONTROL_VM_ENTRY_MSR_LOAD_COUNT));
		LogDump("CONTROL_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD: 0x%llX", vmread(CONTROL_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD));
		LogDump("CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE: 0x%llX", vmread(CONTROL_VM_ENTRY_EXCEPTION_ERROR_CODE));
		LogDump("CONTROL_VM_ENTRY_INSTRUCTION_LENGTH: 0x%llX", vmread(CONTROL_VM_ENTRY_INSTRUCTION_LENGTH));
		LogDump("CONTROL_TPR_THRESHOLD: 0x%llX", vmread(CONTROL_TPR_THRESHOLD));
		LogDump("CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS: 0x%llX", vmread(CONTROL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS));
		LogDump("CONTROL_PLE_GAP: 0x%llX", vmread(CONTROL_PLE_GAP));
		LogDump("CONTROL_PLE_WINDOW: 0x%llX", vmread(CONTROL_PLE_WINDOW));

		// 16-bit Control Register State Fields
		LogDump("CONTROL_VIRTUAL_PROCESSOR_IDENTIFIER: 0x%llX", vmread(CONTROL_VIRTUAL_PROCESSOR_IDENTIFIER));
		LogDump("CONTROL_POSTED_INTERRUPT_NOTIFICATION_VECTOR: 0x%llX", vmread(CONTROL_POSTED_INTERRUPT_NOTIFICATION_VECTOR));
		LogDump("CONTROL_EPTP_INDEX: 0x%llX", vmread(CONTROL_EPTP_INDEX));

		// Natural Read only Register State Fields
		LogDump("EXIT_QUALIFICATION: 0x%llX", vmread(EXIT_QUALIFICATION));
		LogDump("IO_RCX: 0x%llX", vmread(IO_RCX));
		LogDump("IO_RSI: 0x%llX", vmread(IO_RSI));
		LogDump("IO_RDI: 0x%llX", vmread(IO_RDI));
		LogDump("IO_RIP: 0x%llX", vmread(IO_RIP));
		LogDump("GUEST_LINEAR_ADDRESS: 0x%llX", vmread(GUEST_LINEAR_ADDRESS));

		// 64-bit Read only Register State Fields
		LogDump("GUEST_PHYSICAL_ADDRESS: 0x%llX", vmread(GUEST_PHYSICAL_ADDRESS));

		// 32-bit Read only Register State Fields
		LogDump("VM_INSTRUCTION_ERROR: 0x%llX", vmread(VM_INSTRUCTION_ERROR));
		LogDump("EXIT_REASON: 0x%llX", vmread(EXIT_REASON));
		LogDump("VM_EXIT_INTERRUPTION_INFORMATION: 0x%llX", vmread(VM_EXIT_INTERRUPTION_INFORMATION));
		LogDump("VM_EXIT_INTERRUPTION_ERROR_CODE: 0x%llX", vmread(VM_EXIT_INTERRUPTION_ERROR_CODE));
		LogDump("IDT_VECTORING_INFORMATION_FIELD: 0x%llX", vmread(IDT_VECTORING_INFORMATION_FIELD));
		LogDump("IDT_VECTORING_ERROR_CODE: 0x%llX", vmread(IDT_VECTORING_ERROR_CODE));
		LogDump("VM_EXIT_INSTRUCTION_LENGTH: 0x%llX", vmread(VM_EXIT_INSTRUCTION_LENGTH));
		LogDump("VM_EXIT_INSTRUCTION_INFORMATION: 0x%llX", vmread(VM_EXIT_INSTRUCTION_INFORMATION));

		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "-----------------------------------VMCS CORE %u DUMP-----------------------------------\r\n", KeGetCurrentProcessorIndex());

		spinlock::unlock(&vmcs_dump_lock);
	}
}