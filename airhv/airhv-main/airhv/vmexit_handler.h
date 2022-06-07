#pragma once

enum __vm_exit_reason
{
	EXIT_REASON_EXCEPTION_NMI,
	EXIT_REASON_EXTERNAL_INTERRUPT,
	EXIT_REASON_TRIPLE_FAULT,
	EXIT_REASON_INIT_SIGNAL,
	EXIT_REASON_SIPI,
	EXIT_REASON_SMI,
	EXIT_REASON_OTHER_SMI,
	EXIT_REASON_INTERRUPT_WINDOW,
	EXIT_REASON_NMI_WINDOW,
	EXIT_REASON_TASK_SWITCH,
	EXIT_REASON_CPUID,
	EXIT_REASON_GETSEC,
	EXIT_REASON_HLT,
	EXIT_REASON_INVD,
	EXIT_REASON_INVLPG,
	EXIT_REASON_RDPMC,
	EXIT_REASON_RDTSC,
	EXIT_REASON_RSM,
	EXIT_REASON_VMCALL,
	EXIT_REASON_VMCLEAR,
	EXIT_REASON_VMLAUNCH,
	EXIT_REASON_VMPTRLD,
	EXIT_REASON_VMPTRST,
	EXIT_REASON_VMREAD,
	EXIT_REASON_VMRESUME,
	EXIT_REASON_VMWRITE,
	EXIT_REASON_VMXOFF,
	EXIT_REASON_VMXON,
	EXIT_REASON_CR_ACCESSES,
	EXIT_REASON_MOV_DR,
	EXIT_REASON_IO_INSTRUCTION,
	EXIT_REASON_RDMSR,
	EXIT_REASON_WRMSR,
	EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE,
	EXIT_REASON_VM_ENTRY_FAILURE_MSR_LODAING,
	EXIT_REASON_RESERVED1,
	EXIT_REASON_MWAIT,
	EXIT_REASON_MONITOR_TRAP_FLAG,
	EXIT_REASON_RESERVED2,
	EXIT_REASON_MONITOR,
	EXIT_REASON_PAUSE,
	EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT,
	EXIT_REASON_RESERVED3,
	EXIT_REASON_TPR_BELOW_THRESHOLD,
	EXIT_REASON_APIC_ACCESS,
	EXIT_REASON_VIRTUALIZED_EOI,
	EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR,
	EXIT_REASON_ACCESS_TO_LDTR_OR_TR,
	EXIT_REASON_EPT_VIOLATION,
	EXIT_REASON_EPT_MISCONFIGURATION,
	EXIT_REASON_INVEPT,
	EXIT_REASON_RDTSCP,
	EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED,
	EXIT_REASON_INVVPID,
	EXIT_REASON_WBINVD,
	EXIT_REASON_XSETBV,
	EXIT_REASON_APIC_WRITE,
	EXIT_REASON_RDRAND,
	EXIT_REASON_INVPCID,
	EXIT_REASON_VMFUNC,
	EXIT_REASON_ENCLS,
	EXIT_REASON_RDSEED,
	EXIT_REASON_PAGE_MODIFICATION_LOG_FULL,
	EXIT_REASON_XSAVES,
	EXIT_REASON_XRSTORS,
	EXIT_REASON_RESERVED4,
	EXIT_REASON_SPP_RELATED_EVENT,
	EXIT_REASON_UMWAIT,
	EXIT_REASON_TPAUSE,
	EXIT_REASON_LAST
};

// Table 27-8. Format of the VM-Exit Instruction-Information Field as Used for INS and OUTS
union __vmexit_instruction_information1
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 reserved1 : 7;
		unsigned __int64 address_size : 3;
		unsigned __int64 reserved2 : 5;
		unsigned __int64 segment_register : 3;
		unsigned __int64 reserved3 : 14;
	};
};

// Table 27-9. Format of the VM-Exit Instruction-Information Field as Used for INVEPT, INVPCID, and INVVPID
union __vmexit_instruction_information2
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 scaling : 2;
		unsigned __int64 reserved1 : 5;
		unsigned __int64 address_size : 3;
		unsigned __int64 reserved2 : 1;
		unsigned __int64 reserved3 : 4;
		unsigned __int64 segment_register : 3;
		unsigned __int64 index_reg : 4;
		unsigned __int64 index_reg_invalid : 1;
		unsigned __int64 base_reg : 4;
		unsigned __int64 base_reg_invalid : 1;
		unsigned __int64 reg2 : 4;
	};
};

// Table 27-10. Format of the VM-Exit Instruction-Information Field as Used for LIDT, LGDT, SIDT, or SGDT
union __vmexit_instruction_information3 
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 scaling : 2;
		unsigned __int64 reserved1 : 5;
		unsigned __int64 address_size : 3;
		unsigned __int64 reserved2 : 1;
		unsigned __int64 operand_size : 1;
		unsigned __int64 reserved3 : 3;
		unsigned __int64 segment_register : 3;
		unsigned __int64 index_reg : 4;
		unsigned __int64 index_reg_invalid : 1;
		unsigned __int64 base_reg : 4;
		unsigned __int64 base_reg_invalid : 1;
		unsigned __int64 instruction_identity : 2;
		unsigned __int64 reserved4 : 2;
	};
};

// Table 27-11. Format of the VM-Exit Instruction-Information Field as Used for LLDT, LTR, SLDT, and STR
union __vmexit_instruction_information4
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 scaling : 2;
		unsigned __int64 reserved1 : 1;
		unsigned __int64 reg1 : 4;
		unsigned __int64 address_size : 3;
		unsigned __int64 mem_reg : 1;
		unsigned __int64 reserved2 : 4;
		unsigned __int64 segment_register : 3;
		unsigned __int64 index_reg : 4;
		unsigned __int64 index_reg_invalid : 1;
		unsigned __int64 base_reg : 4;
		unsigned __int64 base_reg_invalid : 1;
		unsigned __int64 instruction_identity : 2;
		unsigned __int64 reserved4 : 2;
	};
};

// Table 27-12. Format of the VM-Exit Instruction-Information Field as Used for RDRAND, RDSEED, TPAUSE, and UMWAIT
union __vmexit_instruction_information5
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 reserved1 : 3;
		unsigned __int64 operand_register : 4;
		unsigned __int64 reserved2 : 4;
		unsigned __int64 operand_size : 2;
		unsigned __int64 reserved3 : 19;
	};
};

// Table 27 - 13. Format of the VM - Exit Instruction - Information Field as Used for VMCLEAR, VMPTRLD, VMPTRST, VMXON, XRSTORS, and XSAVES
union __vmexit_instruction_information6
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 scaling : 2;
		unsigned __int64 reserved1 : 5;
		unsigned __int64 address_size : 3;
		unsigned __int64 reserved2 : 1;
		unsigned __int64 reserved3 : 4;
		unsigned __int64 segment_register : 3;
		unsigned __int64 index_reg : 4;
		unsigned __int64 index_reg_invalid : 1;
		unsigned __int64 base_reg : 4;
		unsigned __int64 base_reg_invalid : 1;
		unsigned __int64 instruction_identity : 2;
		unsigned __int64 reserved4 : 2;
	};
};

// Table 27-14. Format of the VM-Exit Instruction-Information Field as Used for VMREAD and VMWRITE
union __vmexit_instruction_information7
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 scaling : 2;
		unsigned __int64 reserved1 : 1;
		unsigned __int64 reg1 : 4;
		unsigned __int64 address_size : 3;
		unsigned __int64 mem_reg : 1;
		unsigned __int64 reserved2 : 4;
		unsigned __int64 segment_register : 3;
		unsigned __int64 index_reg : 4;
		unsigned __int64 index_reg_invalid : 1;
		unsigned __int64 base_reg : 4;
		unsigned __int64 base_reg_invalid : 1;
		unsigned __int64 reg2 : 4;
	};
};

// Table 27-5. Exit Qualification for I/O Instructions
union __exit_qualification_io 
{
	unsigned __int64 all;
	struct
	{
		//
		// 0 = 1 - byte
		// 1 = 2 - byte
		// 3 = 4 - byte
		//
		unsigned __int64 access_size : 3;

		//
		// 0 = OUT
		// 1 = IN
		//
		unsigned __int64 direction : 1;

		//
		// 0 = not string
		// 1 = string
		//
		unsigned __int64 string_instruction : 1;

		//
		// 0 = not REP
		// 1 = REP
		//
		unsigned __int64 rep : 1;

		//
		// 0 = DX
		// 1 = immediate
		//
		unsigned __int64 operand_encoding : 1;

		//
		// Not currently defined
		//
		unsigned __int64 reserved1 : 9;

		//
		// as specified in DX or in an immediate operand
		//
		unsigned __int64 port_number : 16;

		//
		// Not currently defined. These bits exist only on processors that support Intel 64 architecture.
		//
		unsigned __int64 reserved2 : 32;
	};
};

union __exit_qualification_dr 
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 debug_register_number : 3;

		unsigned __int64 reserved1 : 1;

		//
		// 0 = MOV to DR
		// 1 = MOV from DR
		//
		unsigned __int64 access_direction : 1;

		unsigned __int64 reserved2 : 3;

		unsigned __int64 gp_register : 4;

		unsigned __int64 reserved3 : 52;
	};
};

unsigned __int64 return_rsp_for_vmxoff();

unsigned __int64 return_rip_for_vmxoff();

bool vmexit_handler(__vmexit_guest_registers * guest_registers);

void adjust_rip(__vcpu* vcpu);