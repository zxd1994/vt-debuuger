#pragma once

struct __vmcall_hook_page
{
	void* target_adress;
	void* hook_function;
	void** origin_adress;
	void* code_cave;
	unsigned __int8 protection_mask;
	bool swap_context;
};

struct __vmcall_unhook_page
{
	unsigned __int64 physical_adress;
	bool unhook_all;
};

struct __vmcall_hook_msr_lstar
{
	unsigned __int64 new_lstar_value;
};

struct __vmcall_invept
{
	bool invept_all_context;
};

void restore_segment_registers();
void call_vmxoff(__vcpu* vcpu);
//void vmcall_operations(__vmexit_guest_registers_t* guest_regs);
void vmexit_vmcall_handler(__vcpu* vcpu);