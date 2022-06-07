#pragma once
#include <ntddk.h>
#include "common.h"

enum __syscall_type
{
	SYSCALL_NT,
	SYSCALL_WIN32K
};

namespace hv 
{
	/// <summary>
	/// Check if cpu support virtualization
	/// </summary>
	/// <returns></returns>
	bool virtualization_support();

	/// <summary>
	/// Disable vmx operation
	/// </summary>
	/// <returns></returns>
	void disable_vmx_operation();

	/// <summary>
	/// Read vmcs field
	/// </summary>
	/// <param name="vmcs_field"></param>
	/// <returns></returns>
	unsigned __int64 vmread(unsigned __int64 vmcs_field);

	/// <summary>
	/// Dump whole vmcs structure
	/// </summary>
	void dump_vmcs();

	/// <summary>
	/// Set 1 msr in msr bitmap
	/// </summary>
	/// <param name="msr"> Msr number </param>
	/// <param name="vcpu"> Pointer to current vcpu </param>
	/// <param name="read"> If set vmexit occur on reading this msr </param>
	/// <param name="write"> If set vmexit occur on writing to this msr </param>
	/// <param name="value"> If true set msr bit else clear </param>
	void set_msr_bitmap(unsigned __int32 msr, __vcpu* vcpu, bool read, bool write, bool value);

	/// <summary>
	/// Set or unset bit in io port bitmap
	/// </summary>
	/// <param name="io_port"> IO port which you want to set</param>
	/// <param name="vcpu"> Pointer to current vcpu </param>
	/// <param name="value"> If true then set bit else unset bit</param>
	void set_io_bitmap(unsigned __int16 io_port, __vcpu* vcpu, bool value);

	/// <summary>
	/// 
	/// </summary>
	/// <returns> Return current guest privilage level</returns>
	unsigned __int8 get_guest_cpl();

	/// <summary>
	/// Swap cr3 with current process dtb
	/// </summary>
	/// <returns> old cr3 </returns>
	unsigned __int64 swap_context();

	/// <summary>
	/// Restore cr3
	/// </summary>
	/// <param name="old_cr3"></param>
	void restore_context(unsigned __int64 old_cr3);

	/// <summary>
	/// Check if address is canonicial (level 4 paging)
	/// </summary>
	/// <param name="address"></param>
	/// <returns></returns>
	bool is_address_canonical(unsigned __int64 address);

	/// <summary>
	/// Get system directory table base
	/// </summary>
	/// <returns></returns>
	unsigned __int64 get_system_directory_table_base();

	/// <summary>
	/// Inject interrupt/exception to guest system
	/// </summary>
	/// <param name="vector"></param>
	/// <param name="type"></param>
	/// <param name="error_code"></param>
	/// <param name="deliver_error_code"></param>
	void inject_interruption(unsigned __int32 vector, unsigned __int32 type, unsigned __int32 error_code, bool deliver_error_code);

	/// <summary>
	/// Write to reset io port to perform hard reset
	/// </summary>
	void hard_reset();

	/// <summary>
	/// Used to get address passed by user in inpvcid
	/// </summary>
	/// <param name="guest_registers"></param>
	/// <returns></returns>
	unsigned __int64 get_guest_address(__vcpu* vcpu);

	/// <summary>
	/// Write to vmcs field
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="vmcs_field">Field number</param>
	/// <param name="value"> Value </param>
	template <typename T>
	void vmwrite(unsigned __int64 vmcs_field, T value)
	{
		__vmx_vmwrite(vmcs_field, (unsigned __int64)value);
	}
}