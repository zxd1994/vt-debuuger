#pragma once
#include "common.h"

#define IA32_FEATURE_CONTROL 0x3A
#define IA32_VMX_BASIC 0x480
#define IA32_VMX_ENTRY_CTLS 0x484
#define IA32_VMX_CR0_FIXED0 0x486
#define IA32_VMX_CR0_FIXED1 0x487
#define IA32_VMX_CR4_FIXED0 0x488
#define IA32_VMX_CR4_FIXED1 0x489
#define IA32_VMX_TRUE_ENTRY_CTLS 0x490
#define IA32_VMX_TRUE_EXIT_CTLS 0x48F
#define IA32_VMX_EXIT_CTLS 0x483
#define IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define IA32_VMX_PINBASED_CTLS 0x481
#define IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define IA32_VMX_PROCBASED_CTLS 0x482
#define IA32_VMX_PROCBASED_CTLS2 0x48B
#define IA32_DEBUGCTL 0x1D9
#define IA32_SYSENTER_CS 0x174
#define IA32_SYSENTER_ESP 0x175
#define IA32_SYSENTER_EIP 0x176
#define IA32_PERF_GLOBAL_CTRL 0x38F
#define IA32_PAT 0x277
#define IA32_EFER 0xC0000080
#define IA32_BNDCFGS 0xD90
#define IA32_RTIT_CTL 0x570
#define IA32_S_CET 0x6A2
#define IA32_INTERRUPT_SSP_TABLE_ADDR 0x6A8
#define IA32_XSS 0xDA0
#define IA32_PKRS 0x6E1
#define IA32_FS_BASE 0xC0000100
#define IA32_GS_BASE 0xC0000101
#define IA32_TSC_AUX 0xC0000103
#define IA32_MTRRCAP 0xFE
#define IA32_MTRR_DEF_TYPE 0x2FF
#define IA32_MTRR_PHYSBASE0 0x200
#define IA32_MTRR_PHYSMASK0 0x201
#define IA32_SMRR_PHYSBASE 0x1F2
#define IA32_SMRR_PHYSMASK 0x1F3
#define IA32_MTRR_FIX64K_00000 0x250
#define IA32_MTRR_FIX16K_80000 0x258
#define IA32_MTRR_FIX4K_C0000 0x268
#define IA32_LSTAR 0xC0000082
#define SYNTHETHIC_MSR_LOW 0x40000000
#define SYNTHETHIC_MSR_HI  0x400000F0
#define MSR_MASK_LOW ((unsigned __int64)(unsigned __int32) - 1)

union __msr
{
    unsigned __int64 all;
    struct
    {
        unsigned __int32 low;
        unsigned __int32 high;
    };
};

union __ia32_efer_t
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 syscall_enable : 1;
        unsigned __int64 reserved_0 : 7;
        unsigned __int64 long_mode_enable : 1;
        unsigned __int64 reserved_1 : 1;
        unsigned __int64 long_mode_active : 1;
        unsigned __int64 execute_disable : 1;
        unsigned __int64 reserved_2 : 52;
    };
};

union __ia32_feature_control_msr
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 lock : 1;
        unsigned __int64 vmxon_inside_smx : 1;
        unsigned __int64 vmxon_outside_smx : 1;
        unsigned __int64 reserved_0 : 5;
        unsigned __int64 senter_local : 6;
        unsigned __int64 senter_global : 1;
        unsigned __int64 reserved_1 : 1;
        unsigned __int64 sgx_launch_control_enable : 1;
        unsigned __int64 sgx_global_enable : 1;
        unsigned __int64 reserved_2 : 1;
        unsigned __int64 lmce : 1;
        unsigned __int64 system_reserved : 42;
    };
};

union __vmx_misc_msr_t
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 vmx_preemption_tsc_rate : 5;
        unsigned __int64 store_lma_in_vmentry_control : 1;
        unsigned __int64 activate_state_bitmap : 3;
        unsigned __int64 reserved_0 : 5;
        unsigned __int64 pt_in_vmx : 1;
        unsigned __int64 rdmsr_in_smm : 1;
        unsigned __int64 cr3_target_value_count : 9;
        unsigned __int64 max_msr_vmexit : 3;
        unsigned __int64 allow_smi_blocking : 1;
        unsigned __int64 vmwrite_to_any : 1;
        unsigned __int64 interrupt_mod : 1;
        unsigned __int64 reserved_1 : 1;
        unsigned __int64 mseg_revision_identifier : 32;
    };
};

union __vmx_basic_msr
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 vmcs_revision_identifier : 31;
        unsigned __int64 always_0 : 1;
        unsigned __int64 vmxon_region_size : 13;
        unsigned __int64 reserved_1 : 3;
        unsigned __int64 vmxon_physical_address_width : 1;
        unsigned __int64 dual_monitor_smi : 1;
        unsigned __int64 memory_type : 4;
        unsigned __int64 io_instruction_reporting : 1;
        unsigned __int64 true_controls : 1;
    };
};