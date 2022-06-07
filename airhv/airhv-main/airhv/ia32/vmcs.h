#pragma once

union __vmx_secondary_processor_based_control
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 virtualize_apic_accesses : 1;
        unsigned __int64 enable_ept : 1;
        unsigned __int64 descriptor_table_exiting : 1;
        unsigned __int64 enable_rdtscp : 1;
        unsigned __int64 virtualize_x2apic : 1;
        unsigned __int64 enable_vpid : 1;
        unsigned __int64 wbinvd_exiting : 1;
        unsigned __int64 unrestricted_guest : 1;
        unsigned __int64 apic_register_virtualization : 1;
        unsigned __int64 virtual_interrupt_delivery : 1;
        unsigned __int64 pause_loop_exiting : 1;
        unsigned __int64 rdrand_exiting : 1;
        unsigned __int64 enable_invpcid : 1;
        unsigned __int64 enable_vmfunc : 1;
        unsigned __int64 vmcs_shadowing : 1;
        unsigned __int64 enable_encls_exiting : 1;
        unsigned __int64 rdseed_exiting : 1;
        unsigned __int64 enable_pml : 1;
        unsigned __int64 use_virtualization_exception : 1;
        unsigned __int64 conceal_vmx_from_pt : 1;
        unsigned __int64 enable_xsave_xrstor : 1;
        unsigned __int64 reserved_0 : 1;
        unsigned __int64 mode_based_execute_control_ept : 1;
        unsigned __int64 sub_page_write_permission_for_ept : 1;
        unsigned __int64 intel_pt_uses_guest_physical_address : 1;
        unsigned __int64 use_tsc_scaling : 1;
        unsigned __int64 enable_user_wait_and_pause : 1;
        unsigned __int64 enable_enclv_exiting : 1;
    };
};

union __vmx_primary_processor_based_control
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 reserved_0 : 2; 
        unsigned __int64 interrupt_window_exiting : 1;
        unsigned __int64 use_tsc_offsetting : 1;
        unsigned __int64 reserved_1 : 3;
        unsigned __int64 hlt_exiting : 1;
        unsigned __int64 reserved_2 : 1;
        unsigned __int64 invldpg_exiting : 1;
        unsigned __int64 mwait_exiting : 1;
        unsigned __int64 rdpmc_exiting : 1;
        unsigned __int64 rdtsc_exiting : 1;
        unsigned __int64 reserved_3 : 2;
        unsigned __int64 cr3_load_exiting : 1;
        unsigned __int64 cr3_store_exiting : 1;
        unsigned __int64 reserved_4 : 2;
        unsigned __int64 cr8_load_exiting : 1;
        unsigned __int64 cr8_store_exiting : 1;
        unsigned __int64 use_tpr_shadow : 1;
        unsigned __int64 nmi_window_exiting : 1;
        unsigned __int64 mov_dr_exiting : 1;
        unsigned __int64 unconditional_io_exiting : 1;
        unsigned __int64 use_io_bitmaps : 1;
        unsigned __int64 reserved_5 : 1;
        unsigned __int64 monitor_trap_flag : 1;
        unsigned __int64 use_msr_bitmaps : 1;
        unsigned __int64 monitor_exiting : 1;
        unsigned __int64 pause_exiting : 1;
        unsigned __int64 active_secondary_controls : 1;
    };
};

union __vmx_pinbased_control_msr
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 external_interrupt_exiting : 1;
        unsigned __int64 reserved_0 : 2;
        unsigned __int64 nmi_exiting : 1;
        unsigned __int64 reserved_1 : 1;
        unsigned __int64 virtual_nmis : 1;
        unsigned __int64 vmx_preemption_timer : 1;
        unsigned __int64 process_posted_interrupts : 1;
    };
};

union __vmx_true_control_settings
{
    unsigned __int64 all;
    struct
    {
        unsigned __int32 allowed_0_settings;
        unsigned __int32 allowed_1_settings;
    };
};

union __vmx_entry_control
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 reserved_0 : 2;
        unsigned __int64 load_dbg_controls : 1;
        unsigned __int64 reserved_1 : 6;
        unsigned __int64 ia32e_mode_guest : 1;
        unsigned __int64 entry_to_smm : 1;
        unsigned __int64 deactivate_dual_monitor_treament : 1;
        unsigned __int64 reserved_3 : 1;
        unsigned __int64 load_ia32_perf_global_control : 1;
        unsigned __int64 load_ia32_pat : 1;
        unsigned __int64 load_ia32_efer : 1;
        unsigned __int64 load_ia32_bndcfgs : 1;
        unsigned __int64 conceal_vmx_from_pt : 1;
        unsigned __int64 load_ia32_rtit_ctl : 1;
        unsigned __int64 load_cet_state : 1;
        unsigned __int64 load_pkrs : 1;
    };
};

union __interrupt_command_register
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 vector : 8;
        unsigned __int64 delivery_mode : 3;
        unsigned __int64 destination_mode : 1;
        unsigned __int64 delivery_status : 1;
        unsigned __int64 reserved_0 : 1;
        unsigned __int64 level : 1;
        unsigned __int64 trigger_mode : 1;
        unsigned __int64 reserved_1 : 2;
        unsigned __int64 destination_short : 2;
        unsigned __int64 reserved_3 : 35;
        unsigned __int64 destination : 8;
    };
};

union __vmx_exit_control
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 reserved_0 : 2;
        unsigned __int64 save_dbg_controls : 1;
        unsigned __int64 reserved_1 : 6;
        unsigned __int64 host_address_space_size : 1;
        unsigned __int64 reserved_2 : 2;
        unsigned __int64 load_ia32_perf_global_control : 1;
        unsigned __int64 reserved_3 : 2;
        unsigned __int64 ack_interrupt_on_exit : 1;
        unsigned __int64 reserved_4 : 2;
        unsigned __int64 save_ia32_pat : 1;
        unsigned __int64 load_ia32_pat : 1;
        unsigned __int64 save_ia32_efer : 1;
        unsigned __int64 load_ia32_efer : 1;
        unsigned __int64 save_vmx_preemption_timer_value : 1;
        unsigned __int64 clear_ia32_bndcfgs : 1;
        unsigned __int64 conceal_vmx_from_pt : 1;
        unsigned __int64 load_ia32_rtit_ctl : 1;
        unsigned __int64 load_cet_state : 1;
        unsigned __int64 load_pkrs : 1;
    };
};

union __vmx_pending_debug_exceptions 
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 b0 : 1;
        unsigned __int64 b1 : 1;
        unsigned __int64 b2 : 1;
        unsigned __int64 b3 : 1;
        unsigned __int64 reserved1 : 8;
        unsigned __int64 enabled_bp : 1;
        unsigned __int64 reserved2 : 1;
        unsigned __int64 bs : 1;
        unsigned __int64 reserved3 : 1;
        unsigned __int64 rtm : 1;
        unsigned __int64 reserved4 : 47;
    };

};

union __vmx_interruptibility_state
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 blocking_by_sti : 1;
        unsigned __int64 blocking_by_mov_ss : 1;
        unsigned __int64 blocking_by_smi : 1;
        unsigned __int64 blocking_by_nmi : 1;
        unsigned __int64 enclave_interruption : 1;
        unsigned __int64 reserved : 27;
    };
};

void fill_vmcs(__vcpu* vcpu, void* guest_rsp);