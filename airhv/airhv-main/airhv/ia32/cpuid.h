#pragma once

#define QUERY_CPUID_BIT(x, b)        ((x) & (1 << b))
#define SET_CPUID_BIT(x, b)            (x = (x) | (1 << b))
#define CLR_CPUID_BIT(x, b)            ((x) & ~(1 << b))

#define CPUID_EXTENDED_FEATURES           0x00000007
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS 0x40000000
#define CPUID_HV_INTERFACE                0x40000001
#define CPUID_PROCESSOR_FEATURES          0x00000001

union __cpuid_info
{
    struct
    {
        int cpu_info[4];
    };

    struct
    {
        unsigned __int32 eax;
        unsigned __int32 ebx;
        unsigned __int32 ecx;
        unsigned __int32 edx;
    };

    struct
    {
        union
        {
            unsigned __int32 flags;

            struct
            {
                unsigned __int32 stepping_id : 4;
                unsigned __int32 model : 4;
                unsigned __int32 family_id : 4;
                unsigned __int32 processor_type : 2;
                unsigned __int32 reserved1 : 2;
                unsigned __int32 extended_model_id : 4;
                unsigned __int32 extended_family_id : 8;
                unsigned __int32 reserved2 : 4;
            };
        } version_information;

        union
        {
            unsigned __int32 flags;

            struct
            {
                unsigned __int32 brand_index : 8;
                unsigned __int32 clflush_line_size : 8;
                unsigned __int32 max_addressable_ids : 8;
                unsigned __int32 initial_apic_id : 8;
            };
        } additional_information;

        union
        {
            unsigned __int32 flags;

            struct
            {
                unsigned __int32 streaming_simd_extensions_3 : 1;
                unsigned __int32 pclmulqdq_instruction : 1;
                unsigned __int32 ds_area_64bit_layout : 1;
                unsigned __int32 monitor_mwait_instruction : 1;
                unsigned __int32 cpl_qualified_debug_store : 1;
                unsigned __int32 virtual_machine_extensions : 1;
                unsigned __int32 safer_mode_extensions : 1;
                unsigned __int32 enhanced_intel_speedstep_technology : 1;
                unsigned __int32 thermal_monitor_2 : 1;
                unsigned __int32 supplemental_streaming_simd_extensions_3 : 1;
                unsigned __int32 l1_context_id : 1;
                unsigned __int32 silicon_debug : 1;
                unsigned __int32 fma_extensions : 1;
                unsigned __int32 cmpxchg16b_instruction : 1;
                unsigned __int32 xtpr_update_control : 1;
                unsigned __int32 perfmon_and_debug_capability : 1;
                unsigned __int32 reserved1 : 1;
                unsigned __int32 process_context_identifiers : 1;
                unsigned __int32 direct_cache_access : 1;
                unsigned __int32 sse41_support : 1;
                unsigned __int32 sse42_support : 1;
                unsigned __int32 x2apic_support : 1;
                unsigned __int32 movbe_instruction : 1;
                unsigned __int32 popcnt_instruction : 1;
                unsigned __int32 tsc_deadline : 1;
                unsigned __int32 aesni_instruction_extensions : 1;
                unsigned __int32 xsave_xrstor_instruction : 1;
                unsigned __int32 osx_save : 1;
                unsigned __int32 avx_support : 1;
                unsigned __int32 half_precision_conversion_instructions : 1;
                unsigned __int32 rdrand_instruction : 1;
                unsigned __int32 hypervisor_present : 1;
            };
        } feature_information_ecx;

        union
        {
            unsigned __int32 flags;

            struct
            {
                unsigned __int32 floating_point_unit_on_chip : 1;
                unsigned __int32 virtual_8086_mode_enhancements : 1;
                unsigned __int32 debugging_extensions : 1;
                unsigned __int32 page_size_extension : 1;
                unsigned __int32 timestamp_counter : 1;
                unsigned __int32 rdmsr_wrmsr_instructions : 1;
                unsigned __int32 physical_address_extension : 1;
                unsigned __int32 machine_check_exception : 1;
                unsigned __int32 cmpxchg8b : 1;
                unsigned __int32 apic_on_chip : 1;
                unsigned __int32 reserved1 : 1;
                unsigned __int32 sysenter_sysexit_instructions : 1;
                unsigned __int32 memory_type_range_registers : 1;
                unsigned __int32 page_global_bit : 1;
                unsigned __int32 machine_check_architecture : 1;
                unsigned __int32 conditional_move_instructions : 1;
                unsigned __int32 page_attribute_table : 1;
                unsigned __int32 page_size_extension_36bit : 1;
                unsigned __int32 processor_serial_number : 1;
                unsigned __int32 clflush : 1;
                unsigned __int32 reserved2 : 1;
                unsigned __int32 debug_store : 1;
                unsigned __int32 thermal_control_msrs_for_acpi : 1;
                unsigned __int32 mmx_support : 1;
                unsigned __int32 fxsave_fxrstor_instructions : 1;
                unsigned __int32 sse_support : 1;
                unsigned __int32 sse2_support : 1;
                unsigned __int32 self_snoop : 1;
                unsigned __int32 hyper_threading_technology : 1;
                unsigned __int32 thermal_monitor : 1;
                unsigned __int32 reserved3 : 1;
                unsigned __int32 pending_break_enable : 1;
            };
        } feature_information_edx;
    }cpuid_eax_01;

    struct
    {
        union
        {
            unsigned __int32 flags;

            struct
            {
                unsigned __int32 perf_mon_arch_ver_id : 8;
                unsigned __int32 gp_perf_mon_counter_number : 8;
                unsigned __int32 gp_perf_mon_counter_bit_width : 8;
                unsigned __int32 ebx_bit_vector_length : 8;
            };
        } feature_information_eax;

        union
        {
            unsigned __int32 flags;

            struct
            {
                unsigned __int32 core_cycles : 1;
                unsigned __int32 instructions_retired : 1;
                unsigned __int32 reference_cycles : 1;
                unsigned __int32 last_level_cache_references : 1;
                unsigned __int32 last_level_cache_misses : 1;
                unsigned __int32 branch_instructions_retired : 1;
                unsigned __int32 branch_misprediction_retired : 1;
                unsigned __int32 reserved : 25;
            };
        } feature_information_ebx;

        union
        {
            unsigned __int32 flags;

            struct
            {
                unsigned __int32 reserved : 32;
            };
        } feature_information_ecx;

        union
        {
            unsigned __int32 flags;

            struct
            {
                unsigned __int32 fixed_counters_number : 5;
                unsigned __int32 fixed_counters_number_bits : 8;
                unsigned __int32 reserved : 19;
            };
        } feature_information_edx;
    }cpuid_eax_0a;
};