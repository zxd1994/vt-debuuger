#pragma once

union __rflags
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 carry_flag : 1;
        unsigned __int64 read_as_1 : 1;
        unsigned __int64 parity_flag : 1;
        unsigned __int64 reserved_1 : 1;
        unsigned __int64 auxiliary_carry_flag : 1;
        unsigned __int64 reserved_2 : 1;
        unsigned __int64 zero_flag : 1;
        unsigned __int64 sign_flag : 1;
        unsigned __int64 trap_flag : 1;
        unsigned __int64 interrupt_enable_flag : 1;
        unsigned __int64 direction_flag : 1;
        unsigned __int64 overflow_flag : 1;
        unsigned __int64 io_privilege_level : 2;
        unsigned __int64 nested_task_flag : 1;
        unsigned __int64 reserved_3 : 1;
        unsigned __int64 resume_flag : 1;
        unsigned __int64 virtual_8086_mode_flag : 1;
        unsigned __int64 alignment_check_flag : 1;
        unsigned __int64 virtual_interrupt_flag : 1;
        unsigned __int64 virtual_interrupt_pending_flag : 1;
        unsigned __int64 identification_flag : 1;
    };
};