#pragma once
union __dr6
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 breakpoint_condition : 4;
        unsigned __int64 reserved_1 : 8; // always 1
        unsigned __int64 reserved_2 : 1; // always 0
        unsigned __int64 debug_register_access_detected : 1;
        unsigned __int64 single_instruction : 1;
        unsigned __int64 task_switch : 1;
        unsigned __int64 restricted_transactional_memory : 1;
        unsigned __int64 reserved_3 : 15; // always 1
    };
};

union __dr7
{
    unsigned __int64 all;
    struct
    {
        unsigned __int64 local_breakpoint_0 : 1;
        unsigned __int64 global_breakpoint_0 : 1;
        unsigned __int64 local_breakpoint_1 : 1;
        unsigned __int64 global_breakpoint_1 : 1;
        unsigned __int64 local_breakpoint_2 : 1;
        unsigned __int64 global_breakpoint_2 : 1;
        unsigned __int64 local_breakpoint_3 : 1;
        unsigned __int64 global_breakpoint_3 : 1;
        unsigned __int64 local_exact_breakpoint : 1;
        unsigned __int64 global_exact_breakpoint : 1;
        unsigned __int64 reserved_1 : 1; // always 1
        unsigned __int64 restricted_transactional_memory : 1;
        unsigned __int64 reserved_2 : 1; // always 0
        unsigned __int64 general_detect : 1;
        unsigned __int64 reserved_3 : 2; // always 0
        unsigned __int64 read_write_0 : 2;
        unsigned __int64 length_0 : 2;
        unsigned __int64 read_write_1 : 2;
        unsigned __int64 length_1 : 2;
        unsigned __int64 read_write_2 : 2;
        unsigned __int64 length_2 : 2;
        unsigned __int64 read_write_3 : 2;
        unsigned __int64 length_3 : 2;
    };
};
