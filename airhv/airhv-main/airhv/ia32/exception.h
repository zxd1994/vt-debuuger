#pragma once
union __exception_bitmap
{
    unsigned __int32 all;
    struct
    {
        unsigned __int32 divide_error : 1;
        unsigned __int32 debug : 1;
        unsigned __int32 nmi_interrupt : 1;
        unsigned __int32 breakpoint : 1;
        unsigned __int32 overflow : 1;
        unsigned __int32 bound : 1;
        unsigned __int32 invalid_opcode : 1;
        unsigned __int32 device_not_available : 1;
        unsigned __int32 double_fault : 1;
        unsigned __int32 coprocessor_segment_overrun : 1;
        unsigned __int32 invalid_tss : 1;
        unsigned __int32 segment_not_present : 1;
        unsigned __int32 stack_segment_fault : 1;
        unsigned __int32 general_protection : 1;
        unsigned __int32 page_fault : 1;
        unsigned __int32 x87_floating_point_error : 1;
        unsigned __int32 alignment_check : 1;
        unsigned __int32 machine_check : 1;
        unsigned __int32 simd_floating_point_error : 1;
        unsigned __int32 virtualization_exception : 1;
    };
};