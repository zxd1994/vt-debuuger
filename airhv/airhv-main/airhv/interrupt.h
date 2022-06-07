#pragma once
#define RESET_IO_PORT 0xCF9

enum __exception_vectors
{
    EXCEPTION_VECTOR_DIVIDE_ERROR,
    EXCEPTION_VECTOR_SINGLE_STEP,
    EXCEPTION_VECTOR_NMII,
    EXCEPTION_VECTOR_BREAKPOINT,
    EXCEPTION_VECTOR_OVERFLOW,
    EXCEPTION_VECTOR_BOUND_RANGE_EXCEEDED,
    EXCEPTION_VECTOR_UNDEFINED_OPCODE,
    EXCEPTION_VECTOR_NO_MATH_COPROCESSOR,
    EXCEPTION_VECTOR_DOUBLE_FAULTT,
    EXCEPTION_VECTOR_RESERVED0,
    EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR,
    EXCEPTION_VECTOR_SEGMENT_NOT_PRESENTT,
    EXCEPTION_VECTOR_STACK_SEGMENT_FAULT,
    EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT,
    EXCEPTION_VECTOR_PAGE_FAULT,
    EXCEPTION_VECTOR_RESERVED1,
    EXCEPTION_VECTOR_MATH_FAULT,
    EXCEPTION_VECTOR_ALIGNMENT_CHECK,
    EXCEPTION_VECTOR_MACHINE_CHECK,
    EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR,
    EXCEPTION_VECTOR_VIRTUAL_EXCEPTION,
    EXCEPTION_VECTOR_RESERVED2,
    EXCEPTION_VECTOR_RESERVED3,
    EXCEPTION_VECTOR_RESERVED4,
    EXCEPTION_VECTOR_RESERVED5,
    EXCEPTION_VECTOR_RESERVED6,
    EXCEPTION_VECTOR_RESERVED7,
    EXCEPTION_VECTOR_RESERVED8,
    EXCEPTION_VECTOR_RESERVED9,
    EXCEPTION_VECTOR_RESERVED10,
    EXCEPTION_VECTOR_RESERVED11,
    EXCEPTION_VECTOR_RESERVED12
};

enum interrupt_type
{
    INTERRUPT_TYPE_EXTERNAL_INTERRUPT = 0,
    INTERRUPT_TYPE_RESERVED = 1,
    INTERRUPT_TYPE_NMI = 2,
    INTERRUPT_TYPE_HARDWARE_EXCEPTION = 3,
    INTERRUPT_TYPE_SOFTWARE_INTERRUPT = 4,
    INTERRUPT_TYPE_PRIVILEGED_SOFTWARE_INTERRUPT = 5,
    INTERRUPT_TYPE_SOFTWARE_EXCEPTION = 6,
    INTERRUPT_TYPE_OTHER_EVENT = 7
};

union __vmentry_interrupt_info
{
    unsigned __int32 all;
    struct
    {
        unsigned __int32 interrupt_vector : 8;
        unsigned __int32 interruption_type : 3;
        unsigned __int32 deliver_error_code : 1;
        unsigned __int32 reserved : 19;
        unsigned __int32 valid : 1;

    };
};

struct __vmentry_event_information
{
    __vmentry_interrupt_info interrupt_info;
    unsigned __int32 instruction_length;
    unsigned __int64 error_code;
};

union __vmexit_interrupt_info
{
    struct 
    {
        unsigned __int32 vector : 8;
        unsigned __int32 interruption_type : 3;
        unsigned __int32 error_code_valid : 1;
        unsigned __int32 nmi_unblocking : 1;
        unsigned __int32 reserved : 18;
        unsigned __int32 valid : 1;
    };
    unsigned __int32 all;
};

union __reset_control_register
{
    unsigned __int8 all;
    struct
    {
        unsigned __int8 reserved0 : 1;
        unsigned __int8 system_reset : 1;
        unsigned __int8 reset_cpu : 1;
        unsigned __int8 full_reset : 1;
        unsigned __int8 reserved1 : 4;
    };
};
