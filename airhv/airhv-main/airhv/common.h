#pragma once
#include <ntddk.h>
#include "ia32\ept.h"
#include "poolmanager.h"
#include "ia32\exception.h"
#include "ia32\mtrr.h"
#include "ia32\rflags.h"

extern "C" size_t __fastcall LDE(const void* lpData, unsigned int size);

#define VMCALL_IDENTIFIER 0xCDAEFAEDBBAEBEEF
#define VMM_TAG 'vhra'
#define VMM_STACK_SIZE 0x6000

#define LARGE_PAGE_SIZE 0x200000
#define GET_PFN(_VAR_) (_VAR_ >> PAGE_SHIFT)

#define MASK_GET_HIGHER_32BITS(_ARG_)(_ARG_ & 0xffffffff00000000)
#define MASK_GET_LOWER_32BITS(_ARG_)(_ARG_ & 0xffffffff)
#define MASK_GET_LOWER_16BITS(_ARG_)(_ARG_ & 0xffff)
#define MASK_GET_LOWER_8BITS(_ARG_)(_ARG_ & 0xff)
#define MASK_32BITS 0xffffffff

struct __vmexit_guest_registers
{
    __m128 xmm[6];
    unsigned __int64 r15;
    unsigned __int64 r14;                  
    unsigned __int64 r13;
    unsigned __int64 r12;                  
    unsigned __int64 r11;
    unsigned __int64 r10;                  
    unsigned __int64 r9;
    unsigned __int64 r8;                   
    unsigned __int64 rdi;
    unsigned __int64 rsi;
    unsigned __int64 rbp;
    unsigned __int64 rsp;
    unsigned __int64 rbx;
    unsigned __int64 rdx;                  
    unsigned __int64 rcx;
    unsigned __int64 rax;
};

struct __ept_state
{
    LIST_ENTRY hooked_page_list;
    __mtrr_range_descriptor memory_range[100];
    unsigned __int32 enabled_memory_ranges;
    unsigned __int8 default_memory_type;
    __eptp* ept_pointer;
    __vmm_ept_page_table* ept_page_table;
    volatile long pml_lock;
};

struct __vmcs
{
    union
    {
        unsigned int all;
        struct
        {
            unsigned int revision_identifier : 31;
            unsigned int shadow_vmcs_indicator : 1;
        };
    } header;
    unsigned int abort_indicator;
    char data[0x1000 - 2 * sizeof(unsigned)];
};

struct __vcpu
{
    void* vmm_stack;

    __vmcs* vmcs;
    unsigned __int64 vmcs_physical;

    __vmcs* vmxon;
    unsigned __int64 vmxon_physical;

    struct __vmexit_info
    {
        __vmexit_guest_registers* guest_registers;

        unsigned __int64 guest_rip;

       __rflags guest_rflags;

        unsigned __int64 instruction_length;

        unsigned __int64 reason;

        unsigned __int64 qualification;

        unsigned __int64 instruction_information;

    }vmexit_info;

    struct __vcpu_status
    {
        unsigned __int64 vmx_on;
        unsigned __int64 vmm_launched;
    }vcpu_status;

    struct __vmx_off_state
    {
        unsigned __int64  vmx_off_executed;
        unsigned __int64  guest_rip;
        unsigned __int64  guest_rsp;
    }vmx_off_state;

    struct __vcpu_bitmaps
    {
        unsigned __int8* msr_bitmap;
        unsigned __int64 msr_bitmap_physical;

        unsigned __int8* io_bitmap_a;
        unsigned __int64 io_bitmap_a_physical;

        unsigned __int8* io_bitmap_b;
        unsigned __int64 io_bitmap_b_physical;
    }vcpu_bitmaps;
};

struct __vmm_context
{
    __vcpu** vcpu_table;
    pool_manager::__pool_manager* pool_manager;
    __ept_state* ept_state;

    unsigned __int32 processor_count;
    unsigned __int32 highest_basic_leaf;
    bool hv_presence;
};

extern __vmm_context* g_vmm_context;

namespace spinlock 
{
    bool try_lock(volatile long* lock);
    void lock(volatile long* lock);
    void unlock(volatile long* lock);
}