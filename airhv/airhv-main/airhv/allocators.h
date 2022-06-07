#pragma once
#include <ntddk.h>
#include "common.h"

/// <summary>
/// Allocate NonPagedPool with hypervisor tag, custom size
/// </summary>
/// <typeparam name="T"> Return type </typeparam>
/// <param name="size"> Size of allocation, base value is sizeof(T) </param>
/// <returns></returns>
template <typename T>
inline T allocate_pool(unsigned __int64 size)
{
    return (T)ExAllocatePoolWithTag(NonPagedPool, size, VMM_TAG);
}

/// <summary>
/// Allocate NonPagedPool size of T with hypervisor tag,
/// </summary>
/// <typeparam name="T"> Return type </typeparam>
/// <param name="size"> Size of allocation, base value is sizeof(T) </param>
/// <returns></returns>
template <typename T>
inline T* allocate_pool()
{
    return (T*)ExAllocatePoolWithTag(NonPagedPool, sizeof(T), VMM_TAG);
}

/// <summary>
/// Allocate Contignous memory size of T
/// </summary>
/// <typeparam name="T"> Return type </typeparam>
/// <returns></returns>
template <typename T>
inline T* allocate_contignous_memory()
{
    PHYSICAL_ADDRESS a;
    a.QuadPart = 0ULL - 1;
    return (T*)MmAllocateContiguousMemory(sizeof(T), a);
}

/// <summary>
/// Allocate Contignous memory custom size
/// </summary>
/// <typeparam name="T"> Return type </typeparam>
/// <returns></returns>
template <typename T>
inline T allocate_contignous_memory(unsigned __int64 size)
{
    PHYSICAL_ADDRESS a;
    a.QuadPart = 0ULL - 1;
    return (T)MmAllocateContiguousMemory(size, a);
}

/// <summary>
/// Free pool with tahg
/// </summary>
/// <param name="pool_address"> Base address of pool </param>
inline void free_pool(void* pool_address)
{
    ExFreePoolWithTag(pool_address, VMM_TAG);
}

/// <summary>
/// Free contignous memory
/// </summary>
/// <param name="memory_address"> Contignous memory base address </param>
inline void free_contignous_memory(void* memory_address)
{
    MmFreeContiguousMemory(memory_address);
}