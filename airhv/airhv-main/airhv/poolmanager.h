#pragma once
#include <ntddk.h>

namespace pool_manager
{
    enum allocation_intention
    {
        INTENTION_NONE,
        INTENTION_TRACK_HOOKED_PAGES,
        INTENTION_EXEC_TRAMPOLINE,
        INTENTION_SPLIT_PML2,
        INTENTION_TRACK_HOOKED_FUNCTIONS
    };

    struct __request_new_allocation
    {
        unsigned __int64 size[10];
        unsigned __int32 count[10];
        allocation_intention intention[10];
    };

    struct __pool_manager
    {
        __request_new_allocation* allocation_requests;
        PLIST_ENTRY list_of_allocated_pools;
        volatile long lock_for_request_allocation;
        volatile long lock_for_reading_pool;
        bool is_request_for_allocation_recived;
    };

    struct __pool_table
    {
        void* address;
        unsigned __int64  size;
        allocation_intention intention;
        LIST_ENTRY pool_list;
        bool is_busy;
        bool recycled;
    };

    /// <summary>
    /// Writes all information about allocated pools
    /// </summary>
    void dump_pools_info();

    /// <summary>
    /// Request allocation
    /// </summary>
    /// <param name="size">Size of pool</param>
    /// <param name="count">Number of pools to allocate</param>
    /// <param name="intention"></param>
    /// <returns></returns>
    bool request_allocation(unsigned __int64 size, unsigned __int32 count, allocation_intention intention);

    /// <summary>
    /// Initalize pool manager struct and preallocate pools
    /// </summary>
    /// <returns> status </returns>
    bool initialize();

    /// <summary>
    /// Free all allocted pools
    /// </summary>
    void uninitialize();

    /// <summary>
    /// Set information that pool is no longer used by anyone and mark as recycled
    /// </summary>
    /// <param name="address"></param>
    void release_pool(void* address);

    /// <summary>
    /// Allocate all requested pools
    /// </summary>
    /// <returns></returns>
    bool perform_allocation();

    /// <summary>
    /// Returns pre allocated pool and request new one for allocation
    /// </summary>
    /// <param name="intention">Indicates what will be pool used for</param>
    /// <param name="new_pool">If set new pool will (with same properties) be requested to allocate</param>
    /// <param name="size">Only if new_pool is true. Size of new pool</param>
    /// <returns></returns>
    template <typename T>
    T request_pool(allocation_intention intention, bool new_pool, unsigned __int64 size)
    {
        PLIST_ENTRY current = 0;
        void* address = 0;
        bool is_recycled = false;
        __pool_table* pool_table;
        current = g_vmm_context->pool_manager->list_of_allocated_pools;

        spinlock::lock(&g_vmm_context->pool_manager->lock_for_reading_pool);

        while (g_vmm_context->pool_manager->list_of_allocated_pools != current->Flink)
        {
            current = current->Flink;

            // Get the head of the record
            pool_table = (__pool_table*)CONTAINING_RECORD(current, __pool_table, pool_list);

            if (pool_table->intention == intention && pool_table->is_busy == false)
            {
                pool_table->is_busy = true;
                is_recycled = pool_table->recycled;
                address = pool_table->address;
                break;
            }
        }

        spinlock::unlock(&g_vmm_context->pool_manager->lock_for_reading_pool);

        //
        // If pool which we got is recycled then we don't allocate
        // a new one because we don't want to overload memory, If there wasn't any preallocated pool
        // this function will send a request
        //
        if (new_pool == true && is_recycled == false)
            request_allocation(size, 1, intention);

        return (T)address;
    }
}
