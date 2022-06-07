#pragma once
/// <summary>
/// Initialize and launch vmm
/// </summary>
/// <returns> status </returns>
bool vmm_init();

/// <summary>
/// Deallocate all structures
/// </summary>
void free_vmm_context();