#pragma warning( disable : 4201)
#include "invalidators.h"
#include "asm\vm_intrin.h"

/// <summary>
/// Invept single context
/// </summary>
/// <param name="EptPointer"></param>
void invept_single_context(unsigned __int64 ept_pointer)
{
	__invept_descriptor descriptor = { 0 };
	descriptor.ept_pointer = ept_pointer;
	descriptor.reserved = 0;
	__invept(INVEPT_SINGLE_CONTEXT, &descriptor);
}

/// <summary>
/// Invept all contexts
/// </summary>
void invept_all_contexts()
{
	__invept_descriptor descriptor = { 0 };
	__invept(INVEPT_ALL_CONTEXTS, &descriptor);
}

/// <summary>
/// Invvpid invidual address
/// </summary>
/// <param name="linear_address"> Logical processor invalidates mappings for the linear address </param>
/// <param name="vpid"> Invalidates entries in the TLBs and paging-structure caches based on this vpid </param>
void invvpid_invidual_address(unsigned __int64 linear_address,unsigned __int8 vpid)
{
	__invvpid_descriptor descriptor = { 0 };
	descriptor.linear_address = linear_address;
	descriptor.vpid = vpid;

	__invvpid(INVVPID_INVIDUAL_ADDRESS,&descriptor);
}

/// <summary>
/// Invvpid single context
/// </summary>
/// <param name="vpid"> Invalidates entries in the TLBs and paging-structure caches based on this vpid </param>
void invvpid_single_context(unsigned __int8 vpid)
{
	__invvpid_descriptor descriptor = { 0 };
	descriptor.vpid = vpid;

	__invvpid(INVVPID_SINGLE_CONTEXT, &descriptor);
}

/// <summary>
/// Invvpid all contexts
/// </summary>
void invvpid_all_contexts()
{
	__invvpid_descriptor descriptor = { 0 };
	__invvpid(INVVPID_ALL_CONTEXTS, &descriptor);
}

/// <summary>
/// Invvpid single context except global translations
/// </summary>
/// <param name="vpid"> Invalidates entries in the TLBs and paging-structure caches based on this vpid </param>
void invvpid_single_context_except_global_translations(unsigned __int8 vpid)
{
	__invvpid_descriptor descriptor = { 0 };
	descriptor.vpid = vpid;
	return __invvpid(INVVPID_SINGLE_EXCEPT_GLOBAL_TRANSLATIONS, &descriptor);
}
