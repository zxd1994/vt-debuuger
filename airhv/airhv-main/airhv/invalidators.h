#pragma once
#include <ntddk.h>

struct __invept_descriptor
{
	unsigned __int64 ept_pointer;
	unsigned __int64 reserved;
};

struct __invpcid_descriptor 
{
	unsigned __int64 pcid : 12;
	unsigned __int64 reserved : 52;
	unsigned __int64 linear_address;
};

struct __invvpid_descriptor
{
	union
	{
		unsigned __int64 vpid : 16;
		unsigned __int64 reserved : 48;
	};

	unsigned __int64 linear_address;
};

enum invept_type
{
	INVEPT_SINGLE_CONTEXT = 0x00000001,
	INVEPT_ALL_CONTEXTS = 0x00000002
};

enum invvpid_type
{
	INVVPID_INVIDUAL_ADDRESS,
	INVVPID_SINGLE_CONTEXT,
	INVVPID_ALL_CONTEXTS,
	INVVPID_SINGLE_EXCEPT_GLOBAL_TRANSLATIONS
};

enum invpcid_type
{
	INVPCID_INVIDUAL_ADDRESS,
	INVPCID_SINGLE_CONTEXT,
	INVPCID_ALL_CONTEXTS,
	INVPCID_ALL_CONTEXTS_EXCEPT_GLOBAL_TRANSLATIONS
};

/// <summary>
/// Invept single context
/// </summary>
/// <param name="EptPointer"></param>
void invept_single_context(unsigned __int64 ept_pointer);

/// <summary>
/// Invept all contexts
/// </summary>
void invept_all_contexts();

/// <summary>
/// Invvpid invidual address
/// </summary>
/// <param name="linear_address"> Logical processor invalidates mappings for the linear address </param>
/// <param name="vpid"> Invalidates entries in the TLBs and paging-structure caches based on this vpid </param>
void invvpid_invidual_address(unsigned __int64 linear_address, unsigned __int8 vpid);

/// <summary>
/// Invvpid single context
/// </summary>
/// <param name="vpid"> Invalidates entries in the TLBs and paging-structure caches based on this vpid </param>
void invvpid_single_context(unsigned __int8 vpid);

/// <summary>
/// Invvpid all contexts
/// </summary>
void invvpid_all_contexts();

/// <summary>
/// Invvpid single context except global translations
/// </summary>
/// <param name="vpid"> Invalidates entries in the TLBs and paging-structure caches based on this vpid </param>
void invvpid_single_context_except_global_translations(unsigned __int8 vpid);
