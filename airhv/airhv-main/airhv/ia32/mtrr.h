#pragma once
enum __mtrr_memory_types
{
	MEMORY_TYPE_UNCACHEABLE,
	MEMORY_TYPE_WRITE_COMBINING,
	MEMORY_TYPE_WRITE_THROUGH = 4,
	MEMORY_TYPE_WRITE_PROTECTED,
	MEMORY_TYPE_WRITE_BACK,
	MEMORY_TYPE_INVALID = 255,
};

struct __mtrr_range_descriptor
{
	unsigned __int64 physcial_base_address;
	unsigned __int64 physcial_end_address;
	unsigned __int8 memory_type;
	bool fixed_range;
};

union __mtrr_physmask_reg
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 reserved : 11;
		unsigned __int64 valid : 1;
		unsigned __int64 physmask : 36;
		unsigned __int64 reserved2 : 16;
	};
};

union __mtrr_physbase_reg
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 type : 8;
		unsigned __int64 reserved : 4;
		unsigned __int64 physbase : 36;
		unsigned __int64 reserved2 : 16;
	};
};

union __mtrr_cap_reg
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 range_register_number : 8;
		unsigned __int64 fixed_range_support : 1;
		unsigned __int64 reserved : 1;
		unsigned __int64 write_combining_support : 1;
		unsigned __int64 smrr_support : 1;
		unsigned __int64 reserved2 : 52;
	};
};

union __mtrr_def_type 
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 memory_type : 8;
		unsigned __int64 reserved1 : 2;
		unsigned __int64 fixed_range_mtrr_enabled : 1;
		unsigned __int64 mtrr_enabled : 1;
		unsigned __int64 reserved2 : 52;
	};
};

union __mtrr_fixed_range_type 
{
	unsigned __int64 all;
	struct
	{
		unsigned __int8 types[8];
	};
};