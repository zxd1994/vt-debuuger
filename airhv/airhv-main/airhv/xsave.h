#pragma once
union __xcomp_bv 
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 reserved1 : 63;
		unsigned __int64 fromat : 1;
	};
};

union __xstate_bv
{
	unsigned __int64 all;
	struct
	{
		unsigned __int64 x87state : 1;
		unsigned __int64 sse_state : 1;
		unsigned __int64 avx_state : 1;
		unsigned __int64 bndregs_state : 1;
		unsigned __int64 bndcsr_state : 1;
		unsigned __int64 opmask_state : 1;
		unsigned __int64 zmm_hi256_state : 1;
		unsigned __int64 hi16_zmm_state : 1;
		unsigned __int64 pt_state : 1;
		unsigned __int64 pkru_state : 1;
		unsigned __int64 reserved1 : 1;
		unsigned __int64 cet_u_state : 1;
		unsigned __int64 cet_s_state : 1;
		unsigned __int64 hdc_state : 1;
		unsigned __int64 reserved2 : 2;
		unsigned __int64 hwp_state : 1;
		unsigned __int64 reserved3 : 46;
		unsigned __int64 special : 1;
	};
};

struct __xsave_header
{
	__xstate_bv xstate_bv;
	__xcomp_bv xcomp_bv;
	unsigned __int64 reserved[6];
};