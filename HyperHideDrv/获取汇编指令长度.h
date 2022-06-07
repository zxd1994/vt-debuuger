#ifndef INSN_LEN_H
#define INSN_LEN_H

/* References:
 * Intel 64 and IA-32 Architectures Software Developer's Manuals - Volume 2A Ch. 2
 * http://ref.x86asm.net
 * http://sandpile.org
 */

#ifdef __cplusplus
extern "C" {
#endif

#define Mod_M       0xc0
#define RM_M        0x7
#define Base_M      0x7
#define REX_W       0x8

#define MAX_INSN_LEN_x86    15
#define MAX_INSN_LEN_x86_32 MAX_INSN_LEN_x86
#define MAX_INSN_LEN_x86_64 MAX_INSN_LEN_x86

enum __bits { __b16, __b32, __b64 };

#ifdef __i386__
#define insn_len(insn)  insn_len_x86_32(insn)
#define MAX_INSN_LEN    MAX_INSN_LEN_x86_32
#elif defined(__x86_64__)
#define insn_len(insn)  insn_len_x86_64(insn)
#define MAX_INSN_LEN    MAX_INSN_LEN_x86_64
#endif

/* This function returns the length of an x86 instruction.
 * I assume that instruction is valid.
 */
static inline int __insn_len_x86(void *insn, enum __bits bits) {
	int len = 0, twobytes = 0, has_modrm = 0;
	enum __bits operand_bits = __b32, addr_bits = bits;
	unsigned char *c = (unsigned char*)insn, modrm, opcode;

	/* prefixes
	 *
	 * 0xf0, 0xf2, 0xf3, 0x2e, 0x36
	 * 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67
	 */

	// skip prefixes
	while (*c == 0xf0 || *c == 0xf2 || *c == 0xf3 ||
	       *c == 0x2e || *c == 0x36 || *c == 0x3e || *c == 0x26 ||
	       (*c & 0xfc) == 0x64) {
		if (*c == 0x66) // 16bits operands
			operand_bits = __b16;
		if (*c == 0x67) // 16bits addressing (x86-32), 32bits addressing (x86-64)
			addr_bits = bits == __b32 ? __b16 : __b32;
		c++;
		len++;
	}

	if (bits == __b64 && (*c & 0xf0) == 0x40) { // x86-64 && REX byte
		if (*c & REX_W)
			operand_bits = __b64;
		c++;
		len++;
	}

	/* 0x9b prefix is used only by the following 1byte opcodes
	 *
	 * 0xd9 Mod != 11 Reg/Op = 110 or 111
	 * 0xdb ModR/M = 0xe2 or 0xe3
	 * 0xdd Reg/Op = 110 or 111
	 * 0xdf ModR/M = 0xe0
	 */

	// check for 2bytes opcodes (0x0f prefix)
	if (*c == 0x0f) {
		twobytes = 1;
		c++;
		len++;
	} else if (*c == 0x9b && // check 0x9b prefix
		   ( (c[1] == 0xd9 && (c[2] & Mod_M) != Mod_M && (c[2] & 0x30) == 0x30) ||
		     (c[1] == 0xdb && (c[2] == 0xe2 || c[2] == 0xe3)) ||
		     (c[1] == 0xdd && (c[2] & 0x30) == 0x30) ||
		     (c[1] == 0xdf && c[2] == 0xe0)
			   )) {
		c++;
		len++;
	}

	opcode = *c++;
	len++;

	/* 1byte opcodes that use ModR/M byte:
	 *
	 * 0x00 - 0x03, 0x08 - 0x0b,
	 * 0x10 - 0x13, 0x18 - 0x1b,
	 * 0x20 - 0x23, 0x28 - 0x2b,
	 * 0x30 - 0x33, 0x38 - 0x3b,
	 * 0x62, 0x63, 0x69, 0x6b,
	 * 0x80 - 0x8f, 0xc0, 0xc1,
	 * 0xc4 - 0xc7,
	 * 0xd0 - 0xd3, 0xd8 - 0xdf
	 * 0xf6, 0xf7, 0xfe, 0xff
	 */

	if (!twobytes &&
	    ((opcode & 0xf4) == 0 || (opcode & 0xf4) == 0x10 ||
	     (opcode & 0xf4) == 0x20 || (opcode & 0xf4) == 0x30 ||
	     opcode == 0x62 || opcode == 0x63 || opcode == 0x69 || opcode == 0x6b ||
	     (opcode & 0xf0) == 0x80 || opcode == 0xc0 || opcode == 0xc1 ||
	     (opcode & 0xfc) == 0xc4 || (opcode & 0xfc) == 0xd0 ||
	     (opcode & 0xf8) == 0xd8 || opcode == 0xf6 || opcode == 0xf7 ||
	     opcode == 0xfe || opcode == 0xff))
		has_modrm = 1;

	/* 2bytes opcodes that they *don't* use ModR/M byte:
	 *
	 * 0x05 - 0x09, 0x0b, 0x0e,
	 * 0x30 - 0x37, 0x77, 0x80 - 0x8f,
	 * 0xa0 - 0xa2, 0xa8 - 0xaa, 0xb9
	 * 0xc8 - 0xcf
	 */

	if (twobytes) {
		if (!((opcode >= 0x05 && opcode <= 0x09) || opcode == 0x0b ||
		      opcode == 0x0e || (opcode & 0xf8) == 0x30 || opcode == 0x77 ||
		      (opcode & 0xf0) == 0x80 || (opcode >= 0xa0 && opcode <= 0xa2) ||
		      (opcode >= 0xa8 && opcode <= 0xaa) || (opcode & 0xf8) == 0xc8 ||
		      opcode == 0xb9))
			has_modrm = 1;

		// 3bytes opcodes
		if (opcode == 0x38 || opcode == 0x3a) {
			c++;
			len++;
		}

		// 3DNow! opcode
		if (opcode == 0x0f)
			len++;
	}

	if (has_modrm) {
		len++;
		modrm = *c++;
		if (addr_bits != __b16 && (modrm & (Mod_M | RM_M)) == 5) // Mod = 00 R/M = 101
			len += 4;
		if (addr_bits == __b16 && (modrm & (Mod_M | RM_M)) == 6) // Mod = 00 R/M = 110 and 16bits addressing
			len += 2;
		if ((modrm & Mod_M) == 0x40) // Mod = 01
			len += 1;
		if ((modrm & Mod_M) == 0x80) // Mod = 10
			len += addr_bits == __b16 ? 2 : 4;

		// check SIB byte
		if (addr_bits != __b16 && (modrm & Mod_M) != Mod_M && (modrm & RM_M) == 4) { // if it has SIB
			len++;
			if ((modrm & Mod_M) == 0 && (*c & Base_M) == 5) // Mod = 00   SIB Base = 101
				len += 4;
			c++;
		}
	}

	/* Immediate operands
	 *
	 * 1byte opcode list:
	 *
	 * imm8 (1 byte)
	 *
	 * 0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c, 0x6a, 0x6b, 0x70 - 0x7f,
	 * 0x80, 0x82, 0x83, 0xa8, 0xb0 - 0xb7, 0xc0, 0xc1, 0xc6, 0xcd, 0xd4,
	 * 0xd5, 0xe0 - 0xe7, 0xeb, 0xf6 (Reg/Op = 000 or Reg/Op = 001)
	 *
	 * imm16 (2 bytes)
	 *
	 * 0xc2, 0xca
	 *
	 * imm16/32 (2 bytes if operand_bits == __b16 else 4 bytes)
	 *
	 * 0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d, 0x68, 0x69, 0x81, 0xa9
	 * 0xc7, 0xe8, 0xe9
	 *
	 * imm16/32/64 (2 bytes if operand_bits == __b16, 4 bytes if __b32, 8 bytes if __b64)
	 *
	 * 0xb8 - 0xbf, 0xf7 (Reg/Op = 000 or Reg/Op = 001)
	 *
	 * moffs (2 bytes if addr_bits == __b16, 4 bytes if __b32, 8 bytes if __b64)
	 *
	 * 0xa0, 0xa1, 0xa2, 0xa3
	 *
	 * others
	 *
	 * 0xea, 0x9a: imm16 + imm16/32
	 * 0xc8: imm16 + imm8
	 *
	 *
	 * 2bytes opcode list:
	 *
	 * imm8 (1 byte)
	 *
	 * 0x70 - 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4 - 0xc6
	 *
	 * imm16/32 (2 bytes if operand_bits == __b16 else 4 bytes)
	 *
	 * 0x80 - 0x8f
	 *
	 *
	 * all 3bytes opcodes with 0x3a prefix have imm8
	 */
	if (!twobytes) { // 1byte opcodes
		// imm8
		if (((opcode & 7) == 4 && (opcode & 0xf0) <= 0x30) ||
		    opcode == 0x6a || opcode == 0x6b || (opcode & 0xf0) == 0x70 ||
		    opcode == 0x80 || opcode == 0x82 || opcode == 0x83 ||
		    opcode == 0xa8 || (opcode & 0xf8) == 0xb0 || opcode == 0xc0 ||
		    opcode == 0xc1 || opcode == 0xc6 || opcode == 0xcd ||
		    opcode == 0xd4 || opcode == 0xd5 || (opcode & 0xf8) == 0xe0 ||
		    opcode == 0xeb || (opcode == 0xf6 && (modrm & 0x30) == 0))
			len += 1;

		// imm16
		if (opcode == 0xc2 || opcode == 0xca)
			len += 2;

		// imm16/32
		if (((opcode & 7) == 5 && (opcode & 0xf0) <= 0x30) ||
		    opcode == 0x68 || opcode == 0x69 || opcode == 0x81 ||
		    opcode == 0xa9 || opcode == 0xc7 || opcode == 0xe8 ||
		    opcode == 0xe9)
			len += operand_bits == __b16 ? 2 : 4;

		// imm16/32/64
		if ((opcode & 0xf8) == 0xb8 || (opcode == 0xf7 && (modrm & 0x30) == 0))
			len += operand_bits == __b16 ? 2 : operand_bits == __b32 ? 4 : 8;

		// moffs
		if ((opcode & 0xfc) == 0xa0)
			len += addr_bits == __b16 ? 2 : addr_bits == __b32 ? 4 : 8;

		// others
		if (opcode == 0xea || opcode == 0x9a)
			len += 2 + (operand_bits == __b16 ? 2 : 4);
		if (opcode == 0xc8)
			len += 3;
	} else { // 2bytes opcodes
		// imm8
		if ((opcode & 0xfc) == 0x70 || opcode == 0xa4 ||
		    opcode == 0xac || opcode == 0xba || opcode == 0xc2 ||
		    (opcode >= 0xc4 && opcode <= 0xc6))
			len += 1;

		// imm16/32
		if ((opcode & 0xf0) == 0x80)
			len += operand_bits == __b16 ? 2 : 4;

		// 3bytes opcodes with 0x3a prefix
		if (opcode == 0x3a)
			len += 1;
	}

	// wrong length
	if (len > MAX_INSN_LEN_x86)
		len = 1;

	return len;
}

/*==============================================================================*/
/*                            获取32位指令长度                                  */
/*==============================================================================*/
static int insn_len_x86_32(void *insn) {
	return __insn_len_x86(insn, __b32);
}

/*==============================================================================*/
/*                            获取64位指令长度                                  */
/*==============================================================================*/
static int insn_len_x86_64(void *insn) {
	return __insn_len_x86(insn, __b64);
}






#ifdef __cplusplus
}
#endif

#endif