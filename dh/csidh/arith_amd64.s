// +build amd64,!noasm

#include "textflag.h"

// Multipies 512-bit value by 64-bit value. Uses MULX instruction
// x = y * z
//
// func mul512(a, b *u512, c uint64)
TEXT ·mul512(SB), NOSPLIT, $0-24
	MOVQ	x+ 0(FP), DI	// result
	MOVQ	y+ 8(FP), SI	// multiplicand
	MOVQ	z+16(FP), DX	// 64 byte multiplier

	MULXQ	 0(SI), AX, R10;						MOVQ	AX,  0(DI)	// x[0]
	MULXQ	 8(SI), AX, R11; ADDQ	R10, AX; MOVQ	AX,  8(DI) // x[1]
	MULXQ	16(SI), AX, R10; ADCQ	R11, AX; MOVQ	AX, 16(DI) // x[2]
	MULXQ	24(SI), AX, R11; ADCQ	R10, AX; MOVQ	AX, 24(DI) // x[3]
	MULXQ	32(SI), AX, R10; ADCQ	R11, AX; MOVQ	AX, 32(DI) // x[4]
	MULXQ	40(SI), AX, R11; ADCQ	R10, AX; MOVQ	AX, 40(DI) // x[5]
	MULXQ	48(SI), AX, R10; ADCQ	R11, AX; MOVQ	AX, 48(DI) // x[6]
	MULXQ	56(SI), AX, R11; ADCQ	R10, AX; MOVQ	AX, 56(DI) // x[7]

	RET

// x = y + z
// func add512(x, y, z *u512) uint64
TEXT ·add512(SB), NOSPLIT, $0-32
	MOVQ	x+ 0(FP), DI	// result
	MOVQ	y+ 8(FP), SI	// first summand
	MOVQ	z+16(FP), DX	// second summand

	XORQ	AX, AX

	MOVQ	 0(SI), R8;	ADDQ	 0(DX), R8;	MOVQ	R8,  0(DI)	// x[0]
	MOVQ	 8(SI), R8;	ADCQ	 8(DX), R8;	MOVQ	R8,  8(DI)	// x[1]
	MOVQ	16(SI), R8;	ADCQ	16(DX), R8;	MOVQ	R8, 16(DI)	// x[2]
	MOVQ	24(SI), R8;	ADCQ	24(DX), R8;	MOVQ	R8, 24(DI)	// x[3]
	MOVQ	32(SI), R8;	ADCQ	32(DX), R8;	MOVQ	R8, 32(DI)	// x[4]
	MOVQ	40(SI), R8;	ADCQ	40(DX), R8;	MOVQ	R8, 40(DI)	// x[5]
	MOVQ	48(SI), R8;	ADCQ	48(DX), R8;	MOVQ	R8, 48(DI)	// x[6]
	MOVQ	56(SI), R8;	ADCQ	56(DX), R8;	MOVQ	R8, 56(DI)	// x[7]

	// return carry
	ADCQ	AX, AX
	MOVQ	AX, ret+24(FP)
	RET


// x = y - z
// func sub512(x, y, z *u512) uint64
TEXT ·sub512(SB), NOSPLIT, $0-32
	MOVQ	x+ 0(FP), DI	// result
	MOVQ	y+ 8(FP), SI	// minuend
	MOVQ	z+16(FP), DX	// subtrahend

	XORQ	AX, AX

	MOVQ	 0(SI), R8;	SUBQ	 0(DX), R8;	MOVQ	R8,  0(DI)	// x[0]
	MOVQ	 8(SI), R8;	SBBQ	 8(DX), R8;	MOVQ	R8,  8(DI)	// x[1]
	MOVQ	16(SI), R8;	SBBQ	16(DX), R8;	MOVQ	R8, 16(DI)	// x[2]
	MOVQ	24(SI), R8;	SBBQ	24(DX), R8;	MOVQ	R8, 24(DI)	// x[3]
	MOVQ	32(SI), R8;	SBBQ	32(DX), R8;	MOVQ	R8, 32(DI)	// x[4]
	MOVQ	40(SI), R8;	SBBQ	40(DX), R8;	MOVQ	R8, 40(DI)	// x[5]
	MOVQ	48(SI), R8;	SBBQ	48(DX), R8;	MOVQ	R8, 48(DI)	// x[6]
	MOVQ	56(SI), R8;	SBBQ	56(DX), R8;	MOVQ	R8, 56(DI)	// x[7]

	// return borrow
	ADCQ	AX, AX
	MOVQ	AX, ret+24(FP)

	RET

TEXT ·cswap512(SB),NOSPLIT,$0-17
	MOVQ    x+0(FP), DI
	MOVQ    y+8(FP), SI
    MOVBLZX choice+16(FP), AX       // AL = 0 or 1

	// Make AX, so that either all bits are set or non
	// AX = 0 or 1
	NEGQ    AX

	// Fill xmm15. After this step first half of XMM15 is
	// just zeros and second half is whatever in AX
	MOVQ    AX, X15

	// Copy lower double word everywhere else. So that
	// XMM15=AL|AL|AL|AL. As AX has either all bits set
	// or non result will be that XMM15 has also either
	// all bits set or non of them.
	PSHUFD $0, X15, X15

#ifndef CSWAP_BLOCK
#define CSWAP_BLOCK(idx)       \
	MOVOU   (idx*16)(DI), X0 \
	MOVOU   (idx*16)(SI), X1 \
	\ // X2 = mask & (X0 ^ X1)
	MOVO     X1, X2 \
	PXOR     X0, X2 \
	PAND    X15, X2 \
	\
	PXOR     X2, X0 \
	PXOR     X2, X1 \
	\
	MOVOU    X0, (idx*16)(DI) \
	MOVOU    X1, (idx*16)(SI)
#endif

	CSWAP_BLOCK(0)
	CSWAP_BLOCK(1)
	CSWAP_BLOCK(2)
	CSWAP_BLOCK(3)

	RET

// val = val<p?val:val-p
TEXT ·crdc512(SB),NOSPLIT,$0-8
	MOVQ val+0(FP), DI

	MOVQ ( 0)(DI),  SI; SUBQ ·p+ 0(SB),  SI
	MOVQ ( 8)(DI),  DX; SBBQ ·p+ 8(SB),  DX
	MOVQ (16)(DI),  CX; SBBQ ·p+16(SB),  CX
	MOVQ (24)(DI),  R8; SBBQ ·p+24(SB),  R8
	MOVQ (32)(DI),  R9; SBBQ ·p+32(SB),  R9
	MOVQ (40)(DI), R10; SBBQ ·p+40(SB), R10
	MOVQ (48)(DI), R11; SBBQ ·p+48(SB), R11
	MOVQ (56)(DI), R12; SBBQ ·p+56(SB), R12

	MOVQ ( 0)(DI), AX; CMOVQCC  SI, AX; MOVQ AX, ( 0)(DI)
	MOVQ ( 8)(DI), AX; CMOVQCC  DX, AX; MOVQ AX, ( 8)(DI)
	MOVQ (16)(DI), AX; CMOVQCC  CX, AX; MOVQ AX, (16)(DI)
	MOVQ (24)(DI), AX; CMOVQCC  R8, AX; MOVQ AX, (24)(DI)
	MOVQ (32)(DI), AX; CMOVQCC  R9, AX; MOVQ AX, (32)(DI)
	MOVQ (40)(DI), AX; CMOVQCC R10, AX; MOVQ AX, (40)(DI)
	MOVQ (48)(DI), AX; CMOVQCC R11, AX; MOVQ AX, (48)(DI)
	MOVQ (56)(DI), AX; CMOVQCC R12, AX; MOVQ AX, (56)(DI)

	RET

// val = b?val+p:val
TEXT ·csubrdc512(SB),NOSPLIT,$0-16
	MOVQ val+0(FP), DI
	MOVQ choice+8(FP), SI

	XORQ  R8,  R8
	XORQ  R9,  R9
	XORQ R10, R10
	XORQ R11, R11
	XORQ R12, R12
	XORQ R13, R13
	XORQ R14, R14
	XORQ R15, R15

	TESTQ SI, SI
	CMOVQNE ·p+ 0(SB), R8
	CMOVQNE ·p+ 8(SB), R9
	CMOVQNE ·p+16(SB), R10
	CMOVQNE ·p+24(SB), R11
	CMOVQNE ·p+32(SB), R12
	CMOVQNE ·p+40(SB), R13
	CMOVQNE ·p+48(SB), R14
	CMOVQNE ·p+56(SB), R15

	MOVQ ( 0)(DI), DX; ADDQ  R8, DX; MOVQ DX, ( 0)(DI)
	MOVQ ( 8)(DI), DX; ADCQ  R9, DX; MOVQ DX, ( 8)(DI)
	MOVQ (16)(DI), DX; ADCQ R10, DX; MOVQ DX, (16)(DI)
	MOVQ (24)(DI), DX; ADCQ R11, DX; MOVQ DX, (24)(DI)
	MOVQ (32)(DI), DX; ADCQ R12, DX; MOVQ DX, (32)(DI)
	MOVQ (40)(DI), DX; ADCQ R13, DX; MOVQ DX, (40)(DI)
	MOVQ (48)(DI), DX; ADCQ R14, DX; MOVQ DX, (48)(DI)
	MOVQ (56)(DI), DX; ADCQ R15, DX; MOVQ DX, (56)(DI)

	RET

// mul function implements montgomery multiplication interleaved with rdc.
// It takes advantage of the fact that inversion of 'p' has only 64-bits
//
// z = x*y mod p
TEXT ·mul(SB),NOSPLIT,$32-24
	MOVQ y+ 8(FP), DI // multiplicand
	MOVQ z+16(FP), SI // multiplier

	XORQ  R8,  R8
	XORQ  R9,  R9
	XORQ R10, R10
	XORQ R11, R11
	XORQ R12, R12
	XORQ R13, R13
	XORQ R14, R14
	XORQ R15, R15

	MOVQ BP, 24(SP) // OZAPTF: thats maybe wrong
	XORQ BP, BP

// Uses BMI2 and MULX
#ifdef MULS_MULX_512
#undef MULS_MULX_512
#endif
#define MULS_MULX_512(idx, r0, r1, r2, r3, r4, r5, r6, r7, r8) \
	\ // Reduction step
	MOVQ  ( 0)(SI), DX 		\
	MULXQ ( 8*idx)(DI), DX, CX 	\
	ADDQ  r0, DX 			\
	MULXQ ·pNegInv(SB), DX, CX	\
	\ // Clean flags
	XORQ  AX, AX \
	MULXQ ·p+ 0(SB), AX, BX;             ; ADOXQ AX, r0 \
	MULXQ ·p+ 8(SB), AX, CX; ADCXQ BX, r1; ADOXQ AX, r1 \
	MULXQ ·p+16(SB), AX, BX; ADCXQ CX, r2; ADOXQ AX, r2 \
	MULXQ ·p+24(SB), AX, CX; ADCXQ BX, r3; ADOXQ AX, r3 \
	MULXQ ·p+32(SB), AX, BX; ADCXQ CX, r4; ADOXQ AX, r4 \
	MULXQ ·p+40(SB), AX, CX; ADCXQ BX, r5; ADOXQ AX, r5 \
	MULXQ ·p+48(SB), AX, BX; ADCXQ CX, r6; ADOXQ AX, r6 \
	MULXQ ·p+56(SB), AX, CX; ADCXQ BX, r7; ADOXQ AX, r7 \
	MOVQ  $0, AX           ; ADCXQ CX, r8; ADOXQ AX, r8 \
	\ // Multiplication step
	MOVQ (8*idx)(DI), DX \
	\ // Clean flags
	XORQ  AX, AX \
	MULXQ ( 0)(SI), AX, BX; ADOXQ AX, r0 \
	MULXQ ( 8)(SI), AX, CX; ADCXQ BX, r1; ADOXQ AX, r1 \
	MULXQ (16)(SI), AX, BX; ADCXQ CX, r2; ADOXQ AX, r2 \
	MULXQ (24)(SI), AX, CX; ADCXQ BX, r3; ADOXQ AX, r3 \
	MULXQ (32)(SI), AX, BX; ADCXQ CX, r4; ADOXQ AX, r4 \
	MULXQ (40)(SI), AX, CX; ADCXQ BX, r5; ADOXQ AX, r5 \
	MULXQ (48)(SI), AX, BX; ADCXQ CX, r6; ADOXQ AX, r6 \
	MULXQ (56)(SI), AX, CX; ADCXQ BX, r7; ADOXQ AX, r7 \
	MOVQ  $0, AX          ; ADCXQ CX, r8; ADOXQ AX, r8

	MULS_MULX_512(0,  R8,  R9, R10, R11, R12, R13, R14, R15,  BP)
	MULS_MULX_512(1,  R9, R10, R11, R12, R13, R14, R15,  BP,  R8)
	MULS_MULX_512(2, R10, R11, R12, R13, R14, R15,  BP,  R8,  R9)
	MULS_MULX_512(3, R11, R12, R13, R14, R15,  BP,  R8,  R9, R10)
	MULS_MULX_512(4, R12, R13, R14, R15,  BP,  R8,  R9, R10, R11)
	MULS_MULX_512(5, R13, R14, R15,  BP,  R8,  R9, R10, R11, R12)
	MULS_MULX_512(6, R14, R15,  BP,  R8,  R9, R10, R11, R12, R13)
	MULS_MULX_512(7, R15,  BP,  R8,  R9, R10, R11, R12, R13, R14)

	MOVQ x+0(FP), DI
	MOVQ  BP, ( 0)(DI)
	MOVQ  R8, ( 8)(DI)
	MOVQ  R9, (16)(DI)
	MOVQ R10, (24)(DI)
	MOVQ R11, (32)(DI)
	MOVQ R12, (40)(DI)
	MOVQ R13, (48)(DI)
	MOVQ R14, (56)(DI)
	MOVQ 24(SP), BP

	// NOW DI needs to be reduced if > p
	RET

// Checks if x>y. Returns 1 if true otherwise, 0
TEXT ·checkBigger(SB),NOSPLIT,$0-24
	MOVQ	x+ 0(FP), DI	// minuend
	MOVQ	y+ 8(FP), SI	// subtrahend

	XORQ	AX, AX
	MOVQ	 0(SI), R8;	SUBQ	 0(DI), R8
	MOVQ	 8(SI), R8;	SBBQ	 8(DI), R8
	MOVQ	16(SI), R8;	SBBQ	16(DI), R8
	MOVQ	24(SI), R8;	SBBQ	24(DI), R8
	MOVQ	32(SI), R8;	SBBQ	32(DI), R8
	MOVQ	40(SI), R8;	SBBQ	40(DI), R8
	MOVQ	48(SI), R8;	SBBQ	48(DI), R8
	MOVQ	56(SI), R8;	SBBQ	56(DI), R8

	// return borrow
	ADCQ	AX, AX
	MOVQ	AX, 24(SP)

	RET
