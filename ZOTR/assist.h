#ifndef ASSIST_H__
#define ASSIST_H__

#include "types.h"
#include "ZOTR.h"

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif


#if __GNUC__
#define ALIGN(n) __attribute__ ((aligned(n)))
#elif _MSC_VER
#define ALIGN(n) __declspec(align(n))
#define __inline__ __inline
#else 
#define ALIGN(n)
#endif

#define CONST const

typedef unsigned char uint8;
typedef unsigned int	uint32;
typedef ALIGN(16)__m128i block;

#define BLOCK BLOCK_BYTE_NUMBER

#define CRYPTO_KEYBYTES 32
#define CRYPTO_ABYTES 16

#define ROUND   ROUND_NUMBER
#define EK_SZ (ROUND+1) 
#define le(b) _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)) /*Byte order conversion*/
#define le256(b) _mm256_shuffle_epi8(b,_mm256_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)) /*Byte order conversion*/

/*
** AES-256 encrypt
*/
inline static void AES_encrypt(
	block in,
	block *out,
	const block key,
	const block	tweak)
{
	CONST __m128i allzero = _mm_setzero_si128();
	CONST __m128i mask256 = _mm_set1_epi32(0x0c0f0e0d);
	CONST __m128i con1 = _mm_set1_epi32(1);
	CONST __m128i con3 = _mm_set_epi8(7, 6, 5, 4, 7, 6, 5, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

	__m128i xmm0, xmm1, xmm2, xmm3, xmm4;

	xmm1 = key;
	xmm3 = tweak;
	xmm0 = con1;

	in = _mm_xor_si128(in, xmm1);
	in = _mm_aesenc_si128(in, xmm3);

	for (u64 r = 0; r < 6; r++)
	{
		xmm2 = _mm_shuffle_epi8(xmm3, mask256);
		xmm2 = _mm_aesenclast_si128(xmm2, xmm0);
		xmm0 = _mm_slli_epi32(xmm0, 1);

		xmm4 = _mm_slli_epi64(xmm1, 32);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm4 = _mm_shuffle_epi8(xmm1, con3);
		xmm1 = _mm_xor_si128(xmm1, xmm4);
		xmm1 = _mm_xor_si128(xmm1, xmm2);

		in = _mm_aesenc_si128(in, xmm1);

		xmm2 = _mm_shuffle_epi32(xmm1, 0xff);
		xmm2 = _mm_aesenclast_si128(xmm2, allzero);

		xmm4 = _mm_slli_epi64(xmm3, 32);
		xmm3 = _mm_xor_si128(xmm3, xmm4);
		xmm4 = _mm_shuffle_epi8(xmm3, con3);
		xmm3 = _mm_xor_si128(xmm3, xmm4);
		xmm3 = _mm_xor_si128(xmm3, xmm2);

		in = _mm_aesenc_si128(in, xmm3);
	}

	xmm2 = _mm_shuffle_epi8(xmm3, mask256);
	xmm2 = _mm_aesenclast_si128(xmm2, xmm0);

	xmm4 = _mm_slli_epi64(xmm1, 32);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm4 = _mm_shuffle_epi8(xmm1, con3);
	xmm1 = _mm_xor_si128(xmm1, xmm4);
	xmm1 = _mm_xor_si128(xmm1, xmm2);

	*out = _mm_aesenclast_si128(in, xmm1);
}

/*
** AES-256 encrypt for two blocks
*/
inline static void AES_ecb_encrypt_2(
	block *blks,
	const block key,
	const block *tweak)
{
	CONST __m128i mask256 = _mm_set1_epi32(0x0c0f0e0d);
	CONST __m128i con1 = _mm_set1_epi32(1);
	CONST __m128i con3 = _mm_set_epi8(7, 6, 5, 4, 7, 6, 5, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	CONST __m128i allzero = _mm_setzero_si128();

	__m128i 
		xmm0_00,
		xmm0_01, xmm1_01,
		xmm0_02, xmm1_02,
		xmm0_03, xmm1_03,
		xmm0_04, xmm1_04;

	xmm0_01 = key;		xmm1_01 = key;
	xmm0_03 = tweak[0];	xmm1_03 = tweak[1];
	xmm0_00 = con1;

	blks[0] = _mm_xor_si128   (blks[0], xmm0_01);
	blks[1] = _mm_xor_si128   (blks[1], xmm1_01);

	blks[0] = _mm_aesenc_si128(blks[0], xmm0_03);    blks[1] = _mm_aesenc_si128(blks[1], xmm1_03);

	for (u64 r = 0; r < 6; r++)
	{
		xmm0_02 = _mm_shuffle_epi8    (xmm0_03, mask256);
		xmm1_02 = _mm_shuffle_epi8    (xmm1_03, mask256);
		xmm0_02 = _mm_aesenclast_si128(xmm0_02, xmm0_00);    xmm1_02 = _mm_aesenclast_si128(xmm1_02, xmm0_00);

		xmm0_00 = _mm_slli_epi32      (xmm0_00,  1);	     
		xmm0_04 = _mm_slli_epi64      (xmm0_01, 32);	     
		xmm0_01 = _mm_xor_si128       (xmm0_01, xmm0_04);    
		xmm0_04 = _mm_shuffle_epi8    (xmm0_01, con3);	     
		xmm0_01 = _mm_xor_si128       (xmm0_01, xmm0_04);    
		xmm0_01 = _mm_xor_si128       (xmm0_01, xmm0_02);

		xmm1_04 = _mm_slli_epi64      (xmm1_01, 32);
		xmm1_01 = _mm_xor_si128       (xmm1_01, xmm1_04);
		xmm1_04 = _mm_shuffle_epi8    (xmm1_01, con3);
		xmm1_01 = _mm_xor_si128       (xmm1_01, xmm1_04);
		xmm1_01 = _mm_xor_si128       (xmm1_01, xmm1_02);
		blks[0] = _mm_aesenc_si128    (blks[0], xmm0_01);    blks[1] = _mm_aesenc_si128    (blks[1], xmm1_01);

		xmm0_02 = _mm_shuffle_epi32   (xmm0_01, 0xff);	 
		xmm1_02 = _mm_shuffle_epi32   (xmm1_01, 0xff);
		xmm0_02 = _mm_aesenclast_si128(xmm0_02, allzero);    xmm1_02 = _mm_aesenclast_si128(xmm1_02, allzero);

		xmm0_04 = _mm_slli_epi64      (xmm0_03, 32);	     
		xmm0_03 = _mm_xor_si128       (xmm0_03, xmm0_04);    
		xmm0_04 = _mm_shuffle_epi8    (xmm0_03, con3);	     
		xmm0_03 = _mm_xor_si128       (xmm0_03, xmm0_04);    
		xmm0_03 = _mm_xor_si128       (xmm0_03, xmm0_02);    
		xmm1_04 = _mm_slli_epi64      (xmm1_03, 32);
		xmm1_03 = _mm_xor_si128       (xmm1_03, xmm1_04);
		xmm1_04 = _mm_shuffle_epi8    (xmm1_03, con3);
		xmm1_03 = _mm_xor_si128       (xmm1_03, xmm1_04);
		xmm1_03 = _mm_xor_si128       (xmm1_03, xmm1_02);
		blks[0] = _mm_aesenc_si128    (blks[0], xmm0_03);    blks[1] = _mm_aesenc_si128    (blks[1], xmm1_03);
	}

	xmm0_02 = _mm_shuffle_epi8    (xmm0_03, mask256);
	xmm1_02 = _mm_shuffle_epi8    (xmm1_03, mask256);
	xmm0_02 = _mm_aesenclast_si128(xmm0_02, xmm0_00);    xmm1_02 = _mm_aesenclast_si128(xmm1_02, xmm0_00);

	xmm0_04 = _mm_slli_epi64      (xmm0_01, 32);	     
	xmm0_01 = _mm_xor_si128       (xmm0_01, xmm0_04);    
	xmm0_04 = _mm_shuffle_epi8    (xmm0_01, con3);	     
	xmm0_01 = _mm_xor_si128       (xmm0_01, xmm0_04);    
	xmm0_01 = _mm_xor_si128       (xmm0_01, xmm0_02);  
	xmm1_04 = _mm_slli_epi64      (xmm1_01, 32);
	xmm1_01 = _mm_xor_si128       (xmm1_01, xmm1_04);
	xmm1_04 = _mm_shuffle_epi8    (xmm1_01, con3);
	xmm1_01 = _mm_xor_si128       (xmm1_01, xmm1_04);
	xmm1_01 = _mm_xor_si128       (xmm1_01, xmm1_02);
	blks[0] = _mm_aesenclast_si128(blks[0], xmm0_01);    blks[1] = _mm_aesenclast_si128(blks[1], xmm1_01);
}

/*
** AES-256 batch encrypt for PIPE blocks
*/
inline static void AES_ecb_encrypt_PIPE(
	block *blks,
	const block key,
	const block *tweak)
{
	CONST __m128i mask256 = _mm_set1_epi32(0x0c0f0e0d);
	CONST __m128i con1 = _mm_set1_epi32(1);
	CONST __m128i con3 = _mm_set_epi8(7, 6, 5, 4, 7, 6, 5, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	CONST __m128i allzero = _mm_setzero_si128();

	__m128i
		xmm00,
		xmm01[PIPE],
		xmm02[PIPE],
		xmm03[PIPE],
		xmm04[PIPE];
#pragma unroll(PIPE)
	for (int i = 0; i < PIPE; i++) xmm01[i] = key;
#pragma unroll(PIPE)
	for (int i = 0; i < PIPE; i++) xmm03[i] = tweak[i];

	xmm00 = con1;

#pragma unroll(PIPE)
	for (int i = 0; i < PIPE; i++) blks[i] = _mm_xor_si128   (blks[i], xmm01[i]);
#pragma unroll(PIPE)
	for (int i = 0; i < PIPE; i++) blks[i] = _mm_aesenc_si128(blks[i], xmm03[i]);

	for (u64 r = 0; r < 6; r++)
	{
#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++) xmm02[i] = _mm_shuffle_epi8    (xmm03[i],  mask256);
#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++) xmm02[i] = _mm_aesenclast_si128(xmm02[i], xmm00);
		
		xmm00 = _mm_slli_epi32      (xmm00,        1);

#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++)
		{
			xmm04[i] = _mm_slli_epi64      (xmm01[i],       32);
			xmm01[i] = _mm_xor_si128       (xmm01[i], xmm04[i]);
			xmm04[i] = _mm_shuffle_epi8    (xmm01[i],     con3);
			xmm01[i] = _mm_xor_si128       (xmm01[i], xmm04[i]);
			xmm01[i] = _mm_xor_si128       (xmm01[i], xmm02[i]);
		}
			
#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++) blks [i] = _mm_aesenc_si128    (blks [i], xmm01[i]);
#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++) xmm02[i] = _mm_shuffle_epi32   (xmm01[i],     0xff);
#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++) xmm02[i] = _mm_aesenclast_si128(xmm02[i],  allzero);

#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++)
		{
			xmm04[i] = _mm_slli_epi64      (xmm03[i],       32);
			xmm03[i] = _mm_xor_si128       (xmm03[i], xmm04[i]);
			xmm04[i] = _mm_shuffle_epi8    (xmm03[i],     con3);
			xmm03[i] = _mm_xor_si128       (xmm03[i], xmm04[i]);
			xmm03[i] = _mm_xor_si128       (xmm03[i], xmm02[i]);
		}			
			
#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++) blks [i] = _mm_aesenc_si128    (blks [i], xmm03[i]);
	}

#pragma unroll(PIPE)
	for (int i = 0; i < PIPE; i++) xmm02[i] = _mm_shuffle_epi8    (xmm03[i],  mask256);
#pragma unroll(PIPE)
	for (int i = 0; i < PIPE; i++) xmm02[i] = _mm_aesenclast_si128(xmm02[i], xmm00);
#pragma unroll(PIPE)
	for (int i = 0; i < PIPE; i++)
	{
		xmm04[i] = _mm_slli_epi64(xmm01[i], 32);
		xmm01[i] = _mm_xor_si128(xmm01[i], xmm04[i]);
		xmm04[i] = _mm_shuffle_epi8(xmm01[i], con3);
		xmm01[i] = _mm_xor_si128(xmm01[i], xmm04[i]);
		xmm01[i] = _mm_xor_si128(xmm01[i], xmm02[i]);
	}
#pragma unroll(PIPE)
	for (int i = 0; i < PIPE; i++) blks [i] = _mm_aesenclast_si128(blks [i], xmm01[i]);
}

/*
** Batch doubling for PIPE blocks
*/
inline static void mul2_PIPE(__m128i *dat) {
	const __m128i mask = _mm_set_epi32(135, 1, 1, 1);
	__m128i intmp = le(dat[0]);
	__m128i tmp;

#pragma unroll(PIPE)
	for (int i = 1; i <= PIPE; i++)
	{
		tmp = _mm_srai_epi32(intmp, 31);
		tmp = _mm_and_si128(tmp, mask);
		tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2, 1, 0, 3));
		intmp = _mm_slli_epi32(intmp, 1);
		intmp = _mm_xor_si128(intmp, tmp);
		dat[i] = le(intmp);
	}
}


/*
** single doubling
*/
inline static void mul2(block in, block *out) {
	const block shuf = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	const block mask = _mm_set_epi32(135, 1, 1, 1);
	block intmp = _mm_shuffle_epi8(in, shuf);
	block tmp = _mm_srai_epi32(intmp, 31);
	tmp = _mm_and_si128(tmp, mask);
	tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2, 1, 0, 3));
	*out = _mm_slli_epi32(intmp, 1);
	*out = _mm_xor_si128(*out, tmp);
	*out = _mm_shuffle_epi8(*out, shuf);
}

/*
** Batch doubling for PIPE blocks
*/
inline static void mul2_PIPE_256(__m128i *dat) {
	const __m256i mask = _mm256_set_epi32(135, 1, 1, 1, 135, 1, 1, 1);
	__m256i intmp = le256(_mm256_inserti128_si256(_mm256_castsi128_si256(dat[0]), dat[1], 0x1));
	__m256i tmp;

#pragma unroll(PIPE)
	for (int i = 1; i <= PIPE; i++)
	{
		tmp = _mm256_srai_epi32(intmp, 31);
		tmp = _mm256_and_si256(tmp, mask);
		tmp = _mm256_shuffle_epi32(tmp, _MM_SHUFFLE(2, 1, 0, 3));
		intmp = _mm256_slli_epi32(intmp, 1);
		intmp = _mm256_xor_si256(intmp, tmp);
		dat[2 * i + 0] = _mm256_extracti128_si256(le256(intmp), 0);
		dat[2 * i + 1] = _mm256_extracti128_si256(le256(intmp), 1);
	}
}


/*
** single doubling
*/
inline static void mul2_256(block* in, block *out) {
	const __m256i shuf = _mm256_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	const __m256i mask = _mm256_set_epi32(135, 1, 1, 1, 135, 1, 1, 1);
	__m256i intmp = _mm256_shuffle_epi8(_mm256_inserti128_si256(_mm256_castsi128_si256(in[0]), in[1], 0x1), shuf);
	__m256i tmp = _mm256_srai_epi32(intmp, 31);
	__m256i tmp2;
	tmp = _mm256_and_si256(tmp, mask);
	tmp = _mm256_shuffle_epi32(tmp, _MM_SHUFFLE(2, 1, 0, 3));
	tmp2 = _mm256_slli_epi32(intmp, 1);
	tmp2 = _mm256_xor_si256(tmp2, tmp);
	tmp2 = _mm256_shuffle_epi8(tmp2, shuf);
	out[0] = _mm256_extracti128_si256(tmp2, 0);
	out[1] = _mm256_extracti128_si256(tmp2, 1);
}

/*
ozp: one-zero padding for 16-byte block
*/
inline static void ozp(uint32 length, const uint8 *in, block *out) {
	ALIGN(16)uint8 tmp[BLOCK + 1] = { 0 };
	memcpy(tmp, in, length);
	tmp[length] = 0x80;
	*out = _mm_load_si128((block*)tmp);
}

/*
ozpAD: one-zero padding for (BLOCK + TRICK_BYTE_NUMBER)-byte block
*/
inline static void ozpAD(uint32 length, const uint8 *in, uint8 *out) {
	ALIGN(16)uint8 tmp[BLOCK + TRICK_BYTE_NUMBER + 1] = { 0 };
	memcpy(tmp, in, length);
	tmp[length] = 0x80;
	memcpy(out, tmp, BLOCK + TRICK_BYTE_NUMBER);
}

#define ozpInplace(X, BEG, END)				 \
{										 \
	X[BEG] = 0x80;						 \
	for (u64 i = BEG + 1; i < END; i++)  \
	{									 \
		X[i] = 0x00;					 \
	}									 \
}

#endif // ASSIST_H__
