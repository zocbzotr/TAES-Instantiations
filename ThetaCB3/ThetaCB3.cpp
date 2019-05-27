#include <iostream>
#include <iomanip>
#include <fstream>

#include "ThetaCB3.h"
#include "assist.h"

using namespace std;

void ThetaCB3_enc(
	unsigned char * C,
	unsigned char * T,
	unsigned char * N,
	unsigned char * A,
	unsigned char * M,
	long long AByteN,
	long long MByteN,
	unsigned char *Seedkey
)
{
	__m128i allzero = _mm_setzero_si128();
	__m128i K128i = _mm_loadu_si128((__m128i *)Seedkey);
	__m128i *C128ip = (__m128i *)(C);
	__m128i *T128ip = (__m128i *)(T);
	__m128i *M128ip = (__m128i *)(M);
	__m128i Checksum = allzero;
	__m128i M128i[PIPE];
	__m128i C128i[PIPE];
	__m128i Tweak[PIPE];
	__m128i S128i[PIPE];
	__m128i Final;
	__m128i Pad;

	u8 * Cip = C;
	u8 * Mip = M;
	u64 Nonce = *(u64 *)N;

	s64 MBlockN = MByteN / BLOCK_BYTE_NUMBER;
	s64 MRe = MByteN % BLOCK_BYTE_NUMBER;

	for (s64 mi = 0; (mi + PIPE) <= MBlockN; mi += PIPE)
	{
#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++)
		{
			Tweak[i] = _mm_set_epi64x(Nonce, mi + i);
			M128ip = (__m128i *)(Mip + i * BLOCK_BYTE_NUMBER);
			M128i[i] = _mm_loadu_si128(M128ip);
			Checksum = _mm_xor_si128(Checksum, M128i[i]);
		}

#if (PIPE > 1)
		AES_ecb_encrypt_PIPE(M128i, K128i, Tweak);
#else
		AES_encrypt(M128i[0], &(M128i[0]), K128i, Tweak[0]);
#endif

#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++)
		{
			C128ip = (__m128i *)(Cip + i * BLOCK_BYTE_NUMBER);
			_mm_storeu_si128(C128ip, M128i[i]);
		}

		Mip += (BLOCK_BYTE_NUMBER * PIPE);
		Cip += (BLOCK_BYTE_NUMBER * PIPE);
	}

	for (s64 mi = 0; mi < (MBlockN % PIPE); mi++)
	{
		u64 cnt = (MBlockN / PIPE) * PIPE + mi;
		Tweak[0] = _mm_set_epi64x(Nonce, cnt);
		M128ip = (__m128i *)(Mip);
		M128i[0] = _mm_loadu_si128(M128ip);
		Checksum = _mm_xor_si128(Checksum, M128i[0]);
		AES_encrypt(M128i[0], &(M128i[0]), K128i, Tweak[0]);
		C128ip = (__m128i *)(Cip);
		_mm_storeu_si128(C128ip, M128i[0]);

		Mip += BLOCK_BYTE_NUMBER;
		Cip += BLOCK_BYTE_NUMBER;
	}

	if (MRe == 0)
	{
		Tweak[0] = _mm_set_epi64x(Nonce, MBlockN + 2);
		AES_encrypt(Checksum, &Final, K128i, Tweak[0]);
	} 
	else
	{
		Tweak[0] = _mm_set_epi64x(Nonce, MBlockN + 1);
		AES_encrypt(allzero, &Pad, K128i, Tweak[0]);

		M128i[0] = _mm_loadu_si128((__m128i *)(Mip));
		u8 * MRep = (u8 *)(M128i);
		ozpInplace(MRep, MRe, BLOCK_BYTE_NUMBER);
		Checksum = _mm_xor_si128(Checksum, M128i[0]);

		M128i[0] = _mm_xor_si128(M128i[0], Pad);
		memcpy(Cip, MRep, MRe);

		Tweak[0] = _mm_set_epi64x(Nonce, MBlockN + 3);
		AES_encrypt(Checksum, &Final, K128i, Tweak[0]);
	}

	__m128i Tag;
	Hash_enc((u8 *)(&Tag), A, AByteN, Seedkey);
	Tag = _mm_xor_si128(Tag, Final);
	memcpy(T, (u8 *)(&Tag), TAG_BYTE_NUMBER);
};

void Hash_enc(
	unsigned char * Y,
	unsigned char * A,
	long long AByteN,
	unsigned char *Seedkey
)
{
	__m128i allzero = _mm_setzero_si128();
	__m128i Y128i[PIPE];
	__m128i A128i[PIPE];
	__m128i Tweak[PIPE];
	__m128i *Y128ip = (__m128i *)(Y);
	__m128i *A128ip = (__m128i *)(A);
	__m128i K128i = _mm_loadu_si128((__m128i *)Seedkey);
	__m128i Sum = allzero;
	u8 * Aip = A;

	s64 ABlockN = AByteN / BLOCK_BYTE_NUMBER;
	s64 ARe = AByteN % BLOCK_BYTE_NUMBER;

	for (s64 mi = 0; mi + PIPE <= ABlockN; mi += PIPE)
	{
#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++)
		{
			Tweak[i] = _mm_set_epi64x(0x0LL, mi + i);
			A128ip = (__m128i *)(Aip + i * BLOCK_BYTE_NUMBER);
			A128i[i] = _mm_loadu_si128(A128ip);
		}

#if (PIPE > 1)
		AES_ecb_encrypt_PIPE(A128i, K128i, Tweak);
#else
		AES_encrypt(A128i[0], &(A128i[0]), K128i, Tweak[0]);
#endif

		for (int i = 0; i < PIPE; i++)
		{
			Sum = _mm_xor_si128(Sum, A128i[i]);
		}

		Aip += (BLOCK_BYTE_NUMBER * PIPE);
	}

	for (s64 mi = 0; mi < ABlockN % PIPE; mi++)
	{
		u64 cnt = (ABlockN / PIPE) * PIPE + mi;
		Tweak[0] = _mm_set_epi64x(0x0LL, cnt);
		A128ip = (__m128i *)(Aip);
		A128i[0] = _mm_loadu_si128(A128ip);
		AES_encrypt(A128i[0], A128i, K128i, Tweak[0]);
		Sum = _mm_xor_si128(Sum, A128i[0]);

		Aip += BLOCK_BYTE_NUMBER;
	}

	if (ARe != 0)
	{
		Tweak[0] = _mm_set_epi64x(0x0LL, ABlockN + 1);
		A128ip = (__m128i *)(Aip);
		A128i[0] = _mm_loadu_si128(A128ip);
		u8 * ARep = (u8 *)(A128i);
		ozpInplace(ARep, ARe, BLOCK_BYTE_NUMBER);
		AES_encrypt(A128i[0], A128i, K128i, Tweak[0]);
		Sum = _mm_xor_si128(Sum, A128i[0]);
	}
	_mm_store_si128((__m128i *)Y, Sum);
};