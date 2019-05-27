#include "ZOTR.h"
#include "assist.h"
#include <iostream>
#include <iomanip>
#include <fstream>

using namespace std;

void ZOTR_enc(
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
	s64 MBlockN = (MByteN +  BLOCK_BYTE_NUMBER - 1) / BLOCK_BYTE_NUMBER;
	if (MByteN == 0) MBlockN = 1LL;
	u64 BByteN = MBlockN * TRICK_BYTE_NUMBER;

	u8 *B = new u8[BByteN];

	__m128i Y;
	__m128i Yh;
	__m128i Temp;

	if (AByteN < BByteN)
	{
		memcpy(B, A, AByteN);
		ozpInplace(B, AByteN, BByteN);
		Yh = _mm_setzero_si128();
	}
	else
	{
		memcpy(B, A, BByteN);
		s64 BhByteN = AByteN - BByteN;
		u8 *Bh;
		if (BhByteN == 0)
		{
			Bh = new u8[BLOCK_TRICK_BYTE_NUMBER];
		}
		else
		{
			Bh = new u8[BhByteN];
		}
		memcpy(Bh, A + BByteN, BhByteN);
		Hash_enc((u8 *)&Yh, Bh, BhByteN, Seedkey);
		delete[] Bh;
	}

	Core_enc(C, (u8 *)&Y, N, B, M, MByteN, Seedkey);
	Temp = _mm_xor_si128(Y, Yh);
	_mm_storeu_si128((__m128i *)T, Temp);

	delete[] B;
};

void Core_enc(
	unsigned char * C,
	unsigned char * Y,
	unsigned char * N,
	unsigned char * B,
	unsigned char * M,
	long long MByteN,
	unsigned char *Seedkey
)
{
	__m128i allzero = _mm_setzero_si128();
	__m128i oneone = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1);
	__m128i S = allzero;

	__m128i N128i = _mm_loadu_si128((__m128i *)N);;
	__m128i K128i = _mm_loadu_si128((__m128i *)Seedkey);
	__m128i *C128ip = (__m128i *)(C);
	__m128i *Y128ip = (__m128i *)(Y);
	__m128i *M128ip = (__m128i *)(M);
	__m128i *B128ip = (__m128i *)(B);

	u8 * Cip = C;
	u8 * Mip = M;
	u8 * Bip = B;

	__m128i M128i_L[PIPE];
	__m128i M128i_R[PIPE];

	__m128i C128i[PIPE];

	__m128i S128i[PIPE];
	__m128i Tweak[PIPE];
	__m128i alphabeta[PIPE + 1][2];

	alphabeta[0][0] = N128i;
	alphabeta[0][1] = N128i;
	Tweak[0] = _mm_set_epi64x(0x0000000000000000ULL, 0x0000000000000006ULL);
	Tweak[1] = _mm_set_epi64x(0x0000000000000001ULL, 0x0000000000000006ULL);
	AES_ecb_encrypt_2(alphabeta[0], K128i, Tweak);

	if (MByteN == 0)
	{
		//ozpInplace(((u8 *)S), 0, BLOCK_BYTE_NUMBER);
		S = _mm_insert_epi8(S, 0x80, 0);
		B128ip = (__m128i *)(B);
		Tweak[0] = _mm_loadu_si128(B128ip);
		Tweak[0] = _mm_slli_si128(_mm_xor_si128(Tweak[0], alphabeta[0][1]), 1);
		Tweak[0] = _mm_insert_epi8(Tweak[0], 4, 0);
		S = _mm_xor_si128(S, alphabeta[0][0]);
		AES_encrypt(S, Y128ip, K128i, Tweak[0]);
		return;
	}

	s64 MBlockN = (MByteN + BLOCK_BYTE_NUMBER - 1) / BLOCK_BYTE_NUMBER;
	s64 MRe = MByteN % BLOCK_BYTE_NUMBER;

	s64 ResBlockN = MBlockN;

#if (PIPE > 1)
	while (ResBlockN  > (2 * PIPE))
	{
		mul2_PIPE_256(alphabeta[0]);

#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++)
		{
			M128ip = (__m128i *)(Mip + (i * 2 + 0) * BLOCK_BYTE_NUMBER);
			B128ip = (__m128i *)(Bip + (i * 2 + 0) * TRICK_BYTE_NUMBER);

			M128i_L[i] = _mm_loadu_si128(M128ip);
			C128i[i] = _mm_xor_si128(M128i_L[i], alphabeta[i][0]);
			Tweak[i] = _mm_loadu_si128(B128ip);
			Tweak[i] = _mm_slli_si128(_mm_xor_si128(Tweak[i], alphabeta[i][1]), 1);
		}

#if (PIPE == 2)
		AES_ecb_encrypt_2(C128i, K128i, Tweak);
#else
		AES_ecb_encrypt_PIPE(C128i, K128i, Tweak);
#endif

#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++)
		{
			M128ip = (__m128i *)(Mip + (i * 2 + 1) * BLOCK_BYTE_NUMBER);
			B128ip = (__m128i *)(Bip + (i * 2 + 1) * TRICK_BYTE_NUMBER);

			M128i_R[i] = _mm_loadu_si128(M128ip);
			C128i[i] = _mm_xor_si128(C128i[i], M128i_R[i]);
			C128ip = (__m128i *)(Cip + (i * 2 + 0) * BLOCK_BYTE_NUMBER);
			_mm_storeu_si128(C128ip, C128i[i]);

			C128i[i] = _mm_xor_si128(C128i[i], alphabeta[i][0]);
			Tweak[i] = _mm_loadu_si128(B128ip);
			Tweak[i] = _mm_slli_si128(_mm_xor_si128(Tweak[i], alphabeta[i][1]), 1);
			Tweak[i] = _mm_xor_si128(Tweak[i], oneone);
		}

#if (PIPE == 2)
		AES_ecb_encrypt_2(C128i, K128i, Tweak);
#else
		AES_ecb_encrypt_PIPE(C128i, K128i, Tweak);
#endif

#pragma unroll(PIPE)
		for (int i = 0; i < PIPE; i++)
		{
			C128i[i] = _mm_xor_si128(C128i[i], M128i_L[i]);
			C128ip = (__m128i *)(Cip + (i * 2 + 1) * BLOCK_BYTE_NUMBER);
			_mm_storeu_si128(C128ip, C128i[i]);
		}
		for (int i = 0; i < PIPE; i++)
		{
			S = _mm_xor_si128(S, M128i_R[i]);
		}

		alphabeta[0][0] = alphabeta[PIPE][0];
		alphabeta[0][1] = alphabeta[PIPE][1];

		Mip += (2 * BLOCK_BYTE_NUMBER * PIPE);
		Bip += (2 * TRICK_BYTE_NUMBER * PIPE);
		Cip += (2 * BLOCK_BYTE_NUMBER * PIPE);
		ResBlockN -= (2 * PIPE);
	}
#endif

	while (ResBlockN > 2)
	{
		mul2_256(&(alphabeta[0][0]), &(alphabeta[1][0]));

		M128ip = (__m128i *)(Mip);
		B128ip = (__m128i *)(Bip);

		M128i_L[0] = _mm_loadu_si128(M128ip);
		C128i[0] = _mm_xor_si128(M128i_L[0], alphabeta[0][0]);
		Tweak[0] = _mm_loadu_si128(B128ip);
		Tweak[0] = _mm_slli_si128(_mm_xor_si128(Tweak[0], alphabeta[0][1]), 1);

		AES_encrypt(C128i[0], &(C128i[0]), K128i, Tweak[0]);

		M128ip = (__m128i *)(Mip + BLOCK_BYTE_NUMBER);
		B128ip = (__m128i *)(Bip + TRICK_BYTE_NUMBER);

		M128i_R[0] = _mm_loadu_si128(M128ip);
		C128i[0] = _mm_xor_si128(C128i[0], M128i_R[0]);
		C128ip = (__m128i *)(Cip);
		_mm_storeu_si128(C128ip, C128i[0]);

		C128i[0] = _mm_xor_si128(C128i[0], alphabeta[0][0]);
		Tweak[0] = _mm_loadu_si128(B128ip);
		Tweak[0] = _mm_slli_si128(_mm_xor_si128(Tweak[0], alphabeta[0][1]), 1);
		Tweak[0] = _mm_xor_si128(Tweak[0], oneone);

		AES_encrypt(C128i[0], &(C128i[0]), K128i, Tweak[0]);

		C128i[0] = _mm_xor_si128(C128i[0], M128i_L[0]);
		C128ip = (__m128i *)(Cip + BLOCK_BYTE_NUMBER);
		_mm_storeu_si128(C128ip, C128i[0]);

		S = _mm_xor_si128(S, M128i_R[0]);

		alphabeta[0][0] = alphabeta[1][0];
		alphabeta[0][1] = alphabeta[1][1];

		Mip += (2 * BLOCK_BYTE_NUMBER);
		Bip += (2 * TRICK_BYTE_NUMBER);
		Cip += (2 * BLOCK_BYTE_NUMBER);
		ResBlockN -= 2;
	}

	if (ResBlockN == 2)
	{
		M128ip = (__m128i *)(Mip);
		B128ip = (__m128i *)(Bip);

		M128i_L[0] = _mm_loadu_si128(M128ip);
		C128i[0] = _mm_xor_si128(M128i_L[0], alphabeta[0][0]);
		Tweak[0] = _mm_loadu_si128(B128ip);
		Tweak[0] = _mm_slli_si128(_mm_xor_si128(Tweak[0], alphabeta[0][1]), 1);

		AES_encrypt(C128i[0], &C128i[0], K128i, Tweak[0]);
		S = _mm_xor_si128(S, C128i[0]);

		M128ip = (__m128i *)(Mip + BLOCK_BYTE_NUMBER);
		M128i_R[0] = _mm_loadu_si128(M128ip);
		C128i[0] = _mm_xor_si128(C128i[0], M128i_R[0]);
		if (MRe != 0)
		{
			u8 * C128iu8a = (u8 *)C128i;
			ozpInplace(C128iu8a, MRe, BLOCK_BYTE_NUMBER);
			memcpy(Cip + BLOCK_BYTE_NUMBER, C128iu8a, MRe);
		}
		else
		{
			C128ip = (__m128i *)(Cip + BLOCK_BYTE_NUMBER);
			_mm_storeu_si128(C128ip, C128i[0]);
		}
		S = _mm_xor_si128(S, C128i[0]);

		C128i[0] = _mm_xor_si128(C128i[0], alphabeta[0][0]);

		Tweak[0] = _mm_slli_si128(alphabeta[0][1], 1);
		Tweak[0] = _mm_xor_si128(Tweak[0], oneone);

		AES_encrypt(C128i[0], &(C128i[0]), K128i, Tweak[0]);

		C128i[0] = _mm_xor_si128(C128i[0], M128i_L[0]);
		C128ip = (__m128i *)(Cip);
		_mm_storeu_si128(C128ip, C128i[0]);

		Bip += (1 * TRICK_BYTE_NUMBER);
	} 
	else
	{
		Tweak[0] = _mm_slli_si128(alphabeta[0][1], 1);
		AES_encrypt(alphabeta[0][0], &(C128i[0]), K128i, Tweak[0]);

		M128ip = (__m128i *)(Mip);
		M128i_L[0] = _mm_loadu_si128(M128ip);
		C128i[0] = _mm_xor_si128(C128i[0], M128i_L[0]);
		if (MRe != 0)
		{
			u8 * C128iu8a = (u8 *)C128i;
			memcpy(Cip, C128iu8a, MRe);
			u8 * M128iu8a = (u8 *)M128i_L;
			ozpInplace(M128iu8a, MRe, BLOCK_BYTE_NUMBER);
		}
		else
		{
			C128ip = (__m128i *)(Cip);
			_mm_storeu_si128(C128ip, C128i[0]);
		}

		S = _mm_xor_si128(S, M128i_L[0]);
	}

	B128ip = (__m128i *)(Bip);
	Tweak[0] = _mm_loadu_si128(B128ip);
	Tweak[0] = _mm_slli_si128(_mm_xor_si128(Tweak[0], alphabeta[0][1]), 1);

	if (((MBlockN & 1) == 0) && (MRe != 0))
	{
		Tweak[0] = _mm_insert_epi8(Tweak[0], 2, 0);
	}
	else if (((MBlockN & 1) == 0) && (MRe == 0))
	{
		Tweak[0] = _mm_insert_epi8(Tweak[0], 3, 0);
	}
	else if (((MBlockN & 1) != 0) && (MRe != 0))
	{
		Tweak[0] = _mm_insert_epi8(Tweak[0], 4, 0);
	}
	else
	{
		Tweak[0] = _mm_insert_epi8(Tweak[0], 5, 0);
	}
	S = _mm_xor_si128(S, alphabeta[0][0]);
	AES_encrypt(S, Y128ip, K128i, Tweak[0]);
};


void Hash_enc(
	unsigned char * Yh,
	unsigned char * Bh,
	long long BhByteN,
	unsigned char *Seedkey
)
{
	__m128i allzero = _mm_setzero_si128();
	__m128i Yh128i;
	__m128i Bh128i;
	__m128i *Yh128ip = (__m128i *)(Yh);
	__m128i *Bh128ip = (__m128i *)(Bh);

	u8 * Yhip = Yh;
	u8 * Bhip = Bh;

	__m128i P128i[PIPE];
	__m128i Tweak[PIPE];
	__m128i *P128ip;
	__m128i *Q128ip;

	__m128i gammadelta[PIPE + 1][2];

	__m128i K128i = _mm_loadu_si128((__m128i *)Seedkey);
	u8 lastblock[BLOCK_BYTE_NUMBER + TRICK_BYTE_NUMBER];

	s64 BhBlockN;
	s64 BhRe;
	s64 BhBlockN_N_1;

	Yh128i = allzero;

	gammadelta[0][0] = allzero;
	gammadelta[0][1] = allzero;
	Tweak[0] = _mm_set_epi64x(0x0000000000000002ULL, 0x0000000000000003ULL);
	Tweak[1] = _mm_set_epi64x(0x0000000000000003ULL, 0x0000000000000003ULL);
	AES_ecb_encrypt_2(gammadelta[0], K128i, Tweak);

	if (BhByteN != 0)
	{
		BhBlockN = BhByteN / (BLOCK_TRICK_BYTE_NUMBER);
		BhRe = BhByteN % (BLOCK_TRICK_BYTE_NUMBER);
		BhBlockN_N_1;
		if (BhRe == 0)
		{
			BhBlockN_N_1 = BhBlockN - 1;
			BhRe = BLOCK_TRICK_BYTE_NUMBER;
		}
		else
		{
			BhBlockN_N_1 = BhBlockN;
		}

		s64 ResBlockN = BhBlockN_N_1;

#if (PIPE > 1)
		while (ResBlockN >= PIPE)
		{
			mul2_PIPE_256(gammadelta[0]);

#pragma unroll(PIPE)
			for (int i = 0; i < PIPE; i++)
			{
				P128ip = (__m128i *)(Bhip + i * BLOCK_TRICK_BYTE_NUMBER);
				Q128ip = (__m128i *)(Bhip + i * BLOCK_TRICK_BYTE_NUMBER + BLOCK_BYTE_NUMBER);

				P128i[i] = _mm_loadu_si128(P128ip);
				P128i[i] = _mm_xor_si128(P128i[i], gammadelta[i][0]);
				Tweak[i] = _mm_loadu_si128(Q128ip);
				Tweak[i] = _mm_slli_si128(_mm_xor_si128(Tweak[i], gammadelta[i][1]), 1);
			}
			AES_ecb_encrypt_PIPE(P128i, K128i, Tweak);

#pragma unroll(PIPE)
			for (int i = 0; i < PIPE; i++)
			{
				Yh128i = _mm_xor_si128(Yh128i, P128i[i]);
			}
			gammadelta[0][0] = gammadelta[PIPE][0];
			gammadelta[0][1] = gammadelta[PIPE][1];

			Bhip += (BLOCK_TRICK_BYTE_NUMBER * PIPE);
			ResBlockN -= PIPE;
		}
#endif
		while (ResBlockN > 0)
		{
			mul2_256(&(gammadelta[0][0]), &(gammadelta[1][0]));

			int i = 0;
			P128ip = (__m128i *)(Bhip + i * BLOCK_TRICK_BYTE_NUMBER);
			Q128ip = (__m128i *)(Bhip + i * BLOCK_TRICK_BYTE_NUMBER + BLOCK_BYTE_NUMBER);

			P128i[i] = _mm_loadu_si128(P128ip);
			P128i[i] = _mm_xor_si128(P128i[i], gammadelta[i][0]);
			Tweak[i] = _mm_loadu_si128(Q128ip);
			Tweak[i] = _mm_slli_si128(_mm_xor_si128(Tweak[i], gammadelta[i][1]), 1);
			AES_encrypt(P128i[i], &(P128i[i]), K128i, Tweak[i]);
			Yh128i = _mm_xor_si128(Yh128i, P128i[i]);

			gammadelta[0][0] = gammadelta[1][0];
			gammadelta[0][1] = gammadelta[1][1];

			Bhip += (BLOCK_TRICK_BYTE_NUMBER * 1);
			ResBlockN -= 1;
		}
		if (BhRe != BLOCK_TRICK_BYTE_NUMBER)
		{
			ozpAD(BhRe, Bh + BhBlockN_N_1 * (BLOCK_TRICK_BYTE_NUMBER), lastblock);
		}
		else
		{
			memcpy(lastblock, Bh + BhBlockN_N_1 * (BLOCK_TRICK_BYTE_NUMBER), BLOCK_TRICK_BYTE_NUMBER);
		}
	}
	else
	{
		lastblock[0] = 0x80;
		for (int i = 0; i < BLOCK_TRICK_BYTE_NUMBER; i++)
		{
			lastblock[i] = 0;
		}
	}

	P128i[0] = _mm_loadu_si128((__m128i *)lastblock);
	Tweak[0] = _mm_loadu_si128((__m128i *)(lastblock + BLOCK_BYTE_NUMBER));

	Tweak[0] = _mm_xor_si128(Tweak[0], gammadelta[0][1]);
	Tweak[0] = _mm_slli_si128(Tweak[0], 1);
	if (BhRe != BLOCK_TRICK_BYTE_NUMBER)
	{
		Tweak[0] = _mm_insert_epi8(Tweak[0], 0x01, 0);
	}
	else
	{
		Tweak[0] = _mm_insert_epi8(Tweak[0], 0x02, 0);
	}
	P128i[0] = _mm_xor_si128(P128i[0], gammadelta[0][0]);
	AES_encrypt(P128i[0], &(P128i[0]), K128i, Tweak[0]);
	Yh128i = _mm_xor_si128(Yh128i, P128i[0]);
	_mm_storeu_si128(Yh128ip, Yh128i);
};