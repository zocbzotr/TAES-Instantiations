/** @file timing.cpp
 */
#ifdef __GNUC__
#include <sched.h>
#include <unistd.h> 
#endif

#include "timing.h"

using namespace std;

#define MAX_MESSAGE_LENGTH (1UL << 20UL)
#define MAX_ASSOCIATED_DATA_LENGTH ((1UL<<20UL) - (1UL << (20UL - 4UL)))

#define MAX_SHORT_MESSAGE_LENGTH (1UL << 10UL)
#define MAX_SHORT_ASSOCIATED_DATA_LENGTH ((1UL<<10UL) - (1UL << (10UL - 4UL)))

#ifdef _MSC_VER
#define DUAL_CORE

#if defined( DUAL_CORE )
#  define WINDOWS_LEAN_AND_MEAN
#  include <windows.h>
#endif
#include <string.h>
#include <math.h>

#include <intrin.h>
#pragma intrinsic( __rdtsc )

__inline unsigned long long read_tsc(void)
{
	return __rdtsc();
}

#if defined( _M_IX86 )
#if _M_IX86 == 500
#define PROCESSOR   "Pentium"
#elif _M_IX86 == 600
#define PROCESSOR   "P2/P3/P4"
#else
#define PROCESSOR   ""
#endif
#elif defined( _M_X64 )
#define PROCESSOR   "AMD64/EMT64"
#else
#define PROCESSOR   ""
#endif

#if defined( _WIN64 )

#define CurrentProcessorNumber GetCurrentProcessorNumber

#else

unsigned long CurrentProcessorNumber(void)
{
    __asm
    {
        mov     eax,1
        cpuid
        shr     ebx,24
        mov     eax, ebx
    }
}

#endif

void setCPUaffinity()
{
#if defined( DUAL_CORE ) && defined( _WIN32 )
    HANDLE ph;
    DWORD_PTR afp;
    DWORD_PTR afs;
    ph = GetCurrentProcess();
    if(GetProcessAffinityMask(ph, &afp, &afs))
    {
        afp &= (1 << CurrentProcessorNumber());
        if(!SetProcessAffinityMask(ph, afp))
        {
            printf("Couldn't set Process Affinity Mask\n\n");
        }
    }
    else
    {
        printf("Couldn't get Process Affinity Mask\n\n");
    }
#endif
}

#else
#ifdef __GNUC__
#include <sys/resource.h>
#include <x86intrin.h>
inline unsigned long long read_tsc(void)
{
#if defined(__i386__)
	unsigned long long cycles;
	__asm__ volatile (".byte 0x0f, 0x31" : "=A"(cycles));
	return cycles;
#else
#if defined(__x86_64__)
	unsigned int hi, lo;
	__asm__ volatile ("rdtsc" : "a="(lo), "=d"(hi));
	return (((unsigned long long)lo) | ((unsigned long long)(hi)<<32));
#else
#error "Unsupported architecture for counting cycles"
#endif
#endif
}

void setCPUaffinity()
{
	cpu_set_t cpu_mask;
	CPU_SET(0x1, &cpu_mask);
	if(sched_setaffinity(getpid(), sizeof(cpu_mask), &cpu_mask) == -1 )
	{
		printf("Impossible to set CPU affinity...\n");
	}
}
#endif
#endif

#define RAND(a,b) (((a = 36969 * (a & 65535) + (a >> 16)) << 16) + \
	(b = 18000 * (b & 65535) + (b >> 16))  )

void block_rndfill(unsigned char *buf, const int len)
{
	static unsigned long a[2], mt = 1, count = 4;
	static unsigned char r[4];
	int                  i;

	if(mt) { mt = 0; *(unsigned long long*)a = read_tsc(); }

	for(i = 0; i < len; ++i)
	{
		if(count == 4)
		{
			*(unsigned long*)r = RAND(a[0], a[1]);
			count = 0;
		}

		buf[i] = r[count++];
	}
}

const int loops = 100;

#define SAMPLE1  1000
#define SAMPLE2 10000

#define TRUE  1
#define FALSE 0

int timeBase(double *av, double *sig)
{
	volatile int                 i, tol, lcnt, sam_cnt;
	volatile double              cy, av1, sig1;

	tol = 10; lcnt = sam_cnt = 0;
	while(!sam_cnt)
	{
		av1 = sig1 = 0.0;

		for(i = 0; i < SAMPLE1; ++i)
		{
			cy = (volatile double)read_tsc();
			cy = (volatile double)read_tsc() - cy;

			av1 += cy;
			sig1 += cy * cy;
		}

		av1 /= SAMPLE1;
		sig1 = sqrt((sig1 - av1 * av1 * SAMPLE1) / SAMPLE1);
		sig1 = (sig1 < 0.05 * av1 ? 0.05 * av1 : sig1);

		*av = *sig = 0.0;
		for(i = 0; i < SAMPLE2; ++i)
		{
			cy = (volatile double)read_tsc();
			cy = (volatile double)read_tsc() - cy;

			if(cy > av1 - sig1 && cy < av1 + sig1)
			{
				*av += cy;
				*sig += cy * cy;
				sam_cnt++;
			}
		}

		if(10 * sam_cnt > 9 * SAMPLE2)
		{
			*av /= sam_cnt;
			*sig = sqrt((*sig - *av * *av * sam_cnt) / sam_cnt);

			if(*sig > (tol / 100.0) * *av)
				sam_cnt = 0;
		}
		else
		{
			if(lcnt++ == 10)
			{
				lcnt = 0; tol += 5;
				if(tol > 30)
					return FALSE;
			}
			sam_cnt = 0;
		}
	}
	return TRUE;
}

int time_enc16(double *av, double *sig, unsigned int k_len, unsigned long long dataLengthInBytes, unsigned long long AdataLengthInBytes)
{
	volatile int       i, tol, lcnt, sam_cnt;
	volatile double    cy, av1, sig1;
	unsigned char      key[16];
	unsigned char      nonce[16];
	unsigned char      tag[16];
	unsigned char      pt[4][MAX_SHORT_MESSAGE_LENGTH];
	unsigned char      at[4][MAX_SHORT_ASSOCIATED_DATA_LENGTH];

	for (int i = 0; i < 4; i++)
	{
		block_rndfill(pt[i], dataLengthInBytes);
		block_rndfill(at[i], AdataLengthInBytes);
	}

	int out_len;

	block_rndfill(key, 16);
	block_rndfill(nonce, 16);

	tol = 10; lcnt = sam_cnt = 0;
	while(!sam_cnt)
	{
		av1 = sig1 = 0.0;

		for(i = 0; i < SAMPLE1; ++i)
		{
			cy = (double)read_tsc();
			ZOCB_enc(pt[0], tag, nonce, at[0], pt[0], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[1], tag, nonce, at[1], pt[1], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[2], tag, nonce, at[2], pt[2], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[3], tag, nonce, at[3], pt[3], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[0], tag, nonce, at[0], pt[0], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[1], tag, nonce, at[1], pt[1], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[2], tag, nonce, at[2], pt[2], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[3], tag, nonce, at[3], pt[3], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[0], tag, nonce, at[0], pt[0], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[1], tag, nonce, at[1], pt[1], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[2], tag, nonce, at[2], pt[2], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[3], tag, nonce, at[3], pt[3], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[0], tag, nonce, at[0], pt[0], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[1], tag, nonce, at[1], pt[1], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[2], tag, nonce, at[2], pt[2], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[3], tag, nonce, at[3], pt[3], AdataLengthInBytes, dataLengthInBytes, key);
			cy = (double)read_tsc() - cy;

			av1 += cy;
			sig1 += cy * cy;
		}

		av1 /= SAMPLE1;
		sig1 = sqrt((sig1 - av1 * av1 * SAMPLE1) / SAMPLE1);
		sig1 = (sig1 < 0.05 * av1 ? 0.05 * av1 : sig1);

		*av = *sig = 0.0;
		for(i = 0; i < SAMPLE2; ++i)
		{
			cy = (double)read_tsc();
			ZOCB_enc(pt[0], tag, nonce, at[0], pt[0], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[1], tag, nonce, at[1], pt[1], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[2], tag, nonce, at[2], pt[2], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[3], tag, nonce, at[3], pt[3], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[0], tag, nonce, at[0], pt[0], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[1], tag, nonce, at[1], pt[1], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[2], tag, nonce, at[2], pt[2], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[3], tag, nonce, at[3], pt[3], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[0], tag, nonce, at[0], pt[0], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[1], tag, nonce, at[1], pt[1], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[2], tag, nonce, at[2], pt[2], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[3], tag, nonce, at[3], pt[3], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[0], tag, nonce, at[0], pt[0], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[1], tag, nonce, at[1], pt[1], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[2], tag, nonce, at[2], pt[2], AdataLengthInBytes, dataLengthInBytes, key);
			ZOCB_enc(pt[3], tag, nonce, at[3], pt[3], AdataLengthInBytes, dataLengthInBytes, key);
			cy = (double)read_tsc() - cy;

			if(cy > av1 - sig1 && cy < av1 + sig1)
			{
				*av += cy;
				*sig += cy * cy;
				sam_cnt++;
			}
		}

		if(10 * sam_cnt > 9 * SAMPLE2)
		{
			*av /= sam_cnt;
			*sig = sqrt((*sig - *av * *av * sam_cnt) / sam_cnt);
			if(*sig > (tol / 100.0) * *av)
				sam_cnt = 0;
		}
		else
		{
			if(lcnt++ == 10)
			{
				lcnt = 0; tol += 5;
				if(tol > 30)
				{
					return FALSE;
				}
			}
			sam_cnt = 0;
		}
	}
	return TRUE;
}

double enc_cycles(unsigned int k_len, unsigned long long dataLengthInBytes, unsigned long long AdataLengthInBytes)
{
	volatile double cy1, cy2, c1 = -1, c2 = -1;
	volatile int i;
	int out_len;
	unsigned char  key[16];
	unsigned char  nonce[16];
	unsigned char  tag[16];
	unsigned char  pt[MAX_MESSAGE_LENGTH];
	unsigned char  at[MAX_ASSOCIATED_DATA_LENGTH];

	block_rndfill(key, 16);

	block_rndfill(pt, dataLengthInBytes);   c1 = c2 = 0xffffffffffffffff;
	block_rndfill(at, AdataLengthInBytes);

	ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);

	for(i = 0; i < loops; ++i)
	{
		cy1 = (volatile double)read_tsc();
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		cy1 = (volatile double)read_tsc() - cy1;

		cy2 = (volatile double)read_tsc();
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		ZOCB_enc(pt, tag, nonce, at, pt, AdataLengthInBytes, dataLengthInBytes, key);
		cy2 = (volatile double)read_tsc() - cy2;

		if(i > (loops / 10))
		{
			c1 = (c1 < cy1 ? c1 : cy1);
			c2 = (c2 < cy2 ? c2 : cy2);
		}
	}
	return ((c2 - c1) + 4.0) / 8.0;
}

static unsigned long ml[] = { 
	0, 
	1UL << 4UL,
	1UL << 5UL,
	1UL << 6UL,
	1UL << 7UL,
	1UL << 8UL,
	1UL << 9UL,
	1UL << 10UL,
	1UL << 11UL,
	1UL << 12UL,
	1UL << 13UL,
	1UL << 14UL,
	1UL << 15UL,
	1UL << 16UL,
	1UL << 17UL,
	1UL << 18UL,
	1UL << 19UL,
	1UL << 20UL
	};
static unsigned long al[] = { 
	0, 
	(1UL<<4UL) - (1UL << (4UL - 4UL)),
	(1UL<<5UL) - (1UL << (5UL - 4UL)),
	(1UL<<6UL) - (1UL << (6UL - 4UL)),
	(1UL<<7UL) - (1UL << (7UL - 4UL)),
	(1UL<<8UL) - (1UL << (8UL - 4UL)),
	(1UL<<9UL) - (1UL << (9UL - 4UL)),
	(1UL<<10UL) - (1UL << (10UL - 4UL)),
	(1UL<<11UL) - (1UL << (11UL - 4UL)),
	(1UL<<12UL) - (1UL << (12UL - 4UL)),
	(1UL<<13UL) - (1UL << (13UL - 4UL)),
	(1UL<<14UL) - (1UL << (14UL - 4UL)),
	(1UL<<15UL) - (1UL << (15UL - 4UL)),
	(1UL<<16UL) - (1UL << (16UL - 4UL)),
	(1UL<<17UL) - (1UL << (17UL - 4UL)),
	(1UL<<18UL) - (1UL << (18UL - 4UL)),
	(1UL<<19UL) - (1UL << (19UL - 4UL)),
	(1UL<<20UL) - (1UL << (20UL - 4UL)),
	};

static double et, dt;

void timing()
{
	ofstream fout;
	string fn;
	double   a0, av, sig;
	int ki, i, w;
	unsigned long long pi;
	unsigned long long ai;
	unsigned long long di;

	setCPUaffinity();

	fn = "ZOCB_ENC_Timing_PIPE"+ to_string((u64)PIPE) + ".csv";
	fout.open(fn.c_str(), ios::app);
	fout.setf(ios::fixed);
	fout << std::right;

	fout << "Encryption Timing (cycles/byte)" << endl;
	fout << setw(20) << "P_len/AD_len(bytes)" << ",";
	for (ai = 0; ai < sizeof(al)/sizeof(unsigned long); ai++)
	{
		fout << setw(10) << al[ai] << ",";
	}
	fout << endl;
	for (pi = 0; pi < sizeof(ml)/sizeof(unsigned long); pi++)
	{
		fout << setw(20) << ml[pi] << ",";
		for (ai = 0; ai < sizeof(al)/sizeof(unsigned long); ai++)
		{
			et = enc_cycles(256, ml[pi], al[ai]);
			if ((ml[pi] == 0) && (al[ai] == 0))
			{
				av = et;
			}
			else
			{
				av = et / (ml[pi] + al[ai]);
			}
			
			fout << setiosflags(ios::fixed) << std::setprecision(2);
			fout << setw(10) << av << ",";
		}
		fout << setiosflags(ios::fixed) << std::setprecision(0);
		fout << endl;
	}
	fout << endl;
	fout.close();

	fn = "ZOCB_ENC_Short_Timing_PIPE"+ to_string((u64)PIPE) + ".csv";
	fout.open(fn.c_str(), ios::app);
	fout.setf(ios::fixed);
	fout << std::right;
	while (timeBase(&a0, &sig) != TRUE) {}
	fout << setw(20) << "P_len/AD_len(bytes)" << ",";
	for (ai = 0; ai <= MAX_SHORT_ASSOCIATED_DATA_LENGTH; ai += 15UL)
	{
		fout << setw(20) << ai << ",";
	}
	fout << endl;
	for (pi = 16UL; pi <= MAX_SHORT_MESSAGE_LENGTH; pi += 16UL)
	{
		fout << setw(20) << pi << ",";
		for (ai = 0; ai <= MAX_SHORT_ASSOCIATED_DATA_LENGTH; ai += 15UL)
		{
			while (time_enc16(&av, &sig, 256, pi, ai) != TRUE) {}
			sig *= 100.0 / av;
			av = (int)(10.0 * (av - a0) / (16.0 * (pi + ai))) / 10.0;
			fout << setw(10) << setprecision(2) << av << " ("  <<setw(6) << sig << "%),";
		}
		fout << setiosflags(ios::fixed) << std::setprecision(0);
		fout << endl;
	}
	fout << endl;
	fout.close();
}

