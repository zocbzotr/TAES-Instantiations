/** @file test.cpp
  */
#include "test.h"

using namespace std;

#define MN 56
#define AN 24

void test()
{
	ofstream fout;
	string fn = "test_p" + to_string((u64)PIPE) + ".txt";
	fout.open(fn.c_str());
	
	ALIGNED_TYPE_(u8, 16) Seedkey[] =
	{
		0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
		0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
		0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
		0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
	};
	
	u8 plain[MN];
	u8 cipher[MN];
	u8 assoc[AN];
	u8 nounc[BLOCK_BYTE_NUMBER];
	u8 tag[TAG_BYTE_NUMBER];
	
	for (u64 i = 0; i < MN; i++)
	{
		plain[i] = 0;
		cipher[i] = 0;
	}
	for (u64 i = 0; i < AN; i++)
	{
		assoc[i] = 0;
	}
	for (u64 i = 0; i < BLOCK_BYTE_NUMBER; i++)
	{
		nounc[i] = 0;
	}
	
	
	ThetaCB3_enc(
		cipher,
		tag,
		nounc,
		assoc,
		plain,
		AN,
		MN,
		Seedkey
	);
	
	fout << hex;
	fout << setfill('0');
	fout << "Plain:" << endl;
	for (u64 i = 0; i < MN; i++)
	{
		fout << setw(2) << plain[i] + '\0';
	}
	fout << endl;
	fout << "Cipher:" << endl;
	for (u64 i = 0; i < MN; i++)
	{
		fout << setw(2) << cipher[i] + '\0';
	}
	fout << endl;
	fout << "Tag:" << endl;
	for (u64 i = 0; i < TAG_BYTE_NUMBER; i++)
	{
		fout << setw(2) << tag[i] + '\0';
	}
	fout << endl;
	fout.close();

}

