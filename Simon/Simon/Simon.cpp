
/* 
Simon and Speck Block cipher implementation
Published by NSA in June 2013, https://eprint.iacr.org/2013/404.pdf

Author: Nicolas Courtois, Theodosis Mourouzis, Guangyan Song
Jan 2014
*/
//
// SIMON cipher equation generator
// NSA cipher with low MC proposed by NSA
#include "Simon.h"
#include "StdAfx.h"
#include "simonSpeckBasic.h"


char Simonz[5][65] =
{"11111010001001010110000111001101111101000100101011000011100110",
"10001110111110010011000010110101000111011111001001100001011010",
"10101111011100000011010010011000101000010001111110010110110011",
"11011011101011000110010111100000010010001010011100110100001111",
"11010001111001101011011000100000010111000011001010010011101111"};

void SimonEncryptBlockALL(u64 PL,u64 PR,u64 &CL, u64 &CR, u64* key,int nn,int keysize)
{
	u64 k[72]={0};
	/*
	-------------------------- definitions --------------------------
	nn = word size (16, 24, 32, 48, or 64) - this version works for up to 32
	mm = number of key words (must be 4 if n = 16,
	3 or 4 if nn = 24 or 32,
	2 or 3 if nn = 48,
	2, 3, or 4 if nn = 64
	T = number of rounds, in this code it is variable
	Cj = const seq number, avoids self-similarity between different versions
	(T, Cj) = (32,0) if nn = 16
	= (36,0) or (36,1) if nn = 24, mm = 3 or 4
	= (42,2) or (44,3) if nn = 32, mm = 3 or 4
	= (52,2) or (54,3) if nn = 48, mm = 2 or 3
	= (68,2), (69,3), or (72,4) if nn = 64, mm = 2, 3, or 4
	x,y = plaintext words on nn bits
	k[m-1]..k[0] = key words on nn bits
	//*/

	//------------------------- key expansion -------------------------
	int mm=keysize/nn;
	int Cj=0,T=0;

	if (nn == 16) {T=32;Cj=0;}
	if (nn == 24 && mm == 3) { T=36; Cj=0;}
	if (nn == 24 && mm == 4) { T=36; Cj=1;}
	if (mm==3 && nn==32) {T=42;Cj=2;}
	if (mm==4 && nn==32) {T=44;Cj=3;}
	if (mm==2 && nn==48) {T=52;Cj=2;}
	if (mm==3 && nn==48) {T=54;Cj=3;}
	if (mm==2 && nn==64) {T=68;Cj=2;}
	if (mm==3 && nn==64) {T=69;Cj=3;}
	if (mm==4 && nn==64) {T=72;Cj=4;}

	int i,j=0;
	for(i = 0;      i<mm;   i++)
		k[i]=key[i];
	for(i = mm;     i<T;    i++)
	{
		u64 tmp=ROTL2((nn-3),k[i-1],nn);
		if (mm == 4)
			tmp ^= k[i-3];
		tmp = tmp ^ ROTL2((nn-1),tmp,nn);
		//is it bitwise negation?
		u64 t1 = ~(0xffffffffffffffff << nn);

		k[i] = (~(k[i-mm]) & t1) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;

	};
	//-------------------------- encryption ---------------------------
	u64 x=PL;u64 y=PR;
	for(i = 0;      i<T ;        i++)
	{
		u64 tmp = x;
		x = y ^ ROTL2(1,x,nn) & ROTL2(8,x,nn) ^ ROTL2(2,x,nn) ^ k[i];
		y = tmp;
	};
	CL=x;CR=y;
}    
void SimonEncryptBlockALL(u64 PL, u64 PR, u64 &CL, u64 &CR, u64* key, int nn, int keysize, int rounds)
{
	u64 k[72] = { 0 };
	/*
	-------------------------- definitions --------------------------
	nn = word size (16, 24, 32, 48, or 64) - this version works for up to 32
	mm = number of key words (must be 4 if n = 16,
	3 or 4 if nn = 24 or 32,
	2 or 3 if nn = 48,
	2, 3, or 4 if nn = 64
	T = number of rounds, in this code it is variable
	Cj = const seq number, avoids self-similarity between different versions
	(T, Cj) = (32,0) if nn = 16
	= (36,0) or (36,1) if nn = 24, mm = 3 or 4
	= (42,2) or (44,3) if nn = 32, mm = 3 or 4
	= (52,2) or (54,3) if nn = 48, mm = 2 or 3
	= (68,2), (69,3), or (72,4) if nn = 64, mm = 2, 3, or 4
	x,y = plaintext words on nn bits
	k[m-1]..k[0] = key words on nn bits
	//*/

	//------------------------- key expansion -------------------------
	int mm = keysize / nn;
	int Cj = 0, T = 0;

	if (nn == 16) { T = 32; Cj = 0; }
	if (nn == 24 && mm == 3) { T = 36; Cj = 0; }
	if (nn == 24 && mm == 4) { T = 36; Cj = 1; }
	if (mm == 3 && nn == 32) { T = 42; Cj = 2; }
	if (mm == 4 && nn == 32) { T = 44; Cj = 3; }
	if (mm == 2 && nn == 48) { T = 52; Cj = 2; }
	if (mm == 3 && nn == 48) { T = 54; Cj = 3; }
	if (mm == 2 && nn == 64) { T = 68; Cj = 2; }
	if (mm == 3 && nn == 64) { T = 69; Cj = 3; }
	if (mm == 4 && nn == 64) { T = 72; Cj = 4; }

	T = rounds;

	int i, j = 0;
	for (i = 0; i<mm; i++)
		k[i] = key[i];
	for (i = mm; i<T; i++)
	{
		u64 tmp = ROTL2((nn - 3), k[i - 1], nn);
		if (mm == 4)
			tmp ^= k[i - 3];
		tmp = tmp ^ ROTL2((nn - 1), tmp, nn);
		//is it bitwise negation?
		u64 t1 = ~(0xffffffffffffffff << nn);

		k[i] = (~(k[i - mm]) & t1) ^ tmp ^ (Simonz[Cj][(i - mm) % 62] - '0') ^ 3;

	};
	//-------------------------- encryption ---------------------------
	u64 x = PL; u64 y = PR;
	for (i = 0; i<T; i++)
	{
		u64 tmp = x;
		x = y ^ ROTL2(1, x, nn) & ROTL2(8, x, nn) ^ ROTL2(2, x, nn) ^ k[i];
		y = tmp;
	};
	CL = x; CR = y;
}

void SimonEncryptBlockALL(u64 PL, u64 PR, u64 &CL, u64 &CR, u64* ZR, u64* ZL, u64* key, int nn, int keysize, int rounds){
	u64 k[72] = { 0 };
	/*
	-------------------------- definitions --------------------------
	nn = word size (16, 24, 32, 48, or 64) - this version works for up to 32
	mm = number of key words (must be 4 if n = 16,
	3 or 4 if nn = 24 or 32,
	2 or 3 if nn = 48,
	2, 3, or 4 if nn = 64
	T = number of rounds, in this code it is variable
	Cj = const seq number, avoids self-similarity between different versions
	(T, Cj) = (32,0) if nn = 16
	= (36,0) or (36,1) if nn = 24, mm = 3 or 4
	= (42,2) or (44,3) if nn = 32, mm = 3 or 4
	= (52,2) or (54,3) if nn = 48, mm = 2 or 3
	= (68,2), (69,3), or (72,4) if nn = 64, mm = 2, 3, or 4
	x,y = plaintext words on nn bits
	k[m-1]..k[0] = key words on nn bits
	//*/

	//------------------------- key expansion -------------------------
	int mm = keysize / nn;
	int Cj = 0, T = 0;

	if (nn == 16) { T = 32; Cj = 0; }
	if (nn == 24 && mm == 3) { T = 36; Cj = 0; }
	if (nn == 24 && mm == 4) { T = 36; Cj = 1; }
	if (mm == 3 && nn == 32) { T = 42; Cj = 2; }
	if (mm == 4 && nn == 32) { T = 44; Cj = 3; }
	if (mm == 2 && nn == 48) { T = 52; Cj = 2; }
	if (mm == 3 && nn == 48) { T = 54; Cj = 3; }
	if (mm == 2 && nn == 64) { T = 68; Cj = 2; }
	if (mm == 3 && nn == 64) { T = 69; Cj = 3; }
	if (mm == 4 && nn == 64) { T = 72; Cj = 4; }

	T = rounds;

	int i, j = 0;
	for (i = 0; i<mm; i++)
		k[i] = key[i];
	for (i = mm; i<T; i++)
	{
		u64 tmp = ROTL2((nn - 3), k[i - 1], nn);
		if (mm == 4)
			tmp ^= k[i - 3];
		tmp = tmp ^ ROTL2((nn - 1), tmp, nn);
		//is it bitwise negation?
		u64 t1 = ~(0xffffffffffffffff << nn);

		k[i] = (~(k[i - mm]) & t1) ^ tmp ^ (Simonz[Cj][(i - mm) % 62] - '0') ^ 3;

	};
	//-------------------------- encryption ---------------------------
	u64 x = PL; u64 y = PR;
	for (i = 0; i<T; i++)
	{
		ZL[i] = x;
		ZR[i] = y;
		u64 tmp = x;
		x = y ^ ROTL2(1, x, nn) & ROTL2(8, x, nn) ^ ROTL2(2, x, nn) ^ k[i];
		y = tmp;
	};
	CL = x; CR = y;
}
void SimonDecryptBlock64128(u32 CL,u32 CR,u32 &PL, u32 &PR, u32* key,int nn,int keysize,int rounds){
	u32 k[72]={0};
	int mm=keysize/nn;
	int Cj=0,T=0;

	if (nn == 16) {T=32;Cj=0;};
	if (nn == 24 && mm == 3) { T=36; Cj=0;};
	if (nn == 24 && mm == 4) { T=36; Cj=1;};
	if(mm==3 && nn==32) {T=42;Cj=2;};
	if(mm==4 && nn==32) {T=44;Cj=3;};

	int i,j=0;
	for(i = 0;      i<mm;   i++)
		k[i]=key[i];
	for(i = mm;     i<T;    i++)
	{
		u32 tmp=ROTL((nn-3),k[i-1]);
		if (mm == 4)
			tmp ^= k[i-3];
		tmp = tmp ^ ROTL(31,tmp);
		k[i] = (~(k[i-mm])) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;
	};

	u32 x = CL; u32 y = CR;
	for (int i = 0; i < rounds; ++i) {
		u32 tmp = y;
		y = ROTL(1,y) & ROTL(8,y) ^ ROTL(2,y) ^ x ^ k[rounds-i-1];
		x = tmp;
	}

    PL = x; PR = y;
}



//#define ROTL( n, X )    ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )
void SimonEncryptBlock64128(u32 PL,u32 PR,u32 &CL, u32 &CR, u32* key,int nn,int keysize,int rounds)
{

	if(nn>32) printf("not done for 48 and 64-bit words");
	if(nn<32) printf("can work for less than 32 but ROTL must be modified");
	u32 k[72]={0};
	/*
	-------------------------- definitions --------------------------
	nn = word size (16, 24, 32, 48, or 64) - this version works for up to 32
	mm = number of key words (must be 4 if n = 16,
	3 or 4 if nn = 24 or 32,
	2 or 3 if nn = 48,
	2, 3, or 4 if nn = 64
	T = number of rounds, in this code it is variable
	Cj = const seq number, avoids self-similarity between different versions
	(T, Cj) = (32,0) if nn = 16
	= (36,0) or (36,1) if nn = 24, mm = 3 or 4
	= (42,2) or (44,3) if nn = 32, mm = 3 or 4
	= (52,2) or (54,3) if nn = 48, mm = 2 or 3
	= (68,2), (69,3), or (72,4) if nn = 64, mm = 2, 3, or 4
	x,y = plaintext words on nn bits
	k[m-1]..k[0] = key words on nn bits
	//*/
	//------------------------- key expansion -------------------------
	int mm=keysize/nn;
	int Cj=0,T=0;

	if (nn == 16) {T=32;Cj=0;};
	if (nn == 24 && mm == 3) { T=36; Cj=0;};
	if (nn == 24 && mm == 4) { T=36; Cj=1;};
	if(mm==3 && nn==32) {T=42;Cj=2;};
	if(mm==4 && nn==32) {T=44;Cj=3;};

	int i,j=0;
	for(i = 0;      i<mm;   i++)
		k[i]=key[i];
	for(i = mm;     i<T;    i++)
	{
		u32 tmp=ROTL((nn-3),k[i-1]);
		if (mm == 4)
			tmp ^= k[i-3];
		tmp = tmp ^ ROTL(31,tmp);
		//is it bitwise negation?
		k[i] = (~(k[i-mm])) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;
	};
	//-------------------------- encryption ---------------------------
	u32 x=PL;u32 y=PR;
	for(i = 0;      i<T && i<rounds;        i++)
	{
		u32 tmp = x;
		x = y ^ ROTL(1,x) & ROTL(8,x) ^ ROTL(2,x) ^ k[i];
		y = tmp;
	};
	CL=x;CR=y;
} 


void SimonEncryptBlock64128(u32 PL,u32 PR,u32 &CL, u32 &CR, u32* ZR, u32* ZL, u32* key,int nn,int keysize,int rounds)
{

	if(nn>32) printf("not done for 48 and 64-bit words");
	if(nn<32) printf("can work for less than 32 but ROTL must be modified");
	u32 k[72]={0};
	/*
	-------------------------- definitions --------------------------
	nn = word size (16, 24, 32, 48, or 64) - this version works for up to 32
	mm = number of key words (must be 4 if n = 16,
	3 or 4 if nn = 24 or 32,
	2 or 3 if nn = 48,
	2, 3, or 4 if nn = 64
	T = number of rounds, in this code it is variable
	Cj = const seq number, avoids self-similarity between different versions
	(T, Cj) = (32,0) if nn = 16
	= (36,0) or (36,1) if nn = 24, mm = 3 or 4
	= (42,2) or (44,3) if nn = 32, mm = 3 or 4
	= (52,2) or (54,3) if nn = 48, mm = 2 or 3
	= (68,2), (69,3), or (72,4) if nn = 64, mm = 2, 3, or 4
	x,y = plaintext words on nn bits
	k[m-1]..k[0] = key words on nn bits
	//*/
	//------------------------- key expansion -------------------------
	int mm=keysize/nn;
	int Cj=0,T=0;

	if (nn == 16) {T=32;Cj=0;};
	if (nn == 24 && mm == 3) { T=36; Cj=0;};
	if (nn == 24 && mm == 4) { T=36; Cj=1;};
	if(mm==3 && nn==32) {T=42;Cj=2;};
	if(mm==4 && nn==32) {T=44;Cj=3;};

	int i,j=0;
	for(i = 0;      i<mm;   i++)
		k[i]=key[i];
	for(i = mm;     i<T;    i++)
	{
		u32 tmp=ROTL((nn-3),k[i-1]);
		if (mm == 4)
			tmp ^= k[i-3];
		tmp = tmp ^ ROTL(31,tmp);
		//is it bitwise negation?
		k[i] = (~(k[i-mm])) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;
	};
	//-------------------------- encryption ---------------------------
	u32 x=PL;u32 y=PR;
	for(i = 0;      i<T && i<rounds;        i++)
	{
		ZL[i] = x;
		ZR[i] = y;
		u32 tmp = x;
		x = y ^ ROTL(1,x) & ROTL(8,x) ^ ROTL(2,x) ^ k[i];
		y = tmp;
		//printf("Round %d: %08x %08x\n",i+1,x,y);
	};
	CL=x;CR=y;
} 


