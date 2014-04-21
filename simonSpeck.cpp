
/* 
Simon and Speck Block cipher implementation
Published by NSA in June 2013, https://eprint.iacr.org/2013/404.pdf

Author: Nicolas Courtois, Theodosis Mourouzis, Guangyan Song
Jan 2014
*/
//
// SIMON cipher equation generator
// NSA cipher with low MC proposed by NSA

#include "stdafx.h"
#include "simonSpeckBasic.h"
#include "Simon.h"
#include "Equations.h"
#include "Speck.h"

int _tmain(int argc, _TCHAR* argv[])
{


	u32 PL,PR,CL,CR;
	u32 key[4]={0};

	//Simon 64/128 test vector
	//Key: 1b1a1918 13121110 0b0a0908 03020100
	//Plaintext: 656b696c 20646e75
	//Ciphertext: 44c8fc20 b9dfa07a
	key[3]=0x1b1a1918;key[2]=0x13121110;key[1]=0x0b0a0908;key[0]=0x03020100;
	PL=0x656b696c;  PR=0x20646e75;
	SimonEncryptBlock64128(PL,PR,CL,CR,key,32,128,44);
	printf("%08X %08X\n",CL,CR);

	// Generate equations for 8 Round Simon with 5 random fixed key bits, using 2 P/C pairs 
	int fk = 5;
	int round = 8;
	SimonEncryptBlock64128(PL,PR,CL,CR,key,32,128,round);

	generateEquation(PL,PR,CL,CR,key,32,128, round, fk ,0);
	// second P/C pair
	PL=CL;
	PR=CR;
	SimonEncryptBlock64128(PL,PR,CL,CR,key,32,128,round);

	generateEquation(PL,PR,CL,CR,key,32,128, round, fk ,1);



	//Speck 64/128 test vector
	//Key: 1b1a1918 13121110 0b0a0908 03020100
	//Plaintext: 3b726574 7475432d
	//Ciphertext: 8c6fa548 454e028b
	key[3]=0x1b1a1918;key[2]=0x13121110;key[1]=0x0b0a0908;key[0]=0x03020100;
	PL=0x3b726574;  PR=0x7475432d;
	SpeckEncryptBlock64128(PL,PR,CL,CR,key,32,128,27);
	printf("%08X %08X\n",CL,CR);



	u64 PL64,PR64,CL64,CR64;
	u64 k[4]={0};


	k[3]=0x1918;k[2]=0x1110;k[1]=0x0908;k[0]=0x0100;
	PL64=0x6565;  PR64=0x6877;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,16,64);
	printf("%04X ",CL64);	printf("%04X\n",CR64);

	k[2]=0x121110;k[1]=0x0a0908;k[0]=0x020100;
	PL64=0x612067;  PR64=0x6e696c;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,24,72);
	printf("%06X ",CL64); printf("%06X\n",CR64);

	k[3]=0x1a1918;k[2]=0x121110;k[1]=0x0a0908;k[0]=0x020100;
	PL64=0x726963;  PR64=0x20646e;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,24,96);
	printf("%06X ",CL64);printf("%06X\n",CR64);

	k[2]=0x13121110;k[1]=0x0b0a0908;k[0]=0x03020100;
	PL64=0x6f722067;  PR64=0x6e696c63;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,32,96);
	printf("%08X ",CL64);printf("%08X\n",CR64);

	k[3]=0x1b1a1918;k[2]=0x13121110;k[1]=0x0b0a0908;k[0]=0x03020100;
	PL64=0x656b696c;  PR64=0x20646e75;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,32,128);
	printf("%08X ",CL64); printf("%08X\n",CR64);

	k[1]=0x0d0c0b0a0908;k[0]=0x050403020100;
	PL64=0x2072616c6c69;  PR64=0x702065687420;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,48,96);
	printf("%04X",(CL64>>32));printf("%08X ",CL64);printf("%04X",(CR64>>32));printf("%08X\n",CR64);

	k[2]=0x151413121110;k[1]=0x0d0c0b0a0908;k[0]=0x050403020100;
	PL64=0x746168742074;  PR64=0x73756420666f;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,48,144);
	printf("%04X",(CL64>>32));printf("%08X ",CL64);printf("%04X",(CR64>>32));printf("%08X\n",CR64);

	k[1]=0x0f0e0d0c0b0a0908;k[0]=0x0706050403020100;
	PL64=0x6373656420737265;  PR64=0x6c6c657661727420;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,64,128);
	printf("%08X",(CL64>>32));printf("%08X ",CL64);printf("%08X",(CR64>>32));printf("%08X\n",CR64);

	k[2]=0x1716151413121110;k[1]=0x0f0e0d0c0b0a0908;k[0]=0x0706050403020100;
	PL64=0x206572656874206e;  PR64=0x6568772065626972;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,64,192);
	printf("%08X",(CL64>>32));printf("%08X ",CL64);printf("%08X",(CR64>>32));printf("%08X\n",CR64);

	k[3]=0x1f1e1d1c1b1a1918;k[2]=0x1716151413121110;k[1]=0x0f0e0d0c0b0a0908;k[0]=0x0706050403020100;
	PL64=0x74206e69206d6f6f;  PR64=0x6d69732061207369;
	SimonEncryptBlockALL(PL64,PR64,CL64,CR64,k,64,256);
	printf("%08X",(CL64>>32));printf("%08X ",CL64);	printf("%08X",(CR64>>32));printf("%08X\n",CR64);

	return 0;
}

