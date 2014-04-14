/* 
Simon and Speck Block cipher implementation
Published by NSA in June 2013, https://eprint.iacr.org/2013/404.pdf

Author: Nicolas Courtois, Theodosis Mourouzis, Guangyan Song
Jan 2014
*/

#include "stdafx.h"
#include "Equations.h"


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

}

