/* 
Simon and Speck Block cipher implementation
Published by NSA in June 2013, https://eprint.iacr.org/2013/404.pdf

Author: Nicolas Courtois, Theodosis Mourouzis, Guangyan Song
Jan 2014
*/

// Speck (64,128) implementation

#include "Speck.h"
#include "StdAfx.h"
#include "simonSpeckBasic.h"

void SpeckEncryptBlock64128(u32 PL,u32 PR,u32 &CL, u32 &CR, u32* key,int nn,int keysize,int rounds){
	// speck (64,128) version only
	// nn = 32; keysize = 128; mm = 4;
	int mm=keysize/nn;
	int Cj=0;
	int a = 8; int b = 3;
	u32 k[34]={0};
	u32 l[34]={0};
	k[0] = key[0];
	for(int i = 0;  i<mm-1;   i++){
		l[i] = key[i+1];
	}
	//------------------------- key expansion -------------------------
	for (int i = 0; i <= rounds-2; i++){
		l[i+mm-1] = (k[i] + ROTL(-a,l[i]))^i;
		k[i+1] = ROTL(b,k[i]) ^ l[i+mm-1];
		
	}
	

	//------------------------- encryption ----------------------------
	        u32 x=PL;u32 y=PR;
	for (int i = 0; i <= rounds-1; i++){
		x = (ROTL(-a,x) + y) ^ k[i];
		y = ROTL(b,y) ^ x;
		//printf("L:%08X\nk:%08x\n",x,y);
	}
	CL=x;CR=y;
}
