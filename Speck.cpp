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
		l[i+mm-1] = (k[i] + ROTL(-a,l[i]) )^i;

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

void SpeckEncryptBlock(u64 PL,u64 PR,u64 &CL, u64 &CR, u64* key,int nn,int keysize){
	// speck (64,128) version only
	// nn = 32; keysize = 128; mm = 4;
	int mm=keysize/nn;
	int Cj=0;
	int T,a,b;
	if (nn == 16){T=22;}
	if (nn == 24 && mm == 3) {T = 22;}
	if (nn == 24 && mm == 4) {T = 23;}
	if (nn == 32 && mm == 3) {T = 26;}
	if (nn == 32 && mm == 4) {T = 27;}
	if (nn == 48 && mm == 2) {T = 28;}
	if (nn == 48 && mm == 3) {T = 29;}
	if (nn == 64 && mm == 2) {T = 32;}
	if (nn == 64 && mm == 3) {T = 33;}
	if (nn == 64 && mm == 4) {T = 34;}


	if ( nn == 16){a = 7; b = 2;}
	else{ a = 8; b = 3; }
	u64 k[34]={0};
	u64 l[60]={0};
	k[0] = key[0];
	for(int i = 0;  i<mm-1;   i++){
		l[i] = key[i+1];
	}
	//------------------------- key expansion -------------------------
	for (int i = 0; i <= T-2; i++){
		l[i+mm-1] = (k[i] + ROTL2((nn-a),l[i],nn) & (0xffffffffffffffff >> (64-nn) ) )^i;
		k[i+1] = ROTL2(b,k[i],nn) ^ l[i+mm-1];

	}
	

	//------------------------- encryption ----------------------------
	        u64 x=PL;u64 y=PR;
	for (int i = 0; i <= T-1; i++){
		x = ((ROTL2((nn-a),x,nn) + y) & (0xffffffffffffffff >> (64-nn) )) ^ k[i];
		y = ROTL2(b,y,nn) ^ x;
		//printf("L:%08X\nk:%08x\n",x,y);
	}
	CL=x;CR=y;
}
