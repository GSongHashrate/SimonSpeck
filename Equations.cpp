
/* 
Simon and Speck Block cipher implementation
Published by NSA in June 2013, https://eprint.iacr.org/2013/404.pdf

Author: Nicolas Courtois, Theodosis Mourouzis, Guangyan Song
Jan 2014
*/
//
// SIMON cipher equation generator
// NSA cipher with low MC proposed by NSA

#include "StdAfx.h"
#include "Equations.h"
#include "simonSpeckBasic.h"

using namespace std;
typedef stdext::hash_set<int> IntHSet;

char Simonc[5][65] =
{"11111010001001010110000111001101111101000100101011000011100110",
"10001110111110010011000010110101000111011111001001100001011010",
"10101111011100000011010010011000101000010001111110010110110011",
"11011011101011000110010111100000010010001010011100110100001111",
"11010001111001101011011000100000010111000011001010010011101111"};

string PLt = "PL";
string PRt = "PR";
string ekt = "ek";
string ZLt = "ZL";
string ZRt = "ZR";
string CLt = "CL";
string CRt = "CR";
string L = "tmpL";
string ck = "tmpCk";
string ce = "tmpCe";

string fill0(int i){
	std::stringstream ss;
	ss << std::setfill('0') << std::setw(3) << i; 
	return ss.str();
}

void generateEquation(u32 PL,u32 PR,u32 CL, u32 CR, u32* key,int nn,int keysize,int rounds, int fk, int index)
{

	//-------------------------- equations ----------------------------
	int kk;
	int a,b,c;


	ofstream mf;
	char buffer [300];
	int n;
	n=sprintf (buffer, "Equation_%dR_fk%d_%08X%08X%08X%08X.txt", rounds, fk, key[3],key[2],key[1],key[0]);

	if (index == 0){
		mf.open (buffer);
	}else{
		mf.open(buffer, ios::out | ios::app);
	}
	// only the first P/C pair need to have the guessed key bits, the value of P/C pair
	if (index == 0){
		stdext::hash_set<u32> AlreadySeen;
		while (AlreadySeen.size() != fk){
			int index = rand() % (nn*4) ;  
			AlreadySeen.insert(index);
		}

		stdext::hash_set<u32>::iterator it;
		for(it=AlreadySeen.begin();it!=AlreadySeen.end();it++){
			mf << "k[";
			mf << fill0(*it); mf << "]="; 
			int tmp ;
			if (*it < 32){
				int tmp = (key[0]>>*it%32)&1;
				mf << tmp;
			}else if (*it < 64){
				int tmp = (key[1]>>*it%32)&1;
				mf << tmp;
			}else if (*it < 96){
				int tmp = (key[2]>>*it%32)&1;
				mf << tmp;
			}else{
				int tmp = (key[3]>>*it%32)&1;
				mf << tmp;
			}
			mf <<"\n";

		}
	}

	// Write Plaintext[i] = zl/r[000][i]
	for (int i = 0; i < nn; i++){
		mf << PLt << index << "[";
		mf << fill0(i);
		mf << "]="<< ZLt << index << "[000][";
		mf << fill0(i); 
		mf << "]\n";
	}
	for (int i = 0; i < nn; i++){
		mf << PRt << index << "[";
		mf << fill0(i);
		mf << "]=" << ZRt << index << "[000][";
		mf << fill0(i); 
		mf << "]\n";
	}
	// Write CipherText[i] = zl/r[rounds][i]
	for (int i = 0; i < nn; i++){
		mf << CLt << index << "[";
		mf << fill0(i) << "]="<< ZLt << index << "[";
		mf << fill0(rounds) << "][";
		mf << fill0(i) << "]\n";
	}

	for (int i = 0; i < nn; i++){
		mf << CRt << index << "[";
		mf << fill0(i);
		mf << "]=" << ZRt << index << "[";
		mf << fill0(rounds);
		mf << "][";
		mf << fill0(i); 
		mf << "]\n";
	}
    // write key match to ek
	for (int i = 0; i < keysize; i++){
		mf << "k[";
		mf << fill0(i);
		mf <<"]="<<ekt << index <<"[";

		if ( i < 32){
			mf << "000][";
		}else if (i < 64){
			mf << "001][";
		}else if (i < 96){
			mf << "002][";
		}else{
			mf << "003][";
		}
		mf << fill0( i % 32 );

		mf << "]\n";

	}


	// write PL value
	for (int i = 0; i < nn; i++){
		mf << PLt << index << "["; 
		mf << fill0(i);
		mf << "]=";
		int tmp = (PL>>i)&1;
		mf << tmp;
		mf << "\n";
	}

	// write PR value
	for (int i = 0; i < nn; i++){
		mf << PRt << index << "["; 
		mf << fill0(i);
		mf << "]=";
		int tmp = (PR>>i)&1;
		mf << tmp;
		mf << "\n";
	}
	// write CL value
	for (int i = 0; i < nn; i++){
		mf << CLt << index << "["; 
		mf << fill0(i);
		mf << "]=";
		int tmp = (CL>>i)&1;
		mf << tmp;
		mf << "\n";
	}
	// write CR value
	for (int i = 0; i < nn; i++){
		mf << CRt << index << "[";
		mf << fill0(i);
		mf << "]=";
		int tmp = (CR>>i)&1;
		mf << tmp;
		mf << "\n";
	}

	for(int i = 0; i<= rounds; i++)
	{

		if(i>0){
			for(kk=0;kk<=31;kk++){
				a=(kk-1)%32;
				b=(kk-2)%32;
				c=(kk-8)%32;
				if(a>=0) {
					a=(kk-1)%32;;
				}
				else {
					a=32+(kk-1)%32;
				}
				if(b>=0){
					b=(kk-2)%32;
				}
				else {
					b=32+(kk-2)%32;
				}
				if(c>=0){
					c=(kk-8)%32;
				}
				else {
					c=32+(kk-8)%32;
				}


				// write the key now 

				int a1,b1,c1;
				a1=(kk+1)%32;
				b1=(kk+3)%32;
				c1=(kk+4)%32;
				if(a1>=0) {
					a1=(kk+1)%32;
				}
				else {
					a1=32+(kk+1)%32;
				}
				if(b1>=0){
					b1=(kk+3)%32;
				}
				else {
					b1=32+(kk+3)%32;
				}	
				if(c1>=0){
					c1=(kk+4)%32;
				}
				else {
					c1=32+(kk+4)%32;
				}



				if(i>3){
					/*
					when kk = 0:
					k[i][kk]=k[i-4][kk]+k[i-3][kk]+k[i-1][b1]+k[i-3][a1]+k[i-1][c1]+1+ (1 or 0 depends on the constant)
					and when k == 1
					k[i][kk]=k[i-4][kk]+k[i-3][kk]+k[i-1][b1]+k[i-3][a1]+k[i-1][c1];

					and when kk > 1

					k[i][kk]=k[i-4][kk]+k[i-3][kk]+k[i-1][b1]+k[i-3][a1]+k[i-1][c1]+1;
					*/

					mf << ekt << index << "[";
					mf << fill0(i);
					mf << "][";
					mf << fill0(kk);
					mf << "]="<< ekt << index << "[";
					mf << fill0(i-4);
					mf << "][";
					mf << fill0(kk);
					mf << "]+"<< ekt << index << "[";
					mf << fill0(i-3);
					mf <<  "][";
					mf << fill0(kk);
					mf << "]+"<< ekt << index << "[";
					mf << fill0(i-1);
					mf <<  "][";
					mf << fill0(b1);
					mf << "]+"<< ekt << index << "[";					
					mf << fill0(i-3);

					mf <<  "][";					
					mf << fill0(a1);

					mf << "]+"<< ekt << index << "[";					
					mf << fill0(i-1);
					mf << "][";					
					mf << fill0(c1);
					mf << "]";


					if( kk==0) {


						if (Simonc[3][i-4] != '0'){
							mf << "+";
							mf << Simonc[3][i-4];
						}
					}
					else if(kk==1) {

					}
					else {
						//   k[i][kk]=k[i-4][kk]+k[i-3][kk]+k[i-1][b1]+k[i-3][a1]+k[i-1][c1]+1;
						mf << "+ 1";
					}
					mf <<"\n";
				}


				mf << ZLt << index << "[";
				mf << fill0(i);
				mf << "][";
				mf << fill0(kk);
				mf << "]="<< ekt << index << "[";
				mf << fill0(i-1); 
				mf  << "][";
				mf << fill0(kk);
				mf << "]+"<< ZLt << index << "[";
				mf << fill0(i-1);
				mf << "][";
				mf << fill0(b);
				mf << "]+"<< ZRt << index << "[";
				mf << fill0(i-1);
				mf << "][";
				mf << fill0(kk);
				mf << "]+"<< ZLt << index << "[";
				mf << fill0(i-1);
				mf << "][";
				mf << fill0(a);
				mf << "]*"<< ZLt << index << "[";
				mf << fill0(i-1);
				mf << "][";
				mf << fill0(c);
				mf << "]\n";

				mf << ZRt << index << "[";
				mf << fill0(i);
				mf   <<  "][";
				mf << fill0(kk);
				mf   <<  "]=" << ZLt << index << "[";
				mf << fill0(i-1);
				mf<< "][";
				mf << fill0(kk);
				mf << "]\n";
			}
		}
	}


	mf.close();
}       
