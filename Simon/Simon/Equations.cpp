
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
	n=sprintf (buffer, "Equation_%dR_fixk%d.txt", rounds, fk);

	if (index == 0){
		mf.open (buffer);
	}else{
		mf.open(buffer, ios::out | ios::app);
	}
	// Can output to anohter file to seperate the keys and equations.
	// only the first P/C pair need to have the guessed key bits, the value of P/C pair
	if (index == 0){
		stdext::hash_set<u32> AlreadySeen;
		while (AlreadySeen.size() != fk){
			int index = rand() % (nn*4) ;  
			AlreadySeen.insert(index);
		}

		stdext::hash_set<u32>::iterator it;
		for(it=AlreadySeen.begin();it!=AlreadySeen.end();it++){
			mf << "k_";
			mf << fill0(*it); mf << "="; 
			int tmp = 0;
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

	// Write Plaintext_i = zl/r_000_i
	for (int i = 0; i < nn; i++){
		mf << PLt << index << "_";
		mf << fill0(i);
		mf << "="<< ZLt << index << "_000_";
		mf << fill0(i); 
		mf << "\n";
	}
	for (int i = 0; i < nn; i++){
		mf << PRt << index << "_";
		mf << fill0(i);
		mf << "=" << ZRt << index << "_000_";
		mf << fill0(i); 
		mf << "\n";
	}
	// Write CipherText_i = zl/r_rounds_i
	for (int i = 0; i < nn; i++){
		mf << CLt << index << "_";
		mf << fill0(i) << "="<< ZLt << index << "_";
		mf << fill0(rounds) << "_";
		mf << fill0(i) << "\n";
	}

	for (int i = 0; i < nn; i++){
		mf << CRt << index << "_";
		mf << fill0(i);
		mf << "=" << ZRt << index << "_";
		mf << fill0(rounds);
		mf << "_";
		mf << fill0(i); 
		mf << "\n";
	}
	// write key match to ek
	for (int i = 0; i < keysize; i++){
		mf << "k_";
		mf << fill0(i);
		mf <<"="<<ekt << index <<"_";

		if ( i < 32){
			mf << "000_";
		}else if (i < 64){
			mf << "001_";
		}else if (i < 96){
			mf << "002_";
		}else{
			mf << "003_";
		}
		mf << fill0( i % 32 );

		mf << "\n";

	}


	// write PL value
	for (int i = 0; i < nn; i++){
		mf << PLt << index << "_"; 
		mf << fill0(i);
		mf << "=";
		int tmp = (PL>>i)&1;
		mf << tmp;
		mf << "\n";
	}

	// write PR value
	for (int i = 0; i < nn; i++){
		mf << PRt << index << "_"; 
		mf << fill0(i);
		mf << "=";
		int tmp = (PR>>i)&1;
		mf << tmp;
		mf << "\n";
	}
	// write CL value
	for (int i = 0; i < nn; i++){
		mf << CLt << index << "_"; 
		mf << fill0(i);
		mf << "=";
		int tmp = (CL>>i)&1;
		mf << tmp;
		mf << "\n";
	}
	// write CR value
	for (int i = 0; i < nn; i++){
		mf << CRt << index << "_";
		mf << fill0(i);
		mf << "=";
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
					k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1+1+ (1 or 0 depends on the constant)
					and when k == 1
					k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1;

					and when kk > 1

					k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1+1;
					*/
					mf << "                ";
					mf << ekt << index << "_";
					mf << fill0(i);
					mf << "_";
					mf << fill0(kk);
					mf << "="<< ekt << index << "_";
					mf << fill0(i-4);
					mf << "_";
					mf << fill0(kk);
					mf << "+"<< ekt << index << "_";
					mf << fill0(i-3);
					mf <<  "_";
					mf << fill0(kk);
					mf << "+"<< ekt << index << "_";
					mf << fill0(i-1);
					mf <<  "_";
					mf << fill0(b1);
					mf << "+"<< ekt << index << "_";					
					mf << fill0(i-3);

					mf <<  "_";					
					mf << fill0(a1);

					mf << "+"<< ekt << index << "_";					
					mf << fill0(i-1);
					mf << "_";					
					mf << fill0(c1);
					mf << "";


					if( kk==0) {


						if (Simonc[3][i-4] != '0'){
							mf << "+";
							mf << Simonc[3][i-4];
						}
					}
					else if(kk==1) {

					}
					else {
						//   k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1+1;
						mf << "+ 1";
					}
					mf <<"\n";
				}


				mf << ZLt << index << "_";
				mf << fill0(i);
				mf << "_";
				mf << fill0(kk);
				mf << "="<< ekt << index << "_";
				mf << fill0(i-1); 
				mf  << "_";
				mf << fill0(kk);
				mf << "+"<< ZLt << index << "_";
				mf << fill0(i-1);
				mf << "_";
				mf << fill0(b);
				mf << "+"<< ZRt << index << "_";
				mf << fill0(i-1);
				mf << "_";
				mf << fill0(kk);
				mf << "+   "<< ZLt << index << "_";
				mf << fill0(i-1);
				mf << "_";
				mf << fill0(a);
				mf << "*"<< ZLt << index << "_";
				mf << fill0(i-1);
				mf << "_";
				mf << fill0(c);
				mf << "\n";

				mf << ZRt << index << "_";
				mf << fill0(i);
				mf   <<  "_";
				mf << fill0(kk);
				mf   <<  "=" << ZLt << index << "_";
				mf << fill0(i-1);
				mf<< "_";
				mf << fill0(kk);
				mf << "\n";
			}
		}
	}


	mf.close();
}       

//relax nothing, P, C, P&C  - 0, 1, 2, 3
void generateEquation(u32 PL,u32 PR,u32 CL, u32 CR, u32* key,int nn,int keysize,int rounds, int fk, int index, int version)
{

	//-------------------------- equations ----------------------------
	int kk;
	int a,b,c;


	ofstream mf;
	char buffer [300];
	int n;
	n=sprintf (buffer, "Equation_%dR_fixk%d.txt", rounds, fk);

	if (index == 0){
		mf.open (buffer);
	}else{
		mf.open(buffer, ios::out | ios::app);
	}
	// Can output to anohter file to seperate the keys and equations.
	// only the first P/C pair need to have the guessed key bits, the value of P/C pair
	if (index == 0){
		stdext::hash_set<u32> AlreadySeen;
		while (AlreadySeen.size() != fk){
			int index = rand() % (nn*4) ;  
			AlreadySeen.insert(index);
		}

		stdext::hash_set<u32>::iterator it;
		for(it=AlreadySeen.begin();it!=AlreadySeen.end();it++){
			mf << "k_";
			mf << fill0(*it); mf << "="; 
			int tmp = 0;
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

	// Write Plaintext_i = zl/r_000_i
	for (int i = 0; i < nn; i++){
		mf << PLt << index << "_";
		mf << fill0(i);
		mf << "="<< ZLt << index << "_000_";
		mf << fill0(i); 
		mf << "\n";
	}
	for (int i = 0; i < nn; i++){
		mf << PRt << index << "_";
		mf << fill0(i);
		mf << "=" << ZRt << index << "_000_";
		mf << fill0(i); 
		mf << "\n";
	}
	// Write CipherText_i = zl/r_rounds_i
	for (int i = 0; i < nn; i++){
		mf << CLt << index << "_";
		mf << fill0(i) << "="<< ZLt << index << "_";
		mf << fill0(rounds) << "_";
		mf << fill0(i) << "\n";
	}

	for (int i = 0; i < nn; i++){
		mf << CRt << index << "_";
		mf << fill0(i);
		mf << "=" << ZRt << index << "_";
		mf << fill0(rounds);
		mf << "_";
		mf << fill0(i); 
		mf << "\n";
	}
	// write key match to ek
	for (int i = 0; i < keysize; i++){
		mf << "k_";
		mf << fill0(i);
		mf <<"="<<ekt << index <<"_";

		if ( i < 32){
			mf << "000_";
		}else if (i < 64){
			mf << "001_";
		}else if (i < 96){
			mf << "002_";
		}else{
			mf << "003_";
		}
		mf << fill0( i % 32 );

		mf << "\n";

	}

	if (version == 0 || version == 2){
		// write PL value
		for (int i = 0; i < nn; i++){
			mf << PLt << index << "_"; 
			mf << fill0(i);
			mf << "=";
			int tmp = (PL>>i)&1;
			mf << tmp;
			mf << "\n";
		}
	

		// write PR value
		for (int i = 0; i < nn; i++){
			mf << PRt << index << "_"; 
			mf << fill0(i);
			mf << "=";
			int tmp = (PR>>i)&1;
			mf << tmp;
			mf << "\n";
		}
	}

	if (version == 0 || version == 1){
		// write CL value
		for (int i = 0; i < nn; i++){
			mf << CLt << index << "_"; 
			mf << fill0(i);
			mf << "=";
			int tmp = (CL>>i)&1;
			mf << tmp;
			mf << "\n";
		}
	
		// write CR value
		for (int i = 0; i < nn; i++){
			mf << CRt << index << "_";
			mf << fill0(i);
			mf << "=";
			int tmp = (CR>>i)&1;
			mf << tmp;
			mf << "\n";
		}
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
					k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1+1+ (1 or 0 depends on the constant)
					and when k == 1
					k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1;

					and when kk > 1

					k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1+1;
					*/
					mf << "                ";
					mf << ekt << index << "_";
					mf << fill0(i);
					mf << "_";
					mf << fill0(kk);
					mf << "="<< ekt << index << "_";
					mf << fill0(i-4);
					mf << "_";
					mf << fill0(kk);
					mf << "+"<< ekt << index << "_";
					mf << fill0(i-3);
					mf <<  "_";
					mf << fill0(kk);
					mf << "+"<< ekt << index << "_";
					mf << fill0(i-1);
					mf <<  "_";
					mf << fill0(b1);
					mf << "+"<< ekt << index << "_";					
					mf << fill0(i-3);

					mf <<  "_";					
					mf << fill0(a1);

					mf << "+"<< ekt << index << "_";					
					mf << fill0(i-1);
					mf << "_";					
					mf << fill0(c1);
					mf << "";


					if( kk==0) {


						if (Simonc[3][i-4] != '0'){
							mf << "+";
							mf << Simonc[3][i-4];
						}
					}
					else if(kk==1) {

					}
					else {
						//   k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1+1;
						mf << "+ 1";
					}
					mf <<"\n";
				}


				mf << ZLt << index << "_";
				mf << fill0(i);
				mf << "_";
				mf << fill0(kk);
				mf << "="<< ekt << index << "_";
				mf << fill0(i-1); 
				mf  << "_";
				mf << fill0(kk);
				mf << "+"<< ZLt << index << "_";
				mf << fill0(i-1);
				mf << "_";
				mf << fill0(b);
				mf << "+"<< ZRt << index << "_";
				mf << fill0(i-1);
				mf << "_";
				mf << fill0(kk);
				mf << "+   "<< ZLt << index << "_";
				mf << fill0(i-1);
				mf << "_";
				mf << fill0(a);
				mf << "*"<< ZLt << index << "_";
				mf << fill0(i-1);
				mf << "_";
				mf << fill0(c);
				mf << "\n";

				mf << ZRt << index << "_";
				mf << fill0(i);
				mf   <<  "_";
				mf << fill0(kk);
				mf   <<  "=" << ZLt << index << "_";
				mf << fill0(i-1);
				mf<< "_";
				mf << fill0(kk);
				mf << "\n";
			}
		}
	}


	mf.close();
}       

void generateEquationALL(u64 PL, u64 PR, u64 CL, u64 CR, u64* key, int nn, int keysize, int rounds, int fk, int index, int relax)
{

	//-------------------------- equations ----------------------------
	int kk;
	int a, b, c;


	int j = getJ(nn * 2, keysize); // added to allow for all versions of SIMON (Used for Z constants)
	int m = getM(nn * 2, keysize); // multiplier
	int keyWidth = keysize / m; // Helps Determines how many bytes each k[] stores


	ofstream mf;
	char buffer[300];
	int n;
	n = sprintf(buffer, "Equation_%dR_fixk%d_block%d_key%d.txt", rounds, fk, (nn*2), keysize);

	/*printf("\nKey[0]: %8x", key[0]); printKey(key[0]);
	printf("Key[1]: %8x", key[1]); printKey(key[1]);
	printf("Key[2]: %8x", key[2]); printKey(key[2]);
	printf("Key[3]: %8x", key[3]); printKey(key[3]); printf("\n");*/

	// Open file to write to
	if (index == 0){
		mf.open(buffer);
	}
	else{
		mf.open(buffer, ios::out | ios::app);
	}


	// Will choose the guessed key bits from the given key
	// Can output to anohter file to seperate the keys and equations.
	// only the first P/C pair need to have the guessed key bits, the value of P/C pair
	if (index == 0){
		stdext::hash_set<u32> AlreadySeen;
		while (AlreadySeen.size() != fk){
			int index = rand() % (keysize);
			AlreadySeen.insert(index);
		}

		stdext::hash_set<u32>::iterator it;
		for (it = AlreadySeen.begin(); it != AlreadySeen.end(); it++){
			mf << "k_";
			mf << fill0(*it); mf << "=";
			int tmp = 0;
			if (*it < keyWidth){
				int tmp = (key[0] >> *it % keyWidth) & 1;
				mf << tmp;
			}
			else if (*it < (keyWidth * 2)){
				int tmp = (key[1] >> *it % keyWidth) & 1;
				mf << tmp;
			}
			else if (*it < (keyWidth * 3)){
				int tmp = (key[2] >> *it % keyWidth) & 1;
				mf << tmp;
			}
			else{
				int tmp = (key[3] >> *it % keyWidth) & 1;
				mf << tmp;
			}
			mf << "\n";

		}
	}

	// Write Plaintext_i = zl/r_000_i
	// Plaintext Left
	for (int i = 0; i < nn; i++){
		mf << PLt << index << "_";
		mf << fill0(i);
		mf << "=" << ZLt << index << "_000_";
		mf << fill0(i);
		mf << "\n";
	}
	// Plaintext Right
	for (int i = 0; i < nn; i++){
		mf << PRt << index << "_";
		mf << fill0(i);
		mf << "=" << ZRt << index << "_000_";
		mf << fill0(i);
		mf << "\n";
	}



	// Write CipherText_i = zl/r_rounds_i
	// Ciphertext Left
	for (int i = 0; i < nn; i++){
		mf << CLt << index << "_";
		mf << fill0(i) << "=" << ZLt << index << "_";
		mf << fill0(rounds) << "_";
		mf << fill0(i) << "\n";
	}

	// Ciphertext Right
	for (int i = 0; i < nn; i++){
		mf << CRt << index << "_";
		mf << fill0(i);
		mf << "=" << ZRt << index << "_";
		mf << fill0(rounds);
		mf << "_";
		mf << fill0(i);
		mf << "\n";
	}


	// write key match to ek
	for (int i = 0; i < keysize; i++){
		mf << "k_";
		mf << fill0(i);
		mf << "=" << ekt << index << "_";

		if (i < (keyWidth)){
			mf << "000_";
		}
		else if (i < (keyWidth * 2)){
			mf << "001_";
		}
		else if (i < (keyWidth * 3)){
			mf << "002_";
		}
		else{
			mf << "003_";
		}
		mf << fill0(i % keyWidth);
		mf << "\n";
	}

	// Write Plaintext values only if not relaxed
	if (relax != 1 || relax != 3)
	{
		// write PL value
		for (int i = 0; i < nn; i++){
			mf << PLt << index << "_";
			mf << fill0(i);
			mf << "=";
			int tmp = (PL >> i) & 1;
			mf << tmp;
			mf << "\n";
		}

		// write PR value
		for (int i = 0; i < nn; i++){
			mf << PRt << index << "_";
			mf << fill0(i);
			mf << "=";
			int tmp = (PR >> i) & 1;
			mf << tmp;
			mf << "\n";
		}
	}


	// Write Ciphertext values only if not relaxed
	if (relax != 2 || relax != 3)
	{
		// write CL value
		for (int i = 0; i < nn; i++){
			mf << CLt << index << "_";
			mf << fill0(i);
			mf << "=";
			int tmp = (CL >> i) & 1;
			mf << tmp;
			mf << "\n";
		}

		// write CR value
		for (int i = 0; i < nn; i++){
			mf << CRt << index << "_";
			mf << fill0(i);
			mf << "=";
			int tmp = (CR >> i) & 1;
			mf << tmp;
			mf << "\n";
		}
	}

	for (int i = 0; i <= rounds; i++)
	{

		if (i>0){
			for (kk = 0; kk <= (keyWidth - 1); kk++){   // for each round key (size - 1)
				a = (kk - 1) % keyWidth;
				b = (kk - 2) % keyWidth;
				c = (kk - 8) % keyWidth;
				if (a >= 0) {
					a = (kk - 1) % keyWidth;
				}
				else {
					a = keyWidth + (kk - 1) % keyWidth;
				}
				if (b >= 0){
					b = (kk - 2) % keyWidth;
				}
				else {
					b = keyWidth + (kk - 2) % keyWidth;
				}
				if (c >= 0){
					c = (kk - 8) % keyWidth;
				}
				else {
					c = keyWidth + (kk - 8) % keyWidth;
				}


				// write the key now 

				int a1, b1, c1;
				a1 = (kk + 1) % keyWidth;
				b1 = (kk + 3) % keyWidth;
				c1 = (kk + 4) % keyWidth;
				if (a1 >= 0) {
					a1 = (kk + 1) % keyWidth;
				}
				else {
					a1 = keyWidth + (kk + 1) % keyWidth;
				}
				if (b1 >= 0){
					b1 = (kk + 3) % keyWidth;
				}
				else {
					b1 = keyWidth + (kk + 3) % keyWidth;
				}
				if (c1 >= 0){
					c1 = (kk + 4) % keyWidth;
				}
				else {
					c1 = keyWidth + (kk + 4) % keyWidth;
				}


				if (i > 1 && m == 2){

					// Equations:
					// k_[i]_kk = k_[i-2]_kk + k_[i-1]_b1 + k_[i-1]_c1 + z[j][(i-m) mod 62] + 3

					mf << "                ";
					mf << ekt << index << "_";
					mf << fill0(i);
					mf << "_";
					mf << fill0(kk);
					mf << "=" << ekt << index << "_";
					mf << fill0(i - 2);
					mf << "_";
					mf << fill0(kk);
					mf << "+" << ekt << index << "_";
					mf << fill0(i - 1);
					mf << "_";
					mf << fill0(b1);
					mf << "+" << ekt << index << "_";
					mf << fill0(i - 1);
					mf << "_";
					mf << fill0(c1);
					mf << "";


					if (kk == 0) {
						int j = getJ(nn * 2, keysize); // added to allow for all versions of SIMON
						int m = getM(nn * 2, keysize);

						if (Simonc[j][i - m] != '0'){
							mf << "+";
							mf << Simonc[j][i - m];
						}
					}
					else if (kk == 1) {
						// Keep Equation normal
					}
					else {
						mf << "+ 1";
					}
					mf << "\n";
				}

				if (i > 2 && m == 3){

					// Equation:
					//k_[i]_kk = k_[i-3]_kk  +  k_[i-1]_b1  +  k_[i-1]_c1  +  z[j][(i-m) mod 62]  +  3

					mf << "                ";
					mf << ekt << index << "_";
					mf << fill0(i);
					mf << "_";
					mf << fill0(kk);
					mf << "=" << ekt << index << "_";
					mf << fill0(i - 3);
					mf << "_";
					mf << fill0(kk);
					mf << "+" << ekt << index << "_";
					mf << fill0(i - 1);
					mf << "_";
					mf << fill0(b1);
					mf << "+" << ekt << index << "_";
					mf << fill0(i - 1);
					mf << "_";
					mf << fill0(c1);
					mf << "";


					if (kk == 0) {
						if (Simonc[j][i - m] != '0'){
							mf << "+";
							mf << Simonc[j][i - m];
						}
					}
					else if (kk == 1) {
						// Keep Equation normal
					}
					else {
						mf << "+ 1";
					}
					mf << "\n";
				}


				if (i>3 && m==4){
					/*
					when kk = 0:
					k_i_kk= k_i-4_kk  +  k_i-3_kk  +  k_i-1_b1  +  k_i-3_a1  +  k_i-1_c1  +  1  + (1 or 0 depends on the constant)
					and when k == 1
					k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1;

					and when kk > 1

					k_i_kk=k_i-4_kk+k_i-3_kk+k_i-1_b1+k_i-3_a1+k_i-1_c1+1;
					*/
					mf << "                ";
					mf << ekt << index << "_";
					mf << fill0(i);
					mf << "_";
					mf << fill0(kk);
					mf << "=" << ekt << index << "_";
					mf << fill0(i - 4);
					mf << "_";
					mf << fill0(kk);
					mf << "+" << ekt << index << "_";
					mf << fill0(i - 3);
					mf << "_";
					mf << fill0(kk);
					mf << "+" << ekt << index << "_";
					mf << fill0(i - 1);
					mf << "_";
					mf << fill0(b1);
					mf << "+" << ekt << index << "_";
					mf << fill0(i - 3);

					mf << "_";
					mf << fill0(a1);

					mf << "+" << ekt << index << "_";
					mf << fill0(i - 1);
					mf << "_";
					mf << fill0(c1);
					mf << "";


					if (kk == 0) {
						if (Simonc[j][i - m] != '0'){
							mf << "+";
							mf << Simonc[j][i - m];
						}
					}
					else if (kk == 1) {
						// Keep Equation normal
					}
					else {
						mf << "+ 1";
					}
					mf << "\n";
				}


				mf << ZLt << index << "_";
				mf << fill0(i);
				mf << "_";
				mf << fill0(kk);
				mf << "=" << ekt << index << "_";
				mf << fill0(i - 1);
				mf << "_";
				mf << fill0(kk);
				mf << "+" << ZLt << index << "_";
				mf << fill0(i - 1);
				mf << "_";
				mf << fill0(b);
				mf << "+" << ZRt << index << "_";
				mf << fill0(i - 1);
				mf << "_";
				mf << fill0(kk);
				mf << "+   " << ZLt << index << "_";
				mf << fill0(i - 1);
				mf << "_";
				mf << fill0(a);
				mf << "*" << ZLt << index << "_";
				mf << fill0(i - 1);
				mf << "_";
				mf << fill0(c);
				mf << "\n";

				mf << ZRt << index << "_";
				mf << fill0(i);
				mf << "_";
				mf << fill0(kk);
				mf << "=" << ZLt << index << "_";
				mf << fill0(i - 1);
				mf << "_";
				mf << fill0(kk);
				mf << "\n";
			}
		}
	}


	mf.close();
}


int getJ(int blockVersion, int keySize)
{
	switch (blockVersion)
	{
	case 32:
		return 0;

	case 48:
		if (keySize == 72) return 0;
		if (keySize == 96) return 1;

	case 64:
		if (keySize == 96) return 2;
		if (keySize == 128) return 3;

	case 96:
		if (keySize == 96) return 2;
		if (keySize == 144) return 3;

	case 128:
		if (keySize == 128) return 2;
		if (keySize == 192) return 3;
		if (keySize == 256) return 4;
	}

	return 0;
}

int getM(int blockVersion, int keySize)
{
	switch (blockVersion)
	{
	case 32:
		return 4;

	case 48:
		if (keySize == 72) return 3;
		if (keySize == 96) return 4;

	case 64:
		if (keySize == 96) return 3;
		if (keySize == 128) return 4;

	case 96:
		if (keySize == 96) return 2;
		if (keySize == 144) return 3;

	case 128:
		if (keySize == 128) return 2;
		if (keySize == 192) return 3;
		if (keySize == 256) return 4;
	}

	return 0;
}


void printKey(u64 key){
	printf("\t ", key);
	while (key) {
		if ((key & 1))
			printf("1");
		else
			printf("0");

		key >>= 1;
	}
	printf("\n");
}