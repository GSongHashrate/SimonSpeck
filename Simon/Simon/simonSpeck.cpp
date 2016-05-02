
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
#include "CheckEquations.h"

void main(int argc, char * argv[])
{	
	// Modified to add the following options:
	// BlockSizeM - Specify block size
	// KeySizeN - Specify KeySize, Must be used in conjunction with BlockSIzeM
	// verZ - Run specific Simon version
	// relaxP - Don't output plaintext values in the equation generator
	// relaxC - Don't output ciphertext values in the equation generator
	// help - Display Usage and Examples
	//
	// Also added in some input checks and default options to run Simon64/128 for backwards compatibility
	// verZ provides no flexibility on the number of rounds but this can be achieved by using a 
	// combination of /blocksizeM and /keysizeN
	double D = 0;
	int Par1 = 0;

	// If user has asked for help, print the usage and exit
	for (int i = 1; i < argc; i++) if (strstr(argv[i], "/help"))
	{
		printUsage(0);
		exit(0);
	}

	int checkElimlinEq = 0;
	for (int i = 1; i<argc; i++) if (strstr(argv[i], "/checkElim"))
		checkElimlinEq = 1;

	int maxtermused = 0; u32 maxtermPL = 0x00000000; u32 maxtermPR = 0x00000022;

	for (int i = 1; i<argc; i++){ 
		if (strstr(argv[i], "/maxterm")){ 
			// maxterm 0000000000000000
			maxtermused = 1;
			D = BitCount(maxtermPR);
			printf("%d\n",D);
		}
	}

	int blockSize = -1;
	for (int i = 1; i<argc; i++) if (strstr(argv[i], "/blocksize"))
		blockSize = atoi(argv[i] + 10);
	int keySize = -1;
	for (int i = 1; i<argc; i++) if (strstr(argv[i], "/keysize"))
		keySize = atoi(argv[i] + 8);
	int verZ = -1;
	for (int i = 1; i<argc; i++) if (strstr(argv[i], "/ver"))
		verZ = atoi(argv[i] + 4);
	int FixKeyVars=0;
	for(int i=1;i<argc;i++) if(strstr(argv[i],"/fixk"))
		FixKeyVars=atoi(argv[i]+5);
	int insX=0;
	for(int i=1;i<argc;i++) if(strstr(argv[i],"/ins"))
		insX=atoi(argv[i]+4);
	int cp=0;
	for(int i=1;i<argc;i++) if(strstr(argv[i],"/cp"))
		cp = 1;
	int sat=0;
	for(int i=1;i<argc;i++) if(strstr(argv[i],"/sat"))
		sat = 1;
	int xl0=0;
	for(int i=1;i<argc;i++) if(strstr(argv[i],"/xl0"))
		xl0 = 1;
	int relaxP = 0;
	for (int i = 1; i<argc; i++) if (strstr(argv[i], "/relaxP"))
		relaxP = 1;
	int relaxC = 0;
	for (int i = 1; i<argc; i++) if (strstr(argv[i], "/relaxC"))
		relaxC = 1;

	if (verZ == -1){
		if (argc>1) Par1 = atoi(argv[1]);
	}

	int keyWidth; // Used to generate equations later

	// Work out which version of Simon is being used
	// if blocksize, keysize or ver have not been specified, stick with Simon64/128
	// else, work out the max key bits will just be the keysize

	int blockVer;
	int keyVer;

	if (blockSize == -1 && keySize == -1 && verZ == -1){
		blockVer = 64;
		keyVer = 128;
	}
	else{

		if (blockSize != -1 && keySize != -1 && verZ == -1)
		{
			blockVer = blockSize;
			keyVer = keySize;
		}
		else{
			blockVer = getBlockVer(verZ);
			keyVer = getKeyVer(verZ);
		}

	}


	// Error checking on command usage -- Quits if it finds an invalid command
	// ---- Error Messages ----
	// 0 - No Error, just user requesting help page
	// 1 - Can't run blocksize/keysize on their own without each other
	// 2 - Can't run blocksize or keysize with verZ
	// 3 - verZ must be 1-10 OR Blocksize/Keysize must be valid Simon values
	// 4 - Cannot fix more key bits than exist
	// 5 - Cannot specify Number of rounds when using verZ

	if (blockSize*keySize < 0){  // 1
		printUsage(1);
		exit(0);
	}
	else if ((blockSize != -1 || keySize != -1) && verZ != -1){ // 2
		printf("\nBlockSize: %d, KeySize: %d, VerZ: %d\n", blockSize, keySize, verZ);
		printUsage(2);
		exit(0);
	}
	else if ((verZ != -1 && verZ <= 0 && verZ > 10) || (verZ == -1 && !isValidSize(blockVer, keyVer))){ // 3
		printUsage(3);
		exit(0);
	}
	else if (FixKeyVars > keyVer){ // 4
		printf("\nKey Size: %d, Fixed Key Bits: %d\n", keyVer, FixKeyVars);
		printUsage(4);
		exit(0);
	}
	else if ((verZ != -1 && Par1 != 0)){ // 5
		printf("\nVerZ: %d, Nr: %d\n", verZ, Par1);
		printUsage(5);
		exit(0);
	}


	//Set number of fixed known key bits
	int fk = FixKeyVars;

	// Set Number of rounds
	int round;

	// Set to 0: Dont relax P or C
	// Set to 1: Relax P
	// Set to 2: Relax C
	// Set to 3: Relax P&C
	int relaxValues = 0;

	if (relaxP == 1 && relaxC == 0) relaxValues = 1;
	else if (relaxP == 0 && relaxC == 1) relaxValues = 2;
	else if (relaxP == 1 && relaxC == 1) relaxValues = 3;

	if (Par1 != -1) round = Par1;
	if (verZ != -1) round = getRounds(blockVer, keyVer);

	//----------------------------------------------------------------------

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

	SimonDecryptBlock64128(CL,CR,PL,PR,key,32,128,44);
	printf("%08X %08X\n",PL,PR);



	// Case to determine test vectors and key sizes. Set's the test values which are going to be used
	// for the Equation Generator.
	// Plaintext, Ciphertext and Key declarations for up to 64 bits
	u64 PL64, PR64, CL64, CR64;
	u64 k[4] = { 0 };

	if (blockVer == 32 && keyVer == 64)
	{
		k[3] = 0x1918; k[2] = 0x1110; k[1] = 0x0908; k[0] = 0x0100;
		PL64 = 0x6565;  PR64 = 0x6877;
	}

	else if (blockVer == 48 && keyVer == 72)
	{
		k[2] = 0x121110; k[1] = 0x0a0908; k[0] = 0x020100;
		PL64 = 0x612067;  PR64 = 0x6e696c;
	}

	else if (blockVer == 48 && keyVer == 96)
	{
		k[3] = 0x1a1918; k[2] = 0x121110; k[1] = 0x0a0908; k[0] = 0x020100;
		PL64 = 0x726963;  PR64 = 0x20646e;
	}

	else if (blockVer == 64 && keyVer == 96)
	{
		k[2] = 0x13121110; k[1] = 0x0b0a0908; k[0] = 0x03020100;
		PL64 = 0x6f722067;  PR64 = 0x6e696c63;
	}

	else if (blockVer == 64 && keyVer == 128)
	{
		k[3] = 0x1b1a1918; k[2] = 0x13121110; k[1] = 0x0b0a0908; k[0] = 0x03020100;
		PL64 = 0x656b696c;  PR64 = 0x20646e75;
	}

	else if (blockVer == 96 && keyVer == 96)
	{
		k[1] = 0x0d0c0b0a0908; k[0] = 0x050403020100;
		PL64 = 0x2072616c6c69;  PR64 = 0x702065687420;
	}

	else if (blockVer == 96 && keyVer == 144)
	{
		k[2] = 0x151413121110; k[1] = 0x0d0c0b0a0908; k[0] = 0x050403020100;
		PL64 = 0x746168742074;  PR64 = 0x73756420666f;
	}

	else if (blockVer == 128 && keyVer == 128)
	{
		k[1] = 0x0f0e0d0c0b0a0908; k[0] = 0x0706050403020100;
		PL64 = 0x6373656420737265;  PR64 = 0x6c6c657661727420;
	}

	else if (blockVer == 128 && keyVer == 192)
	{
		k[2] = 0x1716151413121110; k[1] = 0x0f0e0d0c0b0a0908; k[0] = 0x0706050403020100;
		PL64 = 0x206572656874206e;  PR64 = 0x6568772065626972;
	}

	else if (blockVer == 128 && keyVer == 256)
	{
		k[3] = 0x1f1e1d1c1b1a1918; k[2] = 0x1716151413121110; k[1] = 0x0f0e0d0c0b0a0908; k[0] = 0x0706050403020100;
		PL64 = 0x74206e69206d6f6f;  PR64 = 0x6d69732061207369;
	}	

	printf("\nGenerating Simon %d/%d Equations For %d Rounds...\n\n", blockVer, keyVer, round);


	// ---- ENCRYPTION STAGE ----
	// Takes round as parameter so will actually output the ciphertext which is used
	// also as part of the equations.
	SimonEncryptBlockALL(PL64, PR64, CL64, CR64, k, (blockVer / 2), keyVer, round);

	// Format for blockvers <= 64 bits
	if (blockVer <= 64){
		printf(" Plaintext: ");  printf("%04X ", PL64);	printf("%04X\n", PR64);
		printf("Ciphertext: ");  printf("%04X ", CL64);	printf("%04X\n\n", CR64);
	}
	else{
		printf(" Plaintext: "); printf("%04X", (PL64 >> 32)); printf("%08X ", PL64); printf("%04X", (PR64 >> 32)); printf("%08X\n", PR64);
		printf("Ciphertext: "); printf("%04X", (CL64 >> 32)); printf("%08X ", CL64); printf("%04X", (CR64 >> 32)); printf("%08X\n\n", CR64);
	}

	// Generate equations for n Rounds Simon with fixk random fixed key bits, using insX P/C pairs 
	u32 *fixPL = new u32[insX*(int)pow(2,D)]; 
	u32 *fixPR = new u32[insX*(int)pow(2,D)];

	if (checkElimlinEq == 1){
		//------ fix insX * 2^D P --------------
		for (int i = 0 ; i < insX; i++){
			if (maxtermused == 0){
				if ( cp == 0 ){
					PL=CL;
					PR=CR;
				}else{
					PL=0x656b696c;  PR=0x20646e75;
					PL = PL ^ i;
				}
				fixPL[i] = PL;
				fixPR[i] = PR;
				SimonEncryptBlock64128(PL,PR,CL,CR,key,32,128,round);

				//generateEquation(PL,PR,CL,CR,key,32,128, round, fk ,i);
				generateEquation(PL,PR,CL,CR,key,32,128, round, fk ,i, relaxValues);
			}else{
				int count = 0;
				PL=randu32();
				PR=randu32();
				stdext::hash_set<u32> PLs, PRs ;
				PLs.insert(PL); PRs.insert(PR);
				double dPL = BitCount(maxtermPL);
				double dPR = BitCount(maxtermPR);
		
				while (PLs.size() != pow(2,dPL)){
					PLs.insert(PL^(randu32()&maxtermPL));
				}
				while (PRs.size() != pow(2,dPR)){
					PRs.insert(PR^(randu32()&maxtermPR));
				}
				printf("%d %d\n",PLs.size(),PRs.size());
				//stdext::hash_set<u32> PRs = getFromTerm(maxtermPR);
				
				stdext::hash_set<u32>::iterator itPL;
				stdext::hash_set<u32>::iterator itPR;
				for(itPL=PLs.begin();itPL!=PLs.end();itPL++){
					PL = *itPL;
					for (itPR=PRs.begin();itPR!=PRs.end();itPR++){
						PR = *itPR;
						printf("%d\n",i*(int)pow(2,(dPL*dPR))+count);
						fixPL[i*(int)pow(2,(dPL*dPR))+count] = PL;
						fixPR[i*(int)pow(2,(dPL*dPR))+count] = PR;
						SimonEncryptBlock64128(PL,PR,CL,CR,key,32,128,round);

						generateEquation(PL,PR,CL,CR,key,32,128, round, fk ,i*(int)pow(2,(dPL*dPR))+count, relaxValues);
						count++;
					}
				}
			}
		}
	}else{
		// Generate equations for n Rounds Simon with fixk random fixed key bits, using insX P/C pairs 

		for (int i = 0 ; i < insX; i++){

			// Generates CPA pairs if /cp flag has been set. Does it for 64 bit addresses
			if ( cp == 0){
				PL64 = CL64;
				PR64 = CR64;
			} else {
				PL64 = PL64 ^ i;
			}

			SimonEncryptBlockALL(PL64, PR64, CL64, CR64, k, (blockVer / 2), keyVer, round);
			generateEquationALL(PL64, PR64, CL64, CR64, k, (blockVer / 2), keyVer, round, fk, i, relaxValues);
		}
	}

	char Command[1024];
	if (sat == 1){
		sprintf(Command, "if exist ax64.exe ax64.exe 4444 Equation_%dR_fixk%d_block%d_key%d.txt /sat", round, fk, blockVer, keyVer);
		printf(Command);
		printf("\n");
		system(Command);
	} 

	if (xl0 == 1) {
		//sprintf(Command, "if exist ax64.exe ax64.exe 4000 Equation_%dR_fixk%d_block%d_key%d.txt", round, fk, blockVer, keyVer);
		sprintf(Command, "if exist ax64.exe ax64.exe 4000 Equation_%dR_fixk%d.txt", round, fk);
		printf(Command);
		printf("\n");
		system(Command);
		if (checkElimlinEq == 1){
			checkEqFile(round, fixPL, fixPR,insX*(int)pow(2,D));
		}
	}
	/*
	u32 *ZR1, *ZR2, ZR3;
	u32 *ZL1, *ZR2, ZR3;
	ZR1 = (u32 *) malloc(round*sizeof(u32));
	ZL1 = (u32 *) malloc(round*sizeof(u32));

	key[3]=0x1b1a1918;key[2]=0x13121110;key[1]=0x0b0a0908;key[0]=0x03020100;
	PL=0x3b726574;  PR=0x7475432d;
	SimonEncryptBlock64128(PL,PR,CL,CR,ZR1,ZL1,key,32,128,round);
	printf("%08X %08X\n",CL,CR);

	for (int i = 0; i < round; i ++){
	printf("Round %d: %08X %08X\n",i,ZL1[i],ZR1[i]);
	}*/

}



int getBlockVer(int version)
{
	if (version == 1) return 32;
	if (version == 2 || version == 3) return 48;
	if (version == 4 || version == 5) return 64;
	if (version == 6 || version == 7) return 96;

	return 128;
}

int getKeyVer(int version)
{
	if (version == 1) return 64;
	if (version == 2) return 72;
	if (version == 3 || version == 4 || version == 6) return 96;
	if (version == 5 || version == 8) return 128;
	if (version == 7) return 144;
	if (version == 9) return 192;

	return 256;
}

// Check if blocksize/keysize pair is valid SIMON version
bool isValidSize(int bSize, int kSize){

	switch (bSize)
	{
	case 32:
		if (kSize == 64) return true;

	case 48:
		if (kSize == 72 || kSize == 96) return true;

	case 64:
		if (kSize == 96 || kSize == 128) return true;

	case 96:
		if (kSize == 96 || kSize == 144) return true;

	case 128:
		if (kSize == 128 || kSize == 192 || kSize == 256) return true;
	}

	return false;
}

// When using verZ, fetches the number of rounds for each blocksize/keysize pair
// Will only get called if inputs have been checked, so defensive programming already done
int getRounds(int bSize, int kSize)
{
	switch (bSize)
	{
	case 32:
		return 32;

	case 48:
		return 36;

	case 64:
		if (kSize == 96) return 42;
		if (kSize == 128) return 44;

	case 96:
		if (kSize == 96) return 52;
		if (kSize == 144) return 54;

	case 128:
		if (kSize == 128) return 68;
		if (kSize == 192) return 69;
		if (kSize == 256) return 72;
	}

	// Shouldn't reach here if coded correctly, if it does, 0 rounds will be run.
	return 0;
}

void printUsage(int uCase)
{
	char errorMessage[110];

	// ---- Error Messages ----
	// 0 - No Error, just user requesting help page
	// 1 - Can't run blocksize/keysize on their own without each other
	// 2 - Can't run blocksize or keysize with verZ
	// 3 - verZ must be 1-10 OR Blocksize/Keysize must be valid Simon values
	// 4 - Cannot fix more key bits than exist
	// 5 - Cannot specify Number of rounds when using verZ

	switch (uCase)
	{
	case 0:
		strcpy(errorMessage, "\n\nHelp Pages:\n\n");
		break;

	case 1:
		strcpy(errorMessage, "\n\nError: Cannot run /blocksize without /keysize and vise versa.\n\n");
		break;

	case 2:
		strcpy(errorMessage, "\n\nError: Cannot run /blocksize and /keysize alongside /verZ.\n\n");
		break;

	case 3:
		strcpy(errorMessage, "\n\nError: /verZ must be between 1 and 10 inclusive OR choose a valid SIMON blocksize/keysize\n\n");
		break;

	case 4:
		strcpy(errorMessage, "\n\nError: Cannot fix more key bits than exist for chosen Simon version! (Default: 64/128)\n\n");
		break;

	case 5:
		strcpy(errorMessage, "\n\nError: Cannot specify verZ and the number of rounds. Use Nr with /blocksize and /keysize for flexibility.\n\n");
		break;
	}

	printf("%sUsage: Simon.exe Nr /insX [/cp] [/fixkY] [[/blocksizeN] [keysizeM] / [verZ]] [/x10] [/sat] [/help]\n \
		   - Nr - Number of Rounds\n \
		   - insX - Where X specifies the number of P/C pairs\n \
		   - cp - Counter mode where plaintexts differ very little. CPA.\n \
		   - fixkY - Fix Y bits out of full key size.\n \
		   - blocksizeN - Block size where N is the number of plaintext bits.\n \
		   - keysizeM - Key size where M is the number of key bits.\n \
		   - verZ - Where Z is the version number (see below).\n \
		   - relaxP - Don't output plaintext values in the equation generator.\n \
		   - relaxC - Don't output ciphertext values in the equation generator\n \
		   - xl0 - Will call ax64.exe 4000 at the end.\n \
		   - sat - Will call ax64.exe 4444 at the end.\n \
		   - help - Shows the help page.\n\n \
		   \
		   Table 1 (verZ)\n \
		   1 - Simon32/64 - 32 Rounds \n \
		   2 - Simon48/72 - 36 Rounds \n \
		   3 - Simon48/96 - 36 Rounds \n \
		   4 - Simon64/96 - 42 Rounds \n \
		   5 - Simon64/128 - 44 Rounds \n \
		   6 - Simon96/96 - 52 Rounds \n \
		   7 - Simon96/144 - 54 Rounds \n \
		   8 - Simon128/128 - 68 Rounds \n \
		   9 - Simon128/196 - 69 Rounds\n \
		   10 - Simon128/256 - 72 Rounds \n\n", errorMessage);

}

int BitCount(u32 u)
{
	unsigned int uCount;

	uCount = u - ((u >> 1) & 033333333333) - ((u >> 2) & 011111111111);
	return ((uCount + (uCount >> 3)) & 030707070707) % 63;
}

u64 skt64=1;
//not a good RNG... 
u32 randu32(void)
{
	//Shamir-Klimov T-function x->1+x+(x^2\/5)
	skt64=((skt64*skt64)|(u64)5)+skt64;
	return ((u32)(skt64>>32) ^ rand() ^ ((u32)rand()<<17) ^ ((u32)rand()<<10));
	/*15 bits only !!!*/\
		//RAND_MAX==0x7fff
};


u64 Put(u32 CL,u32 CR)
{
	return ((u64)CL)<<32 ^ CR;
}


const char *byte_to_binary(int x)
{
	static char b[9];
	b[0] = '\0';

	int z;
	for (z = 128; z > 0; z >>= 1)
	{
		strcat(b, ((x & z) == z) ? "1" : "0");
	}

	return b;
}

