
#include <fstream>
#include <string>
#include <iostream>
#include "CheckEquations.h"

char ** str_split(char* a_str, const char a_delim)
{
	char** result    = 0;
	size_t count     = 0;
	char* tmp        = a_str;
	char* last_comma = 0;
	char delim[2];
	delim[0] = a_delim;
	delim[1] = 0;

	/* Count how many elements will be extracted. */
	while (*tmp)
	{
		if (a_delim == *tmp)
		{
			count++;
			last_comma = tmp;
		}
		tmp++;
	}

	/* Add space for trailing token. */
	count += last_comma < (a_str + strlen(a_str) - 1);

	/* Add space for terminating null string so caller
	knows where the list of returned strings ends. */
	count++;

	result = (char **) malloc(sizeof(char*) * count);

	if (result)
	{
		size_t idx  = 0;
		char* token = strtok(a_str, delim);

		while (token)
		{

			*(result + idx++) = strdup(token);
			token = strtok(0, delim);
		}

		*(result + idx) = 0;
	}

	return result;
}
char ** split(std::string eq, char splitBy){
	char** tokens;
	char *cstr = new char[eq.length() + 1];
	strcpy(cstr, eq.c_str());
	tokens = str_split(cstr, splitBy);

	return tokens;
}
// fix 3 version
int checkSat(char** tokens){

	char integer_string[32];

	bool have_k = false;
	bool have_2_j = false;
	bool have_3_j = false;
	int ins1 = 0, ins2 = 0, ins3 = 0;

	if (tokens)
	{
		int i;
		int count = 0;
		for (i = 0; *(tokens + i); i++)
		{		
			if (strstr(*(tokens + i), "k_") != NULL) {
				// contains
				have_k = true;
				//printf("%d=[%s]\n", i,*(tokens + i));
			}

			if (strstr(*(tokens + i), "Z") != NULL || strstr(*(tokens + i), "P") != NULL || strstr(*(tokens + i), "C") ){
				//printf("%d=[%s]\n", i,*(tokens + i));
				if (
					strstr(*(tokens + i), "ZL0") != NULL || strstr(*(tokens + i), "PL0") != NULL || strstr(*(tokens + i), "CL0") ||
					strstr(*(tokens + i), "ZR0") != NULL || strstr(*(tokens + i), "PR0") != NULL || strstr(*(tokens + i), "CR0") 
					){
						//printf("%d=[%s]\n", i,*(tokens + i));
						ins1 = 1;
				}else if (
					strstr(*(tokens + i), "ZL1") != NULL || strstr(*(tokens + i), "PL1") != NULL || strstr(*(tokens + i), "CL1") ||
					strstr(*(tokens + i), "ZR1") != NULL || strstr(*(tokens + i), "PR1") != NULL || strstr(*(tokens + i), "CR1") 
					){
						ins2 = 1;
				}else {
					ins3 = 1;
				}
			}
			//free(*(tokens + i));
		}
		//printf("\n");

		// come from at least 2 PC pairs
	}

	if (ins1+ins2+ins3 == 2){
		if (have_k){
			return 2;
		}else{
			return 0;
		}
	}else if (ins1+ins2+ins3 == 3){
		if (have_k){
			return 3;
		}else{
			return 0;
		}
	}else{
		return 0;
	}
}
// fix n version
// works for u64 version as well
int checkSat(char** tokens, int fixn){
	int totalj = 0;
	bool have_k = false;
	int *ins;
	ins = (int*) malloc(sizeof(int)*fixn);
	for (int i= 0; i < fixn; i++){
		ins[i] = 0;
	}
	if (tokens)
	{
		int i;
		int count = 0;
		for (i = 0; *(tokens + i); i++)
		{		
			if (strstr(*(tokens + i), "k_") != NULL) {
				// contains
				have_k = true;
				//printf("%d=[%s]\n", i,*(tokens + i));
			}

			if (strstr(*(tokens + i), "Z") != NULL || strstr(*(tokens + i), "P") != NULL || strstr(*(tokens + i), "C") ){
				char ** newTokens = split(*(tokens+i),'_');
				char * tmp = *newTokens;
				int index = atoi(tmp+2);
				ins[index] = 1;
				//printf("%s: %d %s\n",*(tokens+i),index,tmp+2);
			}
			//free(*(tokens + i));
		}
		//printf("\n");

		// come from at least 2 PC pairs
	}
	for (int i = 0; i < fixn; i++){
		totalj+=ins[i];
	}
	if (have_k && totalj > 1){
		return totalj;
	}else{
		return 0;
	}
}

int getValue(u32 ZR, int index3){
	return (ZR >> index3 ) & 1;
}

int getValueALL(u64 ZR, int index3){
	return (ZR >> index3 ) & 1;
}

// fix 3 version
void checkEqs(std::string eq, int round, u32 *fixPL, u32 *fixPR, float &result){

	int totalcount = 0;
	int hit = 0;
	
	while (totalcount < 1000){

		// do simon encryption with random key
		u32 key[4] = {0};
		u32 PL[3] = {0}, PR[3] = {0}, CL[3]={0}, CR[3]={0};

		u32 **ZR, **ZL;
		ZR = (u32 **) malloc(3*sizeof(u32*));
		ZL = (u32 **) malloc(3*sizeof(u32*));

		key[0] = randu32();
		key[1] = randu32();
		key[2] = randu32();
		key[3] = randu32();

		for (int i = 0; i < 3; i++){
			ZL[i] = (u32 *) malloc(round*sizeof(u32));
			ZR[i] = (u32 *) malloc(round*sizeof(u32));

			PL[i] = fixPL[i];
			PR[i] = fixPR[i];
			SimonEncryptBlock64128(PL[i],PR[i],CL[i],CR[i],ZR[i],ZL[i],key,32,128,round);
		}

		// now we have all ZR[i][j], CL[i], CR[i], PL[i], PR[i] ... 

		// parse eq to find the right value
		int res = 0;
		char ** tokens = split(eq,'+');

		if (tokens)
		{
			for (int i = 0; *(tokens + i); i++)
			{		
				if (strstr(*(tokens + i), "k") != NULL ){
					char ** splitByU = split(*(tokens+i),'_');
					if (splitByU+1){
						int k_index = atoi(*(splitByU+1));
						int k_part = k_index / 32;
						int k_j = k_index % 32;
						//printf("K %d %d %d \n",k_index,k_part,k_j);
						res += getValue(key[k_part],k_j);
					}
				}
				// ZR1_003_025 
				else if (strstr(*(tokens + i), "Z") != NULL ){

					char ** splitByU = split(*(tokens+i),'_');
					int index1,index2,index3;

					index1 = atoi(*(splitByU)+2);
					index2 = atoi(*(splitByU+1));
					index3 = atoi(*(splitByU+2));
					//printf("ZR %d %d %d \n", index1, index2, index3);
					res+=getValue(ZR[index1][index2],index3);
				}
				else if (strstr(*(tokens + i), "C") != NULL){
					char ** splitByU = split(*(tokens+i),'_');
					int index1,index2;

					index1 = atoi(*(splitByU)+2);
					index2 = atoi(*(splitByU+1));
					//printf("CR %d %d \n", index1, index2);
					res += getValue(CR[index1],index2);
				}else {
					if (atoi(*(tokens+i))==1){
						res+=1;
					}
				}
			}
		}

		// mod 2 check equation
		if ((res%2)==0){
			hit++;
		}
		totalcount++;
		result = hit / totalcount * 100;
	}
	printf("%s %4.2f\%\n",eq.c_str(), result);
}
// general version fixn version
void checkEqs(std::string eq, int round, u32 *fixPL, u32 *fixPR, float &result, int fixn){

	int totalcount = 0;
	int hit = 0;
	
	while (totalcount < 1000){

		// do simon encryption with random key
		u32 key[4] = {0};
		u32 *PL, *PR, *CL, *CR;
		PL = (u32*)malloc(sizeof(u32)*fixn);
		PR = (u32*)malloc(sizeof(u32)*fixn);
		CL = (u32*)malloc(sizeof(u32)*fixn);
		CR = (u32*)malloc(sizeof(u32)*fixn);

		u32 **ZR, **ZL;
		ZR = (u32 **) malloc(fixn*sizeof(u32*));
		ZL = (u32 **) malloc(fixn*sizeof(u32*));

		key[0] = randu32();
		key[1] = randu32();
		key[2] = randu32();
		key[3] = randu32();

		for (int i = 0; i < fixn; i++){
			ZL[i] = (u32 *) malloc(round*sizeof(u32));
			ZR[i] = (u32 *) malloc(round*sizeof(u32));

			PL[i] = fixPL[i];
			PR[i] = fixPR[i];
			SimonEncryptBlock64128(PL[i],PR[i],CL[i],CR[i],ZR[i],ZL[i],key,32,128,round);
		}

		// now we have all ZR[i][j], CL[i], CR[i], PL[i], PR[i] ... 

		// parse eq to find the right value
		int res = 0;
		char ** tokens = split(eq,'+');

		if (tokens)
		{
			for (int i = 0; *(tokens + i); i++)
			{		
				if (strstr(*(tokens + i), "k") != NULL ){
					char ** splitByU = split(*(tokens+i),'_');
					if (splitByU+1){
						int k_index = atoi(*(splitByU+1));
						int k_part = k_index / 32;
						int k_j = k_index % 32;
						//printf("K %d %d %d \n",k_index,k_part,k_j);
						res += getValue(key[k_part],k_j);
					}
				}
				// ZR1_003_025 
				else if (strstr(*(tokens + i), "Z") != NULL ){

					char ** splitByU = split(*(tokens+i),'_');
					int index1,index2,index3;

					index1 = atoi(*(splitByU)+2);
					index2 = atoi(*(splitByU+1));
					index3 = atoi(*(splitByU+2));
					//printf("ZR %d %d %d \n", index1, index2, index3);
					res+=getValue(ZR[index1][index2],index3);
				}
				else if (strstr(*(tokens + i), "C") != NULL){
					char ** splitByU = split(*(tokens+i),'_');
					int index1,index2;

					index1 = atoi(*(splitByU)+2);
					index2 = atoi(*(splitByU+1));
					//printf("CR %d %d \n", index1, index2);
					res += getValue(CR[index1],index2);
				}else {
					if (atoi(*(tokens+i))==1){
						res+=1;
					}
				}
			}
		}

		// mod 2 check equation
		if ((res%2)==0){
			hit++;
		}
		totalcount++;
		result = hit / totalcount * 100;
	}
	printf("%s %4.2f\%\n",eq.c_str(), result);
}
// general version fixn for all simon

void checkEqsALL(std::string eq, int round, u64 *fixPL, u64 *fixPR, float &result, int fixn, int blocksize, int keysize){

	int totalcount = 0;
	int hit = 0;
	
	while (totalcount < 1000){

		// do simon encryption with random key
		u64 key[4] = {0};
		u64 *PL, *PR, *CL, *CR;
		PL = (u64*)malloc(sizeof(u64)*fixn);
		PR = (u64*)malloc(sizeof(u64)*fixn);
		CL = (u64*)malloc(sizeof(u64)*fixn);
		CR = (u64*)malloc(sizeof(u64)*fixn);

		u64 **ZR, **ZL;
		ZR = (u64 **) malloc(fixn*sizeof(u64*));
		ZL = (u64 **) malloc(fixn*sizeof(u64*));
		
		//TODO:: adjust keysize based on version

		key[0] = randu32();
		key[1] = randu32();
		key[2] = randu32();
		key[3] = randu32();

		for (int i = 0; i < fixn; i++){
			ZL[i] = (u64 *) malloc(round*sizeof(u64));
			ZR[i] = (u64 *) malloc(round*sizeof(u64));

			PL[i] = fixPL[i];
			PR[i] = fixPR[i];
			SimonEncryptBlockALL(PL[i],PR[i],CL[i],CR[i],ZR[i],ZL[i],key,blocksize,keysize,round);
		}

		// now we have all ZR[i][j], CL[i], CR[i], PL[i], PR[i] ... 

		// parse eq to find the right value
		int res = 0;
		char ** tokens = split(eq,'+');

		if (tokens)
		{
			for (int i = 0; *(tokens + i); i++)
			{		
				if (strstr(*(tokens + i), "k") != NULL ){
					char ** splitByU = split(*(tokens+i),'_');
					if (splitByU+1){
						int k_index = atoi(*(splitByU+1));
						// TODO change based on version!!!
						int k_part = k_index / 32;   
						int k_j = k_index % 32;
						//printf("K %d %d %d \n",k_index,k_part,k_j);
						res += getValueALL(key[k_part],k_j);
					}
				}
				// ZR1_003_025 
				else if (strstr(*(tokens + i), "Z") != NULL ){

					char ** splitByU = split(*(tokens+i),'_');
					int index1,index2,index3;

					index1 = atoi(*(splitByU)+2);
					index2 = atoi(*(splitByU+1));
					index3 = atoi(*(splitByU+2));
					//printf("ZR %d %d %d \n", index1, index2, index3);
					res+=getValueALL(ZR[index1][index2],index3);
				}
				else if (strstr(*(tokens + i), "C") != NULL){
					char ** splitByU = split(*(tokens+i),'_');
					int index1,index2;

					index1 = atoi(*(splitByU)+2);
					index2 = atoi(*(splitByU+1));
					//printf("CR %d %d \n", index1, index2);
					res += getValueALL(CR[index1],index2);
				}else {
					if (atoi(*(tokens+i))==1){
						res+=1;
					}
				}
			}
		}

		// mod 2 check equation
		if ((res%2)==0){
			hit++;
		}
		totalcount++;
		result = hit / totalcount * 100;
	}
	if (result > 0){
		printf("%s %4.2f\%\n",eq.c_str(), result);
	}
}

// extract key values from one equation
std::string extractKey(std::string eq){
	std::string res="";
	char ** tokens = split(eq,'+');
	if (tokens)
	{
		bool plus = false;
		for (int i = 0; *(tokens + i); i++)
		{		
			if (strstr(*(tokens + i), "k") != NULL ){
				if (!plus){
					res = res+*(tokens+i);
					plus = true;
				}else{
					res = res+std::string("+")+*(tokens+i);
				}
			}else if (strstr(*(tokens + i), "P") != NULL || strstr(*(tokens + i), "C") != NULL || strstr(*(tokens + i), "Z") != NULL){

			}else if (atoi(*(tokens+i))==1){
				res = res+std::string("+1");
			}
		}
	}
	//printf("! %s \n",res.c_str());
	return res;
}
// fix3 version
int checkEqFile(int round, u32 *fixPL, u32 *fixPR)
{
	FILE *f;
    f = fopen("table.txt", "a");

	int linecount = 0 ;
	int foundCount = 0;
	std::string line ;
	std::string foundEqs[300];
	std::string tmpline ;
	std::ifstream infile("./accumulated_lin.txt") ;
	int J[300];
	char** tokens;
	char* found;

	if ( infile ) {
		while ( getline( infile , line ) ) {
			char *cstr = new char[line.length() + 1];
			strcpy(cstr, line.c_str());
			tokens = str_split(cstr, '+');
			int j = checkSat(tokens);
			if ( j > 0){
				foundEqs[foundCount] = line;
				J[foundCount] = j;
				foundCount++;

			}
			free(tokens);

			//std::cout << linecount << ": " << line << '\n' ;//supposing '\n' to be line end
			linecount++ ;
		}
		for (int i = 0; i < foundCount; i++){
			float result = 0;
			std::string exkey;
			checkEqs(foundEqs[i], round, fixPL,fixPR, result);
			
			exkey = extractKey(foundEqs[i]);
			// 0000 0000 & 0 & 2 & k025+1       & 1    \\ \hline
			fprintf(f,"0000 0000 & 0 & %d & %s & %4.2f & %d \\\\ \\hline\n",J[i],exkey.c_str(),result, round);
		}
		//getVars(foundEqs[foundCount].c_str());
	}
	infile.close() ;
	return 0 ;
}
// fixn version 64/128
int checkEqFile(int round, u32 *fixPL, u32 *fixPR, int fixn)
{
	FILE *f;
    f = fopen("test_table.txt", "a");
	
	int linecount = 0 ;
	int foundCount = 0;
	std::string line ;
	std::string foundEqs[300];
	std::string tmpline ;
	std::ifstream infile("./accumulated_lin.txt") ;
	int J[300];
	char** tokens;
	char* found;

	if ( infile ) {
		while ( getline( infile , line ) ) {
			char *cstr = new char[line.length() + 1];
			strcpy(cstr, line.c_str());
			tokens = str_split(cstr, '+');
			int j = checkSat(tokens, fixn);
			if ( j > 0){
				foundEqs[foundCount] = line;
				J[foundCount] = j;
				foundCount++;

			}
			free(tokens);

			//std::cout << linecount << ": " << line << '\n' ;//supposing '\n' to be line end
			linecount++ ;
		}
		for (int i = 0; i < foundCount; i++){
			float result = 0;
			std::string exkey;
			checkEqs(foundEqs[i], round, fixPL,fixPR, result, fixn);
			
			exkey = extractKey(foundEqs[i]);
			// 0000 0000 & 0 & 2 & k025+1       & 1    \\ \hline
			if (J[i] > 0){
				fprintf(f,"0000 0000 & 0 & %d & %s & %4.2f & %d \\\\ \\hline\n",J[i],exkey.c_str(),result, round);
			}
		}
		//getVars(foundEqs[foundCount].c_str());
	}
	infile.close() ;
	return 0 ;
}

int checkEqFileALL(int round, u64 *fixPL, u64 *fixPR, int fixn, int blocksize, int keysize)
{
	FILE *f;
    f = fopen("test_table.txt", "a");
	
	int linecount = 0 ;
	int foundCount = 0;
	std::string line ;
	std::string foundEqs[300];
	std::string tmpline ;
	std::ifstream infile("./accumulated_lin.txt") ;
	int J[300];
	char** tokens;
	char* found;

	if ( infile ) {
		while ( getline( infile , line ) ) {
			char *cstr = new char[line.length() + 1];
			strcpy(cstr, line.c_str());
			tokens = str_split(cstr, '+');
			int j = checkSat(tokens, fixn);
			if ( j > 0){
				foundEqs[foundCount] = line;
				J[foundCount] = j;
				foundCount++;

			}
			free(tokens);

			//std::cout << linecount << ": " << line << '\n' ;//supposing '\n' to be line end
			linecount++ ;
		}
		for (int i = 0; i < foundCount; i++){
			float result = 0;
			std::string exkey;
			checkEqsALL(foundEqs[i], round, fixPL,fixPR, result, fixn, blocksize, keysize);
			
			exkey = extractKey(foundEqs[i]);
			// 0000 0000 & 0 & 2 & k025+1       & 1    \\ \hline
			if (J[i] > 0){
				fprintf(f,"0000 0000 & 0 & %d & %s & %4.2f & %d \\\\ \\hline\n",J[i],exkey.c_str(),result, round);
			}
		}
		//getVars(foundEqs[foundCount].c_str());
	}
	infile.close() ;
	return 0 ;
}