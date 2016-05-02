#pragma once
#include "simonSpeckBasic.h"

void generateEquation(u32 PL,u32 PR,u32 CL, u32 CR, u32* key,int nn,int keysize,int rounds, int fk, int index);
void generateEquation(u32 PL,u32 PR,u32 CL, u32 CR, u32* key,int nn,int keysize,int rounds, int fk, int index, int version);

void generateEquationALL(u64 PL, u64 PR, u64 CL, u64 CR, u64* key, int nn, int keysize, int rounds, int fk, int index, int relax);
int getJ(int blockVersion, int keySize);
int getM(int blockVersion, int keySize);
void printKey(u64 key);