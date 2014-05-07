#pragma once

#include "simonSpeckBasic.h"

void SimonEncryptBlock64128(u32 PL,u32 PR,u32 &CL, u32 &CR, u32* key,int nn,int keysize,int rounds);
void SimonEncryptBlockALL(u64 PL,u64 PR,u64 &CL, u64 &CR, u64* key,int nn,int keysize);
