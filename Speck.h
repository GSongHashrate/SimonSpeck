#pragma once

class Speck
{
public:
	Speck(void);
public:
	~Speck(void);
};


void SpeckEncryptBlock64128(u32 PL,u32 PR,u32 &CL, u32 &CR, u32* key,int nn,int keysize,int rounds);
