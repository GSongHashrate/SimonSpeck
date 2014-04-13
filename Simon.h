#pragma once


class Simon
{
public:
	Simon(void);
public:
	~Simon(void);
};

void SimonEncryptBlock64128(u32 PL,u32 PR,u32 &CL, u32 &CR, u32* key,int nn,int keysize,int rounds);