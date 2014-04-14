#pragma once
#include <sstream>
#include <iostream>
#include <iomanip>
class Equations
{
public:
	Equations(void);
public:
	~Equations(void);
};


void generateEquation(u32 PL,u32 PR,u32 CL, u32 CR, u32* key,int nn,int keysize,int rounds, int fk, int index);