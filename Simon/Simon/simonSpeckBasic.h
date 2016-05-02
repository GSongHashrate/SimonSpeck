#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include "time.h"
#include <hash_set>
#include "Simon.h"
#include "Speck.h"
#include "Equations.h"

typedef __int64 s64;
typedef unsigned __int64 u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;


#define ROTL( n, X )    ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )

#define ROTL2( n, X, L )    ( ( ( X ) << ( n + 64 - L ) >> (64-L)) | ( ( X ) >> ( L - n ) ) )

int getBlockVer(int version);
int getKeyVer(int version);
bool isValidSize(int bSize, int kSize);
int getRounds(int bSize, int kSize);
void printUsage(int uCase);
int BitCount(u32 u);
u32 randu32(void);