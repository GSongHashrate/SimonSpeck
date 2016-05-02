#include "simonSpeckBasic.h"
#include "Simon.h"

int checkEqFile(int round, u32 *fixPL, u32 *fixPR );
int checkEqFile(int round, u32 *fixPL, u32 *fixPR, int fixn);
int checkEqFileALL(int round, u64 *fixPL, u64 *fixPR, int fixn, int blocksize, int keysize);