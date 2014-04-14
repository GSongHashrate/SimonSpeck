
#pragma once


#define WIN32_LEAN_AND_MEAN		
#include <stdio.h>
#include <tchar.h>

#include "simonSpeck.h"
#include "Simon.h"
#include "Speck.h"
#include "Equations.h"


#define ROTL( n, X )    ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )