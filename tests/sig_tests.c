/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: benchmarking/testing isogeny-based key exchange
*
*********************************************************************************************/ 

#include "../SIDH.h"
#include "../SIDH_signature.h"
#include "test_extras.h"
#include <malloc.h>
#include <stdio.h>


int main (int argc, char** argv) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;

	// Number of bytes in a field element 
	unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;
	// Number of bytes in an element in [1, order]
	unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;
	unsigned long long cycles1, cycles2, kgcycles, scycles, vcycles;

	// Allocate space for keys
	unsigned char *PrivateKey, *PublicKey;
	PrivateKey = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
	PublicKey = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)

	struct Signature sig;
	
	//for (rep=0; rep<100; rep++) {
		Status = isogeny_keygen(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey);
		
		cycles1 = cpucycles();
		Status = isogeny_sign(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, &sig);
		cycles2 = cpucycles();
		scycles = cycles2 - cycles1;
		
		printf("%10lld\n", scycles);
		
		cycles1 = cpucycles();
		Status = isogeny_verify(&CurveIsogeny_SIDHp751, PublicKey, &sig);
		cycles2 = cpucycles();
		scycles = cycles2 - cycles1;
		
		printf("%10lld\n", scycles);
	//}

	return 0;
}
