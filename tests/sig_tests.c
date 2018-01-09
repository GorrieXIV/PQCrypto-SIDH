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
#include <stdlib.h>
#include <stdio.h>

CRYPTO_STATUS cryptotest_signature(int compress) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	// Number of bytes in a field element 
	unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;
	// Number of bytes in an element in [1, order]
	unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;

	// Allocate space for keys
	unsigned char *PrivateKey, *PublicKey;
	PrivateKey = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
	PublicKey = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)

	struct Signature sig;
	
	Status = isogeny_keygen(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, compress);
	if (Status != CRYPTO_SUCCESS) { return Status; }
	
	Status = isogeny_sign(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, &sig, compress);
	if (Status != CRYPTO_SUCCESS) { return Status; }

	Status = isogeny_verify(&CurveIsogeny_SIDHp751, PublicKey, &sig, compress);
	if (Status != CRYPTO_SUCCESS) { return Status; }	
}

CRYPTO_STATUS cryptorun_signature(int compress) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	// Number of bytes in a field element 
	unsigned int pbytes = (CurveIsogeny_SIDHp751.pwordbits + 7)/8;
	// Number of bytes in an element in [1, order]
	unsigned int n, obytes = (CurveIsogeny_SIDHp751.owordbits + 7)/8;
	unsigned long long cycles1, cycles2, scycles;

	// Allocate space for keys
	unsigned char *PrivateKey, *PublicKey;
	PrivateKey = (unsigned char*)calloc(1, obytes);        // One element in [1, order]  
	PublicKey = (unsigned char*)calloc(1, 4*2*pbytes);     // Four elements in GF(p^2)

	struct Signature sig;

	printf("\n\nBENCHMARKING EPHEMERAL ISOGENY-BASED KEY EXCHANGE \n");
	printf("--------------------------------------------------------------------------------------------------------\n\n");
	
	Status = isogeny_keygen(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, compress);
		
	cycles1 = cpucycles();
	Status = isogeny_sign(&CurveIsogeny_SIDHp751, PrivateKey, PublicKey, &sig, compress);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;
		
	printf("%10lld\n", scycles);
		
	cycles1 = cpucycles();
	Status = isogeny_verify(&CurveIsogeny_SIDHp751, PublicKey, &sig, compress);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;
		
	printf("%10lld\n", scycles);

}

int main (int argc, char** argv) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;

	int compression = 0; //1 = compressed, 0 = uncompressed
	
	Status = cryptotest_signature(compression);
	if (Status != CRYPTO_SUCCESS) { 
		printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
		return -1;	
	}
	
	Status = cryptorun_signature(compression);
	if (Status != CRYPTO_SUCCESS) { 
		printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
		return -1;	
	}

	return 0;
}
