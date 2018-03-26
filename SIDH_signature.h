/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral 
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Header file for Yoo et. al signature procedures
*
*********************************************************************************************/ 

#include "SIDH_internal.h"

#define NUM_ROUNDS       248
#define COMPRESS_ROUNDS  83

//signature structure
struct Signature {
	unsigned char *Commitments1[NUM_ROUNDS];
	unsigned char *Commitments2[NUM_ROUNDS];
	unsigned char *HashResp;
	unsigned char *Randoms[NUM_ROUNDS];
	
	//the following is an /anonymous/ union
	//this lets us reference psiS and compPsiS as members of Signature,
	//while ensuring their mutual exclusivity
	union { 
		point_proj *psiS[NUM_ROUNDS];
		digit_t compPsiS[NUM_ROUNDS][NWORDS_ORDER];
	};
	
	int compBit[NUM_ROUNDS];
	int compressed;
};

typedef struct thread_params_compress {
	PCurveIsogenyStruct *CurveIsogeny;
	unsigned char *PublicKey;
	struct Signature *sig;
	
	unsigned int pbytes;
	unsigned int n;
	unsigned int obytes;
} thread_params_compress;

//compressed signature structure

CRYPTO_STATUS isogeny_keygen(PCurveIsogenyStruct CurveIsogeny, unsigned char *PrivateKey, unsigned char *PublicKey);

void *sign_thread(void *TPS);

CRYPTO_STATUS isogeny_sign(PCurveIsogenyStruct CurveIsogeny, unsigned char *PrivateKey, unsigned char *PublicKey, struct Signature *sig, int batched, int compressed);

void *verify_thread(void *TPV);

CRYPTO_STATUS isogeny_verify(PCurveIsogenyStruct CurveIsogeny, unsigned char *PublicKey, struct Signature *sig, int batched, int compressed);
