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

#define NUM_ROUNDS     248

//signature structure
struct Signature {
    unsigned char *Commitments1[NUM_ROUNDS];
    unsigned char *Commitments2[NUM_ROUNDS];
    unsigned char *HashResp;
    unsigned char *Randoms[NUM_ROUNDS];
    point_proj *psiS[NUM_ROUNDS];
};

CRYPTO_STATUS isogeny_keygen(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PrivateKey, unsigned char *PublicKey, int compressed);

void *sign_thread(void *TPS, int compressed);

CRYPTO_STATUS isogeny_sign(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PrivateKey, unsigned char *PublicKey, struct Signature *sig, int compressed);

void *verify_thread(void *TPV, int compressed);

CRYPTO_STATUS isogeny_verify(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PublicKey, struct Signature *sig, int compressed);
