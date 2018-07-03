/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for ephemeral
*       Diffie-Hellman key exchange.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: ephemeral isogeny-based key exchange
*
*********************************************************************************************/

#include "SIDH_internal.h"
#include <inttypes.h>

extern const unsigned int splits_Alice[MAX_Alice];
extern const unsigned int splits_Bob[MAX_Bob];


CRYPTO_STATUS EphemeralKeyGeneration_A(unsigned char* PrivateKeyA, unsigned char* PublicKeyA, PCurveIsogenyStruct CurveIsogeny)
{ // Alice's ephemeral key-pair generation
  // It produces a private key PrivateKeyA and computes the public key PublicKeyA.
  // The private key is an even integer in the range [2, oA-2], where oA = 2^372.
  // The public key consists of 3 elements in GF(p751^2).
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int owords = NBITS_TO_NWORDS(CurveIsogeny->owordbits), pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
    point_basefield_t P;
    point_proj_t R, phiP = {0}, phiQ = {0}, phiD = {0}, pts[MAX_INT_POINTS_ALICE];
    publickey_t* PublicKey = (publickey_t*)PublicKeyA;
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0;
    f2elm_t coeff[5], A = {0}, C = {0}, Aout, Cout;
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

    if (PrivateKeyA == NULL || PublicKey == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // Choose a random even number in the range [2, oA-2] as secret key for Alice
    Status = random_mod_order((digit_t*)PrivateKeyA, ALICE, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {
        clear_words((void*)PrivateKeyA, owords);
        return Status;
    }

    to_mont((digit_t*)CurveIsogeny->PA, (digit_t*)P);                               // Conversion of Alice's generators to Montgomery representation
    to_mont(((digit_t*)CurveIsogeny->PA)+NWORDS_FIELD, ((digit_t*)P)+NWORDS_FIELD);

    Status = secret_pt(P, (digit_t*)PrivateKeyA, ALICE, R, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {
        clear_words((void*)PrivateKeyA, owords);
        return Status;
    }

    copy_words((digit_t*)CurveIsogeny->PB, (digit_t*)phiP, pwords);                 // Copy X-coordinates from Bob's public parameters, set Z <- 1
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)phiP->Z);
    to_mont((digit_t*)phiP, (digit_t*)phiP);
    copy_words((digit_t*)phiP, (digit_t*)phiQ, pwords);                             // QB = (-XPB:1)
    fpneg751(phiQ->X[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)phiQ->Z);
    distort_and_diff(phiP->X[0], phiD, CurveIsogeny);                               // DB = (x(QB-PB),z(QB-PB))

    fpcopy751(CurveIsogeny->A, A[0]);                                               // Extracting curve parameters A and C
    fpcopy751(CurveIsogeny->C, C[0]);
    to_mont(A[0], A[0]);
    to_mont(C[0], C[0]);

    first_4_isog(phiP, A, Aout, Cout, CurveIsogeny);
    first_4_isog(phiQ, A, Aout, Cout, CurveIsogeny);
    first_4_isog(phiD, A, Aout, Cout, CurveIsogeny);
    first_4_isog(R, A, A, C, CurveIsogeny);

    index = 0;
    for (row = 1; row < MAX_Alice; row++) {
        while (index < MAX_Alice-row) {
            fp2copy751(R->X, pts[npts]->X);
            fp2copy751(R->Z, pts[npts]->Z);
            pts_index[npts] = index;
            npts += 1;
            m = splits_Alice[MAX_Alice-index-row];
            xDBLe(R, R, A, C, (int)(2*m));
            index += m;
        }
        get_4_isog(R, A, C, coeff);

        for (i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }
        eval_4_isog(phiP, coeff);
        eval_4_isog(phiQ, coeff);
        eval_4_isog(phiD, coeff);

        fp2copy751(pts[npts-1]->X, R->X);
        fp2copy751(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A, C, coeff);
    eval_4_isog(phiP, coeff);
    eval_4_isog(phiQ, coeff);
    eval_4_isog(phiD, coeff);

    inv_3_way(phiP->Z, phiQ->Z, phiD->Z);
    fp2mul751_mont(phiP->X, phiP->Z, phiP->X);
    fp2mul751_mont(phiQ->X, phiQ->Z, phiQ->X);
    fp2mul751_mont(phiD->X, phiD->Z, phiD->X);

    from_fp2mont(phiP->X, ((f2elm_t*)PublicKey)[0]);                               // Converting back to standard representation
    from_fp2mont(phiQ->X, ((f2elm_t*)PublicKey)[1]);
    from_fp2mont(phiD->X, ((f2elm_t*)PublicKey)[2]);

// Cleanup:
    clear_words((void*)R, 2*2*pwords);
    clear_words((void*)phiP, 2*2*pwords);
    clear_words((void*)phiQ, 2*2*pwords);
    clear_words((void*)phiD, 2*2*pwords);
    clear_words((void*)pts, MAX_INT_POINTS_ALICE*2*2*pwords);
    clear_words((void*)A, 2*pwords);
    clear_words((void*)C, 2*pwords);
    clear_words((void*)coeff, 5*2*pwords);

    return Status;
}

CRYPTO_STATUS KeyGeneration_A(unsigned char* pPrivateKeyA, unsigned char* pPublicKeyA, PCurveIsogenyStruct CurveIsogeny, bool GenerateRandom, batch_struct* batch) {
	// Alice's key-pair generation
	// It produces a private key pPrivateKeyA and computes the public key pPublicKeyA.
	// The private key is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total).
	// The public key consists of 4 elements in GF(p751^2), i.e., 751 bytes in total.
	// CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	unsigned int owords = NBITS_TO_NWORDS(CurveIsogeny->owordbits);
	unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	point_basefield_t P;
	point_proj_t R, phiP = {0}, phiQ = {0}, phiD = {0}, pts[MAX_INT_POINTS_ALICE];
	publickey_t* PublicKeyA = (publickey_t*)pPublicKeyA;
	unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0;
	f2elm_t coeff[5], A = {0}, C = {0}, Aout, Cout;
	CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

	if (pPrivateKeyA == NULL || pPublicKeyA == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return CRYPTO_ERROR_INVALID_PARAMETER;
	}

	//modified
	// Choose a random even number in the range [2, oA-2] as secret key for Alice
	if (GenerateRandom) {
		Status = random_mod_order((digit_t*)pPrivateKeyA, ALICE, CurveIsogeny);
		if (Status != CRYPTO_SUCCESS) {
			clear_words((void*)pPrivateKeyA, owords);
			return Status;
		}
	}

	to_mont((digit_t*)CurveIsogeny->PA, (digit_t*)P);		// Conversion of Alice's generators to Montgomery representation
	to_mont(((digit_t*)CurveIsogeny->PA)+NWORDS_FIELD, ((digit_t*)P)+NWORDS_FIELD);

	Status = secret_pt(P, (digit_t*)pPrivateKeyA, ALICE, R, CurveIsogeny);
	if (Status != CRYPTO_SUCCESS) {
		clear_words((void*)pPrivateKeyA, owords);
		return Status;
	}

	copy_words((digit_t*)CurveIsogeny->PB, (digit_t*)phiP, pwords);		// Copy X-coordinates from Bob's public parameters, set Z <- 1
	fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)phiP->Z);
	to_mont((digit_t*)phiP, (digit_t*)phiP);
	copy_words((digit_t*)phiP, (digit_t*)phiQ, pwords);                             // QB = (-XPB:1)
	fpneg751(phiQ->X[0]);
	fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)phiQ->Z);
	distort_and_diff(phiP->X[0], phiD, CurveIsogeny);                               // DB = (x(QB-PB),z(QB-PB))

	fpcopy751(CurveIsogeny->A, A[0]);                                               // Extracting curve parameters A and C
	fpcopy751(CurveIsogeny->C, C[0]);
	to_mont(A[0], A[0]);
	to_mont(C[0], C[0]);

	first_4_isog(phiP, A, Aout, Cout, CurveIsogeny);
	first_4_isog(phiQ, A, Aout, Cout, CurveIsogeny);
	first_4_isog(phiD, A, Aout, Cout, CurveIsogeny);
	first_4_isog(R, A, A, C, CurveIsogeny);

	index = 0;
	for (row = 1; row < MAX_Alice; row++) {
		while (index < MAX_Alice-row) {
			fp2copy751(R->X, pts[npts]->X);
			fp2copy751(R->Z, pts[npts]->Z);
			pts_index[npts] = index;
			npts += 1;
			m = splits_Alice[MAX_Alice-index-row];
			xDBLe(R, R, A, C, (int)(2*m));
			index += m;
		}
		get_4_isog(R, A, C, coeff);

		for (i = 0; i < npts; i++) {
			eval_4_isog(pts[i], coeff);
		}
		eval_4_isog(phiP, coeff);
		eval_4_isog(phiQ, coeff);
		eval_4_isog(phiD, coeff);

		fp2copy751(pts[npts-1]->X, R->X);
		fp2copy751(pts[npts-1]->Z, R->Z);
		index = pts_index[npts-1];
		npts -= 1;
	}

	get_4_isog(R, A, C, coeff);
	eval_4_isog(phiP, coeff);
	eval_4_isog(phiQ, coeff);
	eval_4_isog(phiD, coeff);

	if(batch != NULL) {
		inv_4_way_batch(C, phiP->Z, phiQ->Z, phiD->Z, batch);
	} else {
		inv_4_way(C, phiP->Z, phiQ->Z, phiD->Z);
	}

	fp2mul751_mont(A, C, A);
	fp2mul751_mont(phiP->X, phiP->Z, phiP->X);
	fp2mul751_mont(phiQ->X, phiQ->Z, phiQ->X);
	fp2mul751_mont(phiD->X, phiD->Z, phiD->X);

	from_fp2mont(A, ((f2elm_t*)PublicKeyA)[0]);		// Converting back to standard representation
	from_fp2mont(phiP->X, ((f2elm_t*)PublicKeyA)[1]);
	from_fp2mont(phiQ->X, ((f2elm_t*)PublicKeyA)[2]);
	from_fp2mont(phiD->X, ((f2elm_t*)PublicKeyA)[3]);

// Cleanup:
	clear_words((void*)R, 2*2*pwords);
	clear_words((void*)phiP, 2*2*pwords);
	clear_words((void*)phiQ, 2*2*pwords);
	clear_words((void*)phiD, 2*2*pwords);
	clear_words((void*)pts, MAX_INT_POINTS_ALICE*2*2*pwords);
	clear_words((void*)A, 2*pwords);
	clear_words((void*)C, 2*pwords);
	clear_words((void*)coeff, 5*2*pwords);

	return Status;
}


CRYPTO_STATUS EphemeralKeyGeneration_B(unsigned char* PrivateKeyB, unsigned char* PublicKeyB, PCurveIsogenyStruct CurveIsogeny)
{ // Bob's ephemeral key-pair generation
  // It produces a private key PrivateKeyB and computes the public key PublicKeyB.
  // The private key is an integer in the range [1, oB-1], where oA = 3^239.
  // The public key consists of 3 elements in GF(p751^2).
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
	unsigned int owords = NBITS_TO_NWORDS(CurveIsogeny->owordbits), pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
	point_basefield_t P;
	point_proj_t R, phiP = {0}, phiQ = {0}, phiD = {0}, pts[MAX_INT_POINTS_BOB];
	publickey_t* PublicKey = (publickey_t*)PublicKeyB;
	unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0;
	f2elm_t A = {0}, C = {0};
	CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

	if (PrivateKeyB == NULL || PublicKey == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
		return CRYPTO_ERROR_INVALID_PARAMETER;
	}

	// Choose a random number equivalent to 0 (mod 3) in the range [3, oB-3] as secret key for Bob
	Status = random_mod_order((digit_t*)PrivateKeyB, BOB, CurveIsogeny);
	if (Status != CRYPTO_SUCCESS) {
		clear_words((void*)PrivateKeyB, owords);
		return Status;
	}

	to_mont((digit_t*)CurveIsogeny->PB, (digit_t*)P);                               // Conversion of Bob's generators to Montgomery representation
	to_mont(((digit_t*)CurveIsogeny->PB)+NWORDS_FIELD, ((digit_t*)P)+NWORDS_FIELD);

	Status = secret_pt(P, (digit_t*)PrivateKeyB, BOB, R, CurveIsogeny);
	if (Status != CRYPTO_SUCCESS) {
		clear_words((void*)PrivateKeyB, owords);
		return Status;
	}

	copy_words((digit_t*)CurveIsogeny->PA, (digit_t*)phiP, pwords);                 // Copy X-coordinates from Alice's public parameters, set Z <- 1
	fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)phiP->Z);
	to_mont((digit_t*)phiP, (digit_t*)phiP);                                        // Conversion to Montgomery representation
	copy_words((digit_t*)phiP, (digit_t*)phiQ, pwords);                             // QA = (-XPA:1)
	fpneg751(phiQ->X[0]);
	fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)phiQ->Z);
	distort_and_diff(phiP->X[0], phiD, CurveIsogeny);                               // DA = (x(QA-PA),z(QA-PA))

	fpcopy751(CurveIsogeny->A, A[0]);                                               // Extracting curve parameters A and C
	fpcopy751(CurveIsogeny->C, C[0]);
	to_mont(A[0], A[0]);
	to_mont(C[0], C[0]);

	index = 0;
	for (row = 1; row < MAX_Bob; row++) {
		while (index < MAX_Bob-row) {
			fp2copy751(R->X, pts[npts]->X);
			fp2copy751(R->Z, pts[npts]->Z);
			pts_index[npts] = index;
			npts += 1;
			m = splits_Bob[MAX_Bob-index-row];
			xTPLe(R, R, A, C, (int)m);
			index += m;
		}
		get_3_isog(R, A, C);

		for (i = 0; i < npts; i++) {
			eval_3_isog(R, pts[i]);
		}
		eval_3_isog(R, phiP);
		eval_3_isog(R, phiQ);
		eval_3_isog(R, phiD);

		fp2copy751(pts[npts-1]->X, R->X);
		fp2copy751(pts[npts-1]->Z, R->Z);
		index = pts_index[npts-1];
		npts -= 1;
	}

	get_3_isog(R, A, C);
	eval_3_isog(R, phiP);
	eval_3_isog(R, phiQ);
	eval_3_isog(R, phiD);

	inv_3_way(phiP->Z, phiQ->Z, phiD->Z);
	fp2mul751_mont(phiP->X, phiP->Z, phiP->X);
	fp2mul751_mont(phiQ->X, phiQ->Z, phiQ->X);
	fp2mul751_mont(phiD->X, phiD->Z, phiD->X);

	// Converting back to standard representation
	from_fp2mont(phiP->X, ((f2elm_t*)PublicKey)[0]);
	from_fp2mont(phiQ->X, ((f2elm_t*)PublicKey)[1]);
	from_fp2mont(phiD->X, ((f2elm_t*)PublicKey)[2]);

	// Cleanup:
	clear_words((void*)R, 2*2*pwords);
	clear_words((void*)phiP, 2*2*pwords);
	clear_words((void*)phiQ, 2*2*pwords);
	clear_words((void*)phiD, 2*2*pwords);
	clear_words((void*)pts, MAX_INT_POINTS_BOB*2*2*pwords);
	clear_words((void*)A, 2*pwords);
	clear_words((void*)C, 2*pwords);

	return Status;
}

CRYPTO_STATUS KeyGeneration_B(unsigned char* pPrivateKeyB, unsigned char* pPublicKeyB, PCurveIsogenyStruct CurveIsogeny)
{ // Bob's key-pair generation
  // It produces a private key pPrivateKeyB and computes the public key pPublicKeyB.
  // The private key is an integer in the range [1, oB-1], where oA = 3^239 (i.e., 379 bits in total).
  // The public key consists of 4 elements in GF(p751^2), i.e., 751 bytes in total.
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int owords = NBITS_TO_NWORDS(CurveIsogeny->owordbits), pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
    point_basefield_t P;
    point_proj_t R, phiP = {0}, phiQ = {0}, phiD = {0}, pts[MAX_INT_POINTS_BOB];
    publickey_t* PublicKeyB = (publickey_t*)pPublicKeyB;
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0;
    f2elm_t A = {0}, C = {0};
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

    if (pPrivateKeyB == NULL || pPublicKeyB == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // Choose a random number equivalent to 0 (mod 3) in the range [3, oB-3] as secret key for Bob
    Status = random_mod_order((digit_t*)pPrivateKeyB, BOB, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {
        clear_words((void*)pPrivateKeyB, owords);
        return Status;
    }

    to_mont((digit_t*)CurveIsogeny->PB, (digit_t*)P);                               // Conversion of Bob's generators to Montgomery representation
    to_mont(((digit_t*)CurveIsogeny->PB)+NWORDS_FIELD, ((digit_t*)P)+NWORDS_FIELD);

    Status = secret_pt(P, (digit_t*)pPrivateKeyB, BOB, R, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {
        clear_words((void*)pPrivateKeyB, owords);
        return Status;
    }

    copy_words((digit_t*)CurveIsogeny->PA, (digit_t*)phiP, pwords);                 // Copy X-coordinates from Alice's public parameters, set Z <- 1
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)phiP->Z);
    to_mont((digit_t*)phiP, (digit_t*)phiP);                                        // Conversion to Montgomery representation
    copy_words((digit_t*)phiP, (digit_t*)phiQ, pwords);                             // QA = (-XPA:1)
    fpneg751(phiQ->X[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, (digit_t*)phiQ->Z);
    distort_and_diff(phiP->X[0], phiD, CurveIsogeny);                               // DA = (x(QA-PA),z(QA-PA))

    fpcopy751(CurveIsogeny->A, A[0]);                                               // Extracting curve parameters A and C
    fpcopy751(CurveIsogeny->C, C[0]);
    to_mont(A[0], A[0]);
    to_mont(C[0], C[0]);

    index = 0;
    for (row = 1; row < MAX_Bob; row++) {
        while (index < MAX_Bob-row) {
            fp2copy751(R->X, pts[npts]->X);
            fp2copy751(R->Z, pts[npts]->Z);
            pts_index[npts] = index;
            npts += 1;
            m = splits_Bob[MAX_Bob-index-row];
            xTPLe(R, R, A, C, (int)m);
            index += m;
        }
        get_3_isog(R, A, C);

        for (i = 0; i < npts; i++) {
            eval_3_isog(R, pts[i]);
        }
        eval_3_isog(R, phiP);
        eval_3_isog(R, phiQ);
        eval_3_isog(R, phiD);

        fp2copy751(pts[npts-1]->X, R->X);
        fp2copy751(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A, C);
    eval_3_isog(R, phiP);
    eval_3_isog(R, phiQ);
    eval_3_isog(R, phiD);

    inv_4_way(C, phiP->Z, phiQ->Z, phiD->Z);

    fp2mul751_mont(A, C, A);
    fp2mul751_mont(phiP->X, phiP->Z, phiP->X);
    fp2mul751_mont(phiQ->X, phiQ->Z, phiQ->X);
    fp2mul751_mont(phiD->X, phiD->Z, phiD->X);

    from_fp2mont(A, ((f2elm_t*)PublicKeyB)[0]);                                     // Converting back to standard representation
    from_fp2mont(phiP->X, ((f2elm_t*)PublicKeyB)[1]);
    from_fp2mont(phiQ->X, ((f2elm_t*)PublicKeyB)[2]);
    from_fp2mont(phiD->X, ((f2elm_t*)PublicKeyB)[3]);

// Cleanup:
    clear_words((void*)R, 2*2*pwords);
    clear_words((void*)phiP, 2*2*pwords);
    clear_words((void*)phiQ, 2*2*pwords);
    clear_words((void*)phiD, 2*2*pwords);
    clear_words((void*)pts, MAX_INT_POINTS_BOB*2*2*pwords);
    clear_words((void*)A, 2*pwords);
    clear_words((void*)C, 2*pwords);

    return Status;
}


CRYPTO_STATUS EphemeralSecretAgreement_A(const unsigned char* PrivateKeyA, const unsigned char* PublicKeyB, unsigned char* SharedSecretA, PCurveIsogenyStruct CurveIsogeny)
{ // Alice's ephemeral shared secret computation
  // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's public key PublicKeyB
  // Inputs: Alice's PrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372.
  //         Bob's PublicKeyB consists of 3 elements in GF(p751^2).
  // Output: a shared secret SharedSecretA that consists of one element in GF(p751^2).
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0;
    point_proj_t R, pts[MAX_INT_POINTS_ALICE];
    publickey_t* PublicKey = (publickey_t*)PublicKeyB;
    f2elm_t jinv, coeff[5], PKB[3], A, C = {0};
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

    if (PrivateKeyA == NULL || PublicKey == NULL || SharedSecretA == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    to_fp2mont(((f2elm_t*)PublicKey)[0], PKB[0]);    // Extracting and converting Bob's public curve parameters to Montgomery representation
    to_fp2mont(((f2elm_t*)PublicKey)[1], PKB[1]);
    to_fp2mont(((f2elm_t*)PublicKey)[2], PKB[2]);

    get_A(PKB[0], PKB[1], PKB[2], A, CurveIsogeny);
    fpcopy751(CurveIsogeny->C, C[0]);
    to_mont(C[0], C[0]);

    Status = ladder_3_pt(PKB[0], PKB[1], PKB[2], (digit_t*)PrivateKeyA, ALICE, R, A, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {
        return Status;
    }
    first_4_isog(R, A, A, C, CurveIsogeny);

    index = 0;
    for (row = 1; row < MAX_Alice; row++) {
        while (index < MAX_Alice-row) {
            fp2copy751(R->X, pts[npts]->X);
            fp2copy751(R->Z, pts[npts]->Z);
            pts_index[npts] = index;
            npts += 1;
            m = splits_Alice[MAX_Alice-index-row];
            xDBLe(R, R, A, C, (int)(2*m));
            index += m;
        }
        get_4_isog(R, A, C, coeff);

        for (i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }

        fp2copy751(pts[npts-1]->X, R->X);
        fp2copy751(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A, C, coeff);
    j_inv(A, C, jinv);
    from_fp2mont(jinv, (felm_t*)SharedSecretA);      // Converting back to standard representation

// Cleanup:
    clear_words((void*)R, 2*2*pwords);
    clear_words((void*)pts, MAX_INT_POINTS_ALICE*2*2*pwords);
    clear_words((void*)A, 2*pwords);
    clear_words((void*)C, 2*pwords);
    clear_words((void*)jinv, 2*pwords);
    clear_words((void*)coeff, 5*2*pwords);

    return Status;
}

CRYPTO_STATUS SecretAgreement_A(unsigned char* pPrivateKeyA, unsigned char* pPublicKeyB, unsigned char* pSharedSecretA, PCurveIsogenyStruct CurveIsogeny, point_proj_t kerngen, batch_struct* batch)
{ // Alice's shared secret generation
  // It produces a shared secret key pSharedSecretA using her secret key pPrivateKeyA and Bob's public key pPublicKeyB
  // Inputs: Alice's pPrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372 (i.e., 372 bits in total).
  //         Bob's pPublicKeyB consists of 4 elements in GF(p751^2), i.e., 751 bytes in total.
  // Output: a shared secret pSharedSecretA that consists of one element in GF(p751^2), i.e., 1502 bits in total.
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0;
    point_proj_t R, pts[MAX_INT_POINTS_ALICE];
    publickey_t* PublicKeyB = (publickey_t*)pPublicKeyB;
    f2elm_t jinv, coeff[5], A, C = {0}, PKB2, PKB3, PKB4;
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

    if (pPrivateKeyA == NULL || pPublicKeyB == NULL || pSharedSecretA == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    to_fp2mont(((f2elm_t*)PublicKeyB)[0], A);         // Extracting and converting Bob's public curve parameters to Montgomery representation
    to_fp2mont(((f2elm_t*)PublicKeyB)[1], PKB2);
    to_fp2mont(((f2elm_t*)PublicKeyB)[2], PKB3);
    to_fp2mont(((f2elm_t*)PublicKeyB)[3], PKB4);

    fpcopy751(CurveIsogeny->C, C[0]);
    to_mont(C[0], C[0]);

    if (kerngen == NULL) {
        Status = ladder_3_pt(PKB2, PKB3, PKB4, (digit_t*)pPrivateKeyA, ALICE, R, A, CurveIsogeny);
        if (Status != CRYPTO_SUCCESS) {
            return Status;
        }
    } else {
        fp2copy751(kerngen->X, R->X);
        fp2copy751(kerngen->Z, R->Z);
    }

    first_4_isog(R, A, A, C, CurveIsogeny);

    index = 0;
    for (row = 1; row < MAX_Alice; row++) {
        while (index < MAX_Alice-row) {
            fp2copy751(R->X, pts[npts]->X);
            fp2copy751(R->Z, pts[npts]->Z);
            pts_index[npts] = index;
            npts += 1;
            m = splits_Alice[MAX_Alice-index-row];
            xDBLe(R, R, A, C, (int)(2*m));
            index += m;
        }
        get_4_isog(R, A, C, coeff);

        for (i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }

        fp2copy751(pts[npts-1]->X, R->X);
        fp2copy751(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A, C, coeff);

		if (batch != NULL) {
			j_inv_batch(A, C, jinv, batch);
		} else {
			j_inv(A, C, jinv);
		}

    from_fp2mont(jinv, (felm_t*)pSharedSecretA);      // Converting back to standard representation

// Cleanup:
    clear_words((void*)R, 2*2*pwords);
    clear_words((void*)pts, MAX_INT_POINTS_ALICE*2*2*pwords);
    clear_words((void*)A, 2*pwords);
    clear_words((void*)C, 2*pwords);
    clear_words((void*)jinv, 2*pwords);
    clear_words((void*)coeff, 5*2*pwords);

    return Status;
}


CRYPTO_STATUS EphemeralSecretAgreement_B(const unsigned char* PrivateKeyB, const unsigned char* PublicKeyA, unsigned char* SharedSecretB, PCurveIsogenyStruct CurveIsogeny)
{ // Bob's ephemeral shared secret computation
  // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's public key PublicKeyA
  // Inputs: Bob's PrivateKeyB is an integer in the range [1, oB-1], where oB = 3^239.
  //         Alice's PublicKeyA consists of 3 elements in GF(p751^2).
  // Output: a shared secret SharedSecretB that consists of one element in GF(p751^2).
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0;
    point_proj_t R, pts[MAX_INT_POINTS_BOB];
    publickey_t* PublicKey = (publickey_t*)PublicKeyA;
    f2elm_t jinv, A, PKA[3], C = {0};
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

    if (PrivateKeyB == NULL || PublicKey == NULL || SharedSecretB == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    to_fp2mont(((f2elm_t*)PublicKey)[0], PKA[0]);    // Extracting and converting Alice's public curve parameters to Montgomery representation
    to_fp2mont(((f2elm_t*)PublicKey)[1], PKA[1]);
    to_fp2mont(((f2elm_t*)PublicKey)[2], PKA[2]);

    get_A(PKA[0], PKA[1], PKA[2], A, CurveIsogeny);
    fpcopy751(CurveIsogeny->C, C[0]);
    to_mont(C[0], C[0]);

    Status = ladder_3_pt(PKA[0], PKA[1], PKA[2], (digit_t*)PrivateKeyB, BOB, R, A, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {
        return Status;
    }

    index = 0;
    for (row = 1; row < MAX_Bob; row++) {
        while (index < MAX_Bob-row) {
            fp2copy751(R->X, pts[npts]->X);
            fp2copy751(R->Z, pts[npts]->Z);
            pts_index[npts] = index;
            npts += 1;
            m = splits_Bob[MAX_Bob-index-row];
            xTPLe(R, R, A, C, (int)m);
            index += m;
        }
        get_3_isog(R, A, C);

        for (i = 0; i < npts; i++) {
            eval_3_isog(R, pts[i]);
        }

        fp2copy751(pts[npts-1]->X, R->X);
        fp2copy751(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A, C);
    j_inv(A, C, jinv);
    from_fp2mont(jinv, (felm_t*)SharedSecretB);      // Converting back to standard representation

// Cleanup:
    clear_words((void*)R, 2*2*pwords);
    clear_words((void*)pts, MAX_INT_POINTS_BOB*2*2*pwords);
    clear_words((void*)A, 2*pwords);
    clear_words((void*)C, 2*pwords);
    clear_words((void*)jinv, 2*pwords);

    return Status;
}

CRYPTO_STATUS SecretAgreement_B(unsigned char* pPrivateKeyB, unsigned char* pPublicKeyA, unsigned char* pSharedSecretB, PCurveIsogenyStruct CurveIsogeny, point_proj_t kerngen, point_proj_t extractpoint, batch_struct* batch)
{ // Bob's shared secret generation
  // It produces a shared secret key pSharedSecretB using his secret key pPrivateKeyB and Alice's public key pPublicKeyA
  // Inputs: Bob's pPrivateKeyB is an integer in the range [1, oB-1], where oA = 3^239 (i.e., 379 bits in total).
  //         Alice's pPublicKeyA consists of 4 elements in GF(p751^2), i.e., 751 bytes in total.
  // Output: a shared secret pSharedSecretB that consists of one element in GF(p751^2), i.e., 1502 bits in total.
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0;
    point_proj_t R, pts[MAX_INT_POINTS_BOB];
    publickey_t* PublicKeyA = (publickey_t*)pPublicKeyA;
    f2elm_t jinv, A, C = {0}, PKA2, PKA3, PKA4;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;

//modified
    if (kerngen == NULL) {

        if (pPrivateKeyB == NULL || pPublicKeyA == NULL || pSharedSecretB == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
            return CRYPTO_ERROR_INVALID_PARAMETER;
        }
    }

    to_fp2mont(((f2elm_t*)PublicKeyA)[0], A);         // Extracting and converting Alice's public curve parameters to Montgomery representation
    to_fp2mont(((f2elm_t*)PublicKeyA)[1], PKA2);
    to_fp2mont(((f2elm_t*)PublicKeyA)[2], PKA3);
    to_fp2mont(((f2elm_t*)PublicKeyA)[3], PKA4);

    fpcopy751(CurveIsogeny->C, C[0]);
    to_mont(C[0], C[0]);

		//will probably need an additional parameter flag for compressed signatures, to determine the order of compressed psiS by some other means
    if (kerngen == NULL) {
        Status = ladder_3_pt(PKA2, PKA3, PKA4, (digit_t*)pPrivateKeyB, BOB, R, A, CurveIsogeny);
        if (Status != CRYPTO_SUCCESS) {
            return Status;
        }

// modified
        if (extractpoint != NULL) {
            fp2copy751(R->X, extractpoint->X);
            fp2copy751(R->Z, extractpoint->Z);
        }
    } else {
        fp2copy751(kerngen->X, R->X);
        fp2copy751(kerngen->Z, R->Z);
    }

    index = 0;
    for (row = 1; row < MAX_Bob; row++) {
        while (index < MAX_Bob-row) {
            fp2copy751(R->X, pts[npts]->X);
            fp2copy751(R->Z, pts[npts]->Z);
            pts_index[npts] = index;
            npts += 1;
            m = splits_Bob[MAX_Bob-index-row];
            xTPLe(R, R, A, C, (int)m);
            index += m;
        }
        get_3_isog(R, A, C);

        for (i = 0; i < npts; i++) {
            eval_3_isog(R, pts[i]);
        }

        fp2copy751(pts[npts-1]->X, R->X);
        fp2copy751(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A, C);

		if (batch != NULL) {
			j_inv_batch(A, C, jinv, batch);
		} else {
			j_inv(A, C, jinv);
		}

    from_fp2mont(jinv, (felm_t*)pSharedSecretB);      // Converting back to standard representation

// Cleanup:
    clear_words((void*)R, 2*2*pwords);
    clear_words((void*)pts, MAX_INT_POINTS_BOB*2*2*pwords);
    clear_words((void*)A, 2*pwords);
    clear_words((void*)C, 2*pwords);
    clear_words((void*)jinv, 2*pwords);

    return Status;
}

///////////////////////////////////////////////////////////////////////////////////
///////////////          KEY EXCHANGE USING DECOMPRESSION           ///////////////

void PublicKeyCompression_A(const unsigned char* PublicKeyA, unsigned char* CompressedPKA, PCurveIsogenyStruct CurveIsogeny)
{ // Alice's public key compression
  // It produces a compressed output that consists of three elements in Z_orderB and one field element
  // Input : Alice's public key PublicKeyA, which consists of 3 elements in GF(p751^2).
  // Output: a compressed value CompressedPKA that consists of three elements in Z_orderB and one element in GF(p751^2).
  // CurveIsogeny must be set up in advance using SIDH_curve_initializ().
    point_full_proj_t P, Q, phP, phQ, phX;
    point_t R1, R2, phiP, phiQ;
    publickey_t PK;
    digit_t* comp = (digit_t*)CompressedPKA;
    digit_t inv[NWORDS_ORDER];
    f2elm_t A, vec[4], Zinv[4];
    digit_t a0[NWORDS_ORDER], b0[NWORDS_ORDER], a1[NWORDS_ORDER], b1[NWORDS_ORDER];
    uint64_t Montgomery_Rprime[NWORDS64_ORDER] = {0x1A55482318541298, 0x070A6370DFA12A03, 0xCB1658E0E3823A40, 0xB3B7384EB5DEF3F9, 0xCBCA952F7006EA33, 0x00569EF8EC94864C}; // Value (2^384)^2 mod 3^239
    uint64_t Montgomery_rprime[NWORDS64_ORDER] = {0x48062A91D3AB563D, 0x6CE572751303C2F5, 0x5D1319F3F160EC9D, 0xE35554E8C2D5623A, 0xCA29300232BC79A5, 0x8AAD843D646D78C5}; // Value -(3^239)^-1 mod 2^384
    unsigned int bit;

    to_fp2mont(((f2elm_t*)PublicKeyA)[0], ((f2elm_t*)&PK)[0]);    // Converting to Montgomery representation
    to_fp2mont(((f2elm_t*)PublicKeyA)[1], ((f2elm_t*)&PK)[1]);
    to_fp2mont(((f2elm_t*)PublicKeyA)[2], ((f2elm_t*)&PK)[2]);

    recover_y(PK, phP, phQ, phX, A, CurveIsogeny);
    generate_3_torsion_basis(A, P, Q, CurveIsogeny);
    fp2copy751(P->Z, vec[0]);
    fp2copy751(Q->Z, vec[1]);
    fp2copy751(phP->Z, vec[2]);
    fp2copy751(phQ->Z, vec[3]);
    mont_n_way_inv(vec, 4, Zinv);

    fp2mul751_mont(P->X, Zinv[0], R1->x);
    fp2mul751_mont(P->Y, Zinv[0], R1->y);
    fp2mul751_mont(Q->X, Zinv[1], R2->x);
    fp2mul751_mont(Q->Y, Zinv[1], R2->y);
    fp2mul751_mont(phP->X, Zinv[2], phiP->x);
    fp2mul751_mont(phP->Y, Zinv[2], phiP->y);
    fp2mul751_mont(phQ->X, Zinv[3], phiQ->x);
    fp2mul751_mont(phQ->Y, Zinv[3], phiQ->y);

    ph3(phiP, phiQ, R1, R2, A, (uint64_t*)a0, (uint64_t*)b0, (uint64_t*)a1, (uint64_t*)b1, CurveIsogeny);

    bit = mod3(a0);
    to_Montgomery_mod_order(a0, a0, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);    // Converting to Montgomery representation
    to_Montgomery_mod_order(a1, a1, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
    to_Montgomery_mod_order(b0, b0, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
    to_Montgomery_mod_order(b1, b1, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);

    if (bit != 0) {  // Storing [b1*a0inv, a1*a0inv, b0*a0inv] and setting bit384 to 0
        Montgomery_inversion_mod_order_bingcd(a0, inv, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
        Montgomery_multiply_mod_order(b0, inv, &comp[0], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        Montgomery_multiply_mod_order(a1, inv, &comp[NWORDS_ORDER], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        Montgomery_multiply_mod_order(b1, inv, &comp[2*NWORDS_ORDER], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        from_Montgomery_mod_order(&comp[0], &comp[0], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);                           // Converting back from Montgomery representation
        from_Montgomery_mod_order(&comp[NWORDS_ORDER], &comp[NWORDS_ORDER], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        from_Montgomery_mod_order(&comp[2*NWORDS_ORDER], &comp[2*NWORDS_ORDER], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        comp[3*NWORDS_ORDER-1] &= (digit_t)(-1) >> 1;
    } else {  // Storing [b1*b0inv, a1*b0inv, a0*b0inv] and setting bit384 to 1
        Montgomery_inversion_mod_order_bingcd(b0, inv, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
        Montgomery_multiply_mod_order(a0, inv, &comp[0], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        Montgomery_multiply_mod_order(a1, inv, &comp[NWORDS_ORDER], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        Montgomery_multiply_mod_order(b1, inv, &comp[2*NWORDS_ORDER], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        from_Montgomery_mod_order(&comp[0], &comp[0], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);                           // Converting back from Montgomery representation
        from_Montgomery_mod_order(&comp[NWORDS_ORDER], &comp[NWORDS_ORDER], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        from_Montgomery_mod_order(&comp[2*NWORDS_ORDER], &comp[2*NWORDS_ORDER], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        comp[3*NWORDS_ORDER-1] |= (digit_t)1 << (sizeof(digit_t)*8 - 1);
    }

    from_fp2mont(A, (felm_t*)&comp[3*NWORDS_ORDER]);
}


void PublicKeyADecompression_B(const unsigned char* SecretKeyB, const unsigned char* CompressedPKA, unsigned char* point_R, unsigned char* param_A, PCurveIsogenyStruct CurveIsogeny)
{ // Alice's public key value decompression computed by Bob
  // Inputs: Bob's private key SecretKeyB, and
  //         Alice's compressed public key data CompressedPKA, which consists of three elements in Z_orderB and one element in GF(p751^2),
  // Output: a point point_R in coordinates (X:Z) and the curve parameter param_A in GF(p751^2). Outputs are stored in Montgomery representation.
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    point_t R1, R2;
    point_proj_t* R = (point_proj_t*)point_R;
    point_full_proj_t P, Q;
    digit_t* comp = (digit_t*)CompressedPKA;
    digit_t* SKin = (digit_t*)SecretKeyB;
    f2elm_t A24, vec[2], invs[2], one = {0};
    felm_t* A = (felm_t*)param_A;
    digit_t t1[NWORDS_ORDER], t2[NWORDS_ORDER], t3[NWORDS_ORDER], t4[NWORDS_ORDER], vone[NWORDS_ORDER] = {0};
    uint64_t Montgomery_Rprime[NWORDS64_ORDER] = {0x1A55482318541298, 0x070A6370DFA12A03, 0xCB1658E0E3823A40, 0xB3B7384EB5DEF3F9, 0xCBCA952F7006EA33, 0x00569EF8EC94864C}; // Value (2^384)^2 mod 3^239
    uint64_t Montgomery_rprime[NWORDS64_ORDER] = {0x48062A91D3AB563D, 0x6CE572751303C2F5, 0x5D1319F3F160EC9D, 0xE35554E8C2D5623A, 0xCA29300232BC79A5, 0x8AAD843D646D78C5}; // Value -(3^239)^-1 mod 2^384
    unsigned int bit;

    vone[0] = 1;
    to_Montgomery_mod_order(vone, vone, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);  // Converting to Montgomery representation
    fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
    to_fp2mont((felm_t*)&comp[3*NWORDS_ORDER], A);    // Converting to Montgomery representation
    generate_3_torsion_basis(A, P, Q, CurveIsogeny);

    // Normalize basis points
    fp2copy751(P->Z, vec[0]);
    fp2copy751(Q->Z, vec[1]);
    mont_n_way_inv(vec, 2, invs);
    fp2mul751_mont(P->X, invs[0], R1->x);
    fp2mul751_mont(P->Y, invs[0], R1->y);
    fp2mul751_mont(Q->X, invs[1], R2->x);
    fp2mul751_mont(Q->Y, invs[1], R2->y);

    fp2add751(A, one, A24);
    fp2add751(A24, one, A24);
    fp2div2_751(A24, A24);
    fp2div2_751(A24, A24);

    bit = comp[3*NWORDS_ORDER-1] >> (sizeof(digit_t)*8 - 1);
    comp[3*NWORDS_ORDER-1] &= (digit_t)(-1) >> 1;
    to_Montgomery_mod_order(SKin, t1, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);    // Converting to Montgomery representation
    to_Montgomery_mod_order(&comp[0], t2, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
    to_Montgomery_mod_order(&comp[NWORDS_ORDER], t3, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
    to_Montgomery_mod_order(&comp[2*NWORDS_ORDER], t4, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);

    if (bit == 0) {
        Montgomery_multiply_mod_order(t1, t3, t3, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        mp_add(t3, vone, t3, NWORDS_ORDER);
        Montgomery_inversion_mod_order_bingcd(t3, t3, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
        Montgomery_multiply_mod_order(t1, t4, t4, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        mp_add(t2, t4, t4, NWORDS_ORDER);
        Montgomery_multiply_mod_order(t3, t4, t3, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        from_Montgomery_mod_order(t3, t3, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);    // Converting back from Montgomery representation
        mont_twodim_scalarmult(t3, R1, R2, A, A24, P, CurveIsogeny);
    } else {
        Montgomery_multiply_mod_order(t1, t4, t4, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        mp_add(t4, vone, t4, NWORDS_ORDER);
        Montgomery_inversion_mod_order_bingcd(t4, t4, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
        Montgomery_multiply_mod_order(t1, t3, t3, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        mp_add(t2, t3, t3, NWORDS_ORDER);
        Montgomery_multiply_mod_order(t3, t4, t3, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
        from_Montgomery_mod_order(t3, t3, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);    // Converting back from Montgomery representation
        mont_twodim_scalarmult(t3, R2, R1, A, A24, P, CurveIsogeny);
    }

    fp2copy751(P->X, R[0]->X);
    fp2copy751(P->Z, R[0]->Z);
}


CRYPTO_STATUS EphemeralSecretAgreement_Compression_A(const unsigned char* PrivateKeyA, const unsigned char* point_R, const unsigned char* param_A, unsigned char* SharedSecretA, PCurveIsogenyStruct CurveIsogeny)
{ // Alice's ephemeral shared secret computation
  // It produces a shared secret key SharedSecretA using her secret key PrivateKeyA and Bob's decompressed data point_R and param_A
  // Inputs: Alice's PrivateKeyA is an even integer in the range [2, oA-2], where oA = 2^372.
  //         Bob's decompressed data consists of point_R in (X:Z) coordinates and the curve paramater param_A in GF(p751^2).
  // Output: a shared secret SharedSecretA that consists of one element in GF(p751^2).
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0;
    point_proj_t R, pts[MAX_INT_POINTS_ALICE];
    f2elm_t jinv, coeff[5], A, C = {0};

    if (PrivateKeyA == NULL || SharedSecretA == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    fp2copy751((((point_proj_t*)point_R)[0])->X, R->X);
    fp2copy751((((point_proj_t*)point_R)[0])->Z, R->Z);
    fpcopy751(CurveIsogeny->C, C[0]);
    to_mont(C[0], C[0]);
    first_4_isog(R, (felm_t*)param_A, A, C, CurveIsogeny);

    index = 0;
    for (row = 1; row < MAX_Alice; row++) {
        while (index < MAX_Alice-row) {
            fp2copy751(R->X, pts[npts]->X);
            fp2copy751(R->Z, pts[npts]->Z);
            pts_index[npts] = index;
            npts += 1;
            m = splits_Alice[MAX_Alice-index-row];
            xDBLe(R, R, A, C, (int)(2*m));
            index += m;
        }
        get_4_isog(R, A, C, coeff);

        for (i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }

        fp2copy751(pts[npts-1]->X, R->X);
        fp2copy751(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A, C, coeff);
    j_inv(A, C, jinv);
    from_fp2mont(jinv, (felm_t*)SharedSecretA);      // Converting back to standard representation

// Cleanup:
    clear_words((void*)R, 2*2*pwords);
    clear_words((void*)pts, MAX_INT_POINTS_ALICE*2*2*pwords);
    clear_words((void*)A, 2*pwords);
    clear_words((void*)C, 2*pwords);
    clear_words((void*)jinv, 2*pwords);
    clear_words((void*)coeff, 5*2*pwords);

    return CRYPTO_SUCCESS;
}


void PublicKeyCompression_B(const unsigned char* PublicKeyB, unsigned char* CompressedPKB, PCurveIsogenyStruct CurveIsogeny)
{ // Bob's public key compression
  // It produces a compressed output that consists of three elements in Z_orderA and one field element
  // Input : Bob's public key PublicKeyB, which consists of 3 elements in GF(p751^2).
  // Output: a compressed value CompressedPKB that consists of three elements in Z_orderA and one element in GF(p751^2).
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
  point_full_proj_t P, Q, phP, phQ, phX;
  point_t R1, R2, phiP, phiQ;
  publickey_t PK;digit_t* comp = (digit_t*)CompressedPKB;
  digit_t inv[NWORDS_ORDER];
  f2elm_t A, vec[4], Zinv[4];
  digit_t a0[NWORDS_ORDER], b0[NWORDS_ORDER], a1[NWORDS_ORDER], b1[NWORDS_ORDER], tmp[2*NWORDS_ORDER], mask = (digit_t)(-1);

	mask >>= (CurveIsogeny->owordbits - CurveIsogeny->oAbits);
	to_fp2mont(((f2elm_t*)PublicKeyB)[0], ((f2elm_t*)&PK)[0]);    // Converting to Montgomery representation
	to_fp2mont(((f2elm_t*)PublicKeyB)[1], ((f2elm_t*)&PK)[1]);
	to_fp2mont(((f2elm_t*)PublicKeyB)[2], ((f2elm_t*)&PK)[2]);

	recover_y(PK, phP, phQ, phX, A, CurveIsogeny);
	generate_2_torsion_basis(A, P, Q, CurveIsogeny);
	fp2copy751(P->Z, vec[0]);
	fp2copy751(Q->Z, vec[1]);
	fp2copy751(phP->Z, vec[2]);
	fp2copy751(phQ->Z, vec[3]);
	mont_n_way_inv(vec, 4, Zinv);

	fp2mul751_mont(P->X, Zinv[0], R1->x);
	fp2mul751_mont(P->Y, Zinv[0], R1->y);
	fp2mul751_mont(Q->X, Zinv[1], R2->x);
	fp2mul751_mont(Q->Y, Zinv[1], R2->y);
	fp2mul751_mont(phP->X, Zinv[2], phiP->x);
	fp2mul751_mont(phP->Y, Zinv[2], phiP->y);
	fp2mul751_mont(phQ->X, Zinv[3], phiQ->x);
	fp2mul751_mont(phQ->Y, Zinv[3], phiQ->y);

	ph2(phiP, phiQ, R1, R2, A, (uint64_t*)a0, (uint64_t*)b0, (uint64_t*)a1, (uint64_t*)b1, CurveIsogeny);

	if ((a0[0] & 1) == 1) {  // Storing [b1*a0inv, a1*a0inv, b0*a0inv] and setting bit384 to 0
		inv_mod_orderA(a0, inv);
		multiply(b0, inv, tmp, NWORDS_ORDER);
		copy_words(tmp, &comp[0], NWORDS_ORDER);
		comp[NWORDS_ORDER-1] &= mask;
		multiply(a1, inv, tmp, NWORDS_ORDER);
		copy_words(tmp, &comp[NWORDS_ORDER], NWORDS_ORDER);
		comp[2*NWORDS_ORDER-1] &= mask;
		multiply(b1, inv, tmp, NWORDS_ORDER);
		copy_words(tmp, &comp[2 * NWORDS_ORDER], NWORDS_ORDER);
		comp[3*NWORDS_ORDER-1] &= mask;
    } else {  // Storing [b1*b0inv, a1*b0inv, a0*b0inv] and setting bit384 to 1
		inv_mod_orderA(b0, inv);
		multiply(a0, inv, tmp, NWORDS_ORDER);
		copy_words(tmp, &comp[0], NWORDS_ORDER);
		comp[NWORDS_ORDER - 1] &= mask;
		multiply(a1, inv, tmp, NWORDS_ORDER);
		copy_words(tmp, &comp[NWORDS_ORDER], NWORDS_ORDER);
		comp[2*NWORDS_ORDER-1] &= mask;
		multiply(b1, inv, tmp, NWORDS_ORDER);
		copy_words(tmp, &comp[2 * NWORDS_ORDER], NWORDS_ORDER);
		comp[3*NWORDS_ORDER-1] &= mask;
		comp[3*NWORDS_ORDER-1] |= (digit_t)1 << (sizeof(digit_t)*8 - 1);
	}

	from_fp2mont(A, (felm_t*)&comp[3*NWORDS_ORDER]);  // Converting back from Montgomery representation
}


void PublicKeyBDecompression_A(const unsigned char* SecretKeyA, const unsigned char* CompressedPKB, unsigned char* point_R, unsigned char* param_A, PCurveIsogenyStruct CurveIsogeny)
{ // Bob's public key value decompression computed by Alice
  // Inputs: Alice's private key SecretKeyA, and
  //         Bob's compressed public key data CompressedPKB, which consists of three elements in Z_orderA and one element in GF(p751^2).
  // Output: a point point_R in coordinates (X:Z) and the curve parameter param_A in GF(p751^2). Outputs are stored in Montgomery representation.
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    point_t R1, R2;
    point_proj_t* R = (point_proj_t*)point_R;
    point_full_proj_t P, Q;
    digit_t* comp = (digit_t*)CompressedPKB;
    f2elm_t A24, vec[2], invs[2], one = {0};
    felm_t* A = (felm_t*)param_A;
    digit_t tmp1[2*NWORDS_ORDER], tmp2[2*NWORDS_ORDER], vone[2*NWORDS_ORDER] = {0}, mask = (digit_t)(-1);
    unsigned int bit;

    mask >>= (CurveIsogeny->owordbits - CurveIsogeny->oAbits);
    vone[0] = 1;
    fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
    to_fp2mont((felm_t*)&comp[3*NWORDS_ORDER], A);    // Converting to Montgomery representation
    generate_2_torsion_basis(A, P, Q, CurveIsogeny);

    // normalize basis points
    fp2copy751(P->Z, vec[0]);
    fp2copy751(Q->Z, vec[1]);
    mont_n_way_inv(vec, 2, invs);
    fp2mul751_mont(P->X, invs[0], R1->x);
    fp2mul751_mont(P->Y, invs[0], R1->y);
    fp2mul751_mont(Q->X, invs[1], R2->x);
    fp2mul751_mont(Q->Y, invs[1], R2->y);

    fp2add751(A, one, A24);
    fp2add751(A24, one, A24);
    fp2div2_751(A24, A24);
    fp2div2_751(A24, A24);

    bit = comp[3*NWORDS_ORDER-1] >> (sizeof(digit_t)*8 - 1);
    comp[3*NWORDS_ORDER-1] &= (digit_t)(-1) >> 1;

    if (bit == 0) {
		multiply((digit_t*)SecretKeyA, &comp[NWORDS_ORDER], tmp1, NWORDS_ORDER);
		mp_add(tmp1, vone, tmp1, NWORDS_ORDER);
		tmp1[NWORDS_ORDER-1] &= mask;
		inv_mod_orderA(tmp1, tmp2);
		multiply((digit_t*)SecretKeyA, &comp[2*NWORDS_ORDER], tmp1, NWORDS_ORDER);
		mp_add(&comp[0], tmp1, tmp1, NWORDS_ORDER);
		multiply(tmp1, tmp2, vone, NWORDS_ORDER);
		vone[NWORDS_ORDER-1] &= mask;
		mont_twodim_scalarmult(vone, R1, R2, A, A24, P, CurveIsogeny);
	} else {
		multiply((digit_t*)SecretKeyA, &comp[2*NWORDS_ORDER], tmp1, NWORDS_ORDER);
		mp_add(tmp1, vone, tmp1, NWORDS_ORDER);
		tmp1[NWORDS_ORDER-1] &= mask;
		inv_mod_orderA(tmp1, tmp2);
		multiply((digit_t*)SecretKeyA, &comp[NWORDS_ORDER], tmp1, NWORDS_ORDER);
		mp_add(&comp[0], tmp1, tmp1, NWORDS_ORDER);
		multiply(tmp1, tmp2, vone, NWORDS_ORDER);
		vone[NWORDS_ORDER-1] &= mask;
		mont_twodim_scalarmult(vone, R2, R1, A, A24, P, CurveIsogeny);
	}

	fp2copy751(P->X, R[0]->X);
	fp2copy751(P->Z, R[0]->Z);
}


CRYPTO_STATUS EphemeralSecretAgreement_Compression_B(const unsigned char* PrivateKeyB, const unsigned char* point_R, const unsigned char* param_A, unsigned char* SharedSecretB, PCurveIsogenyStruct CurveIsogeny)
{ // Bob's ephemeral shared secret computation
  // It produces a shared secret key SharedSecretB using his secret key PrivateKeyB and Alice's decompressed data point_R and param_A
  // Inputs: Bob's PrivateKeyB is an integer in the range [1, oB-1], where oB = 3^239.
  //         Alice's decompressed data consists of point_R in (X:Z) coordinates and the curve paramater param_A in GF(p751^2).
  // Output: a shared secret SharedSecretB that consists of one element in GF(p751^2).
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    unsigned int pwords = NBITS_TO_NWORDS(CurveIsogeny->pwordbits);
    unsigned int i, row, m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0;
    point_proj_t R, pts[MAX_INT_POINTS_BOB];
    f2elm_t jinv, A, C = {0};

    if (PrivateKeyB == NULL || SharedSecretB == NULL || is_CurveIsogenyStruct_null(CurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    fp2copy751((((point_proj_t*)point_R)[0])->X, R->X);
    fp2copy751((((point_proj_t*)point_R)[0])->Z, R->Z);
    fp2copy751((felm_t*)param_A, A);
    fpcopy751(CurveIsogeny->C, C[0]);
    to_mont(C[0], C[0]);

    index = 0;
    for (row = 1; row < MAX_Bob; row++) {
        while (index < MAX_Bob-row) {
            fp2copy751(R->X, pts[npts]->X);
            fp2copy751(R->Z, pts[npts]->Z);
            pts_index[npts] = index;
            npts += 1;
            m = splits_Bob[MAX_Bob-index-row];
            xTPLe(R, R, A, C, (int)m);
            index += m;
        }
        get_3_isog(R, A, C);

        for (i = 0; i < npts; i++) {
            eval_3_isog(R, pts[i]);
        }

        fp2copy751(pts[npts-1]->X, R->X);
        fp2copy751(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A, C);
    j_inv(A, C, jinv);
    from_fp2mont(jinv, (felm_t*)SharedSecretB);      // Converting back to standard representation

// Cleanup:
    clear_words((void*)R, 2*2*pwords);
    clear_words((void*)pts, MAX_INT_POINTS_BOB*2*2*pwords);
    clear_words((void*)A, 2*pwords);
    clear_words((void*)C, 2*pwords);
    clear_words((void*)jinv, 2*pwords);

    return CRYPTO_SUCCESS;
}

static void print_digit(digit_t d) {
  unsigned char *c = (unsigned char *) &d;
  for (int i = sizeof(digit_t) - 1; i >= 0; i--) {
    printf("%02X", c[i]);
  }
}

static void print_digit_order(digit_t* d, int order) {
  printf("Fborder![0x");
  for (int i = order - 1; i >= 0; i--) {
    print_digit(d[i]);
  }
  printf("];");
}

static void print_felm(felm_t f) {
  printf("Fp![0x");
  for (int i = NWORDS_FIELD - 1; i >= 0; i--) {
    print_digit(f[i]);
  }
  printf("]");
}

static void print_f2elm(f2elm_t f2) {
  printf("");
  print_felm(f2[0]);
  printf(" + ");
  print_felm(f2[1]);
  printf("*i;");
}

static void printf_digit_order(char *s, digit_t* d, int order) {
  printf("%s := ", s);
  print_digit_order(d, order);
  printf("\n");
}

static void printf_f2elm(char *s, f2elm_t f2) {
  printf("%s := ", s);
  print_f2elm(f2);
  printf("\n");
}

///////////////////////////////////////////////////////////////////////////////////
///////////////             COMPRESSION FOR SIGNATURES              ///////////////

CRYPTO_STATUS compressPsiS(const point_proj* psiS, unsigned char* CompressedPsiS, int* compBit, const f2elm_t A, PCurveIsogenyStruct CurveIsogeny, batch_struct* batch) {
// Inputs:  psiS - a point in projective coordinates - computed by SecretAgreementB
//          A - f2elm in montgomery form - the A value for the signers curve
//          CurveIsogeny - SIDHp751
// Outputs: CompressedPsiS - f2elm in subgroub E[3^239] - ainv*b or binv*a
//          compBit - a bit signifying if ainv*b (0) or binv*a (1) was computed

	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	point_full_proj_t P, Q;
	point_proj_t Pnot, Qnot, psiSTriple;
	point_t psiSa, notPsiSa, R1, R2;
	point_t R1not, R2not;
	digit_t *comp = CompressedPsiS;
	f2elm_t vec[3], Zinv[3];
	f2elm_t A_temp, A24;
	digit_t a[NWORDS_ORDER], b[NWORDS_ORDER], anot[NWORDS_ORDER], bnot[NWORDS_ORDER], anot2[NWORDS_ORDER], bnot2[NWORDS_ORDER];  //for pohlig-hellman results
	digit_t inv[NWORDS_ORDER];                 //for storing the inverse of alpha
	uint64_t Montgomery_Rprime[NWORDS64_ORDER] = {0x1A55482318541298, 0x070A6370DFA12A03, 0xCB1658E0E3823A40, 0xB3B7384EB5DEF3F9, 0xCBCA952F7006EA33, 0x00569EF8EC94864C}; // Value (2^384)^2 mod 3^239
	uint64_t Montgomery_rprime[NWORDS64_ORDER] = {0x48062A91D3AB563D, 0x6CE572751303C2F5, 0x5D1319F3F160EC9D, 0xE35554E8C2D5623A, 0xCA29300232BC79A5, 0x8AAD843D646D78C5}; // Value -(3^239)^-1 mod 2^384
	unsigned int bita, bitb;
	f2elm_t tmp, tmp2, t, inf, one = {0};
	int error;
	fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
	fp2copy751(A, A_temp);

	// check that psi(S) has full order -----------------------------------//
	copy_words((digit_t*)psiS, (digit_t*)psiSTriple, 2*2*NWORDS_FIELD);
	for (int i=0; i < 238; i++) {
		xTPL(psiSTriple, psiSTriple, A_temp, CurveIsogeny->C);

		if (is_felm_zero(((felm_t*)psiSTriple->Z)[0]) && is_felm_zero(((felm_t*)psiSTriple->Z)[1])) {
      #ifdef TEST_RUN_PRINTS
      printf ("Error: order of psi(S) falls short of 3^239\n");
      #endif
			return CRYPTO_ERROR_INVALID_ORDER;
		}
	}
	//---------------------------------------------------------------------//

	// generate projective basis {P, Q} generating E[3^239] which gives affine basis {R1, R2} //
	generate_3_torsion_basis(A_temp, P, Q, CurveIsogeny);

	// check that P and Q have full order ----------------------------------------------//
	fp2copy751(P->X, Pnot->X);
	fp2copy751(P->Z, Pnot->Z);
	fp2copy751(Q->X, Qnot->X);
	fp2copy751(Q->Z, Qnot->Z);
	for (int i=0; i < 238; i++) {
		xTPL(Pnot, Pnot, A, CurveIsogeny->C);
		xTPL(Qnot, Qnot, A, CurveIsogeny->C);

		if (is_felm_zero(((felm_t*)Pnot->Z)[0]) && is_felm_zero(((felm_t*)Pnot->Z)[1])) {
      #ifdef TEST_RUN_PRINTS
      printf ("Error: order of P falls short of 3^239\n");
      #endif
			error++;
		}
		if (is_felm_zero(((felm_t*)Qnot->Z)[0]) && is_felm_zero(((felm_t*)Qnot->Z)[1])) {
      #ifdef TEST_RUN_PRINTS
      printf ("Error: order of Q falls short of 3^239\n");
      #endif
			error++;
		}
		if (error) {
			return CRYPTO_ERROR_INVALID_ORDER;
		}
	}
	//----------------------------------------------------------------------------------//

	// convert P, Q, and psiS to affine coordinates -//
	fp2copy751(P->Z, vec[0]);
	fp2copy751(Q->Z, vec[1]);
	fp2copy751(psiS->Z, vec[2]);

	mont_n_way_inv(vec, 3, Zinv);

	fp2mul751_mont(P->X, Zinv[0], R1->x);
	fp2mul751_mont(P->Y, Zinv[0], R1->y);
	fp2mul751_mont(Q->X, Zinv[1], R2->x);
	fp2mul751_mont(Q->Y, Zinv[1], R2->y);

	fp2mul751_mont(psiS->X, Zinv[2], psiSa->x);

	fp2mul751_mont(psiSa->x, psiSa->x, tmp);
	fp2mul751_mont(tmp, psiSa->x, tmp2);
	fp2mul751_mont(tmp, A_temp, tmp);
	fp2add751(tmp, tmp2, tmp);
	fp2add751(tmp, psiSa->x, tmp);
	sqrt_Fp2(tmp, psiSa->y);
	fp2neg751(psiSa->y);
	//-----------------------------------------------//

  from_fp2mont(psiSa->x, psiSa->x);
  from_fp2mont(psiSa->y, psiSa->y);
  from_fp2mont(A_temp, A_temp);

	// do polleg-hellman to find a and b -------------------------------------//
	half_ph3(psiSa, R1, R2, A_temp, (uint64_t*)a, (uint64_t*)b, CurveIsogeny);
	// check validity of half_ph3 compared to ph3 ----------------------------//
	//fp2copy751(psiSa->x, notPsiSa->x);
	//fp2copy751(psiSa->y, notPsiSa->y);
	//ph3(psiSa, notPsiSa, R1, R2, A_temp, (uint64_t*)anot, (uint64_t*)bnot, (uint64_t*)anot2, (uint64_t*)bnot2, CurveIsogeny);
	//int cmpA = memcmp(a, anot, NWORDS_ORDER*sizeof(digit_t));
	//int cmpB = memcmp(b, bnot, NWORDS_ORDER*sizeof(digit_t));
	//if (cmpA != 0 && cmpB != 0) {
		//return CRYPTO_ERROR_DURING_TEST;
	//}

	// compute ainv*b or binv*a depending on which element is divisible by 3 ----------------------------------------------------------//
#ifdef COMP_PSIS_PRINTS
  from_fp2mont(R1->x, R1->x);
  from_fp2mont(R1->y, R1->y);
  from_fp2mont(R2->x, R2->x);
  from_fp2mont(R2->y, R2->y);

  printf_f2elm("A", A_temp);
  printf_f2elm("psiSx", psiSa->x);
  printf_f2elm("psiSy", psiSa->y);
  printf_f2elm("R1x", R1->x);
  printf_f2elm("R1y", R1->y);
  printf_f2elm("R2x", R2->x);
  printf_f2elm("R2y", R2->y);
  printf_digit_order("a", a, NWORDS_ORDER);
  printf_digit_order("b", b, NWORDS_ORDER);

  to_fp2mont(R1->x, R1->x);
  to_fp2mont(R1->y, R1->y);
  to_fp2mont(R2->x, R2->x);
  to_fp2mont(R2->y, R2->y);
#endif

  to_fp2mont(psiSa->x, psiSa->x);
  to_fp2mont(psiSa->y, psiSa->y);
  to_fp2mont(A_temp, A_temp);

	bita = mod3(a);
	bitb = mod3(b);

	if (bita == 0 && bitb == 0) {
    #ifdef TEST_RUN_PRINTS
		printf("Both a and b of order of 3\n");
    #endif
		return CRYPTO_ERROR_INVALID_ORDER;
	}

	to_Montgomery_mod_order(a, a, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
	to_Montgomery_mod_order(b, b, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);

	if (bita != 0) {
		*compBit = 0;
		Montgomery_inversion_mod_order_bingcd(a, inv, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
		Montgomery_multiply_mod_order(b, inv, &comp[0], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
		from_Montgomery_mod_order(&comp[0], &comp[0], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
	} else {
		*compBit = 1;
		Montgomery_inversion_mod_order_bingcd(b, inv, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime, (digit_t*)&Montgomery_Rprime);
		Montgomery_multiply_mod_order(a, inv, &comp[0], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
		from_Montgomery_mod_order(&comp[0], &comp[0], CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);
	}
	//---------------------------------------------------------------------------------------------------------------------------------//

	// make sure comp has order 3 -------//
	bita = mod3(comp);
	if (bita != 0) {
		return CRYPTO_ERROR_INVALID_ORDER;
	}
	//-----------------------------------//

	return Status;
}

CRYPTO_STATUS decompressPsiS(const unsigned char* CompressedPsiS, point_proj* S, int compBit, const f2elm_t A, PCurveIsogenyStruct CurveIsogeny) {
// Inputs:  CompressedPsiS: x s.t. psi(S) = R1 + [x]R2 or psi(S) = [x]R1 + R2
//          CurveIsogeny - SIDHp751
//          compBit - a bit signifying if ainv*b (0) or binv*a (1) was computed
// Outputs: point S generating the same kernel as the original psi(S)
//
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;

	point_full_proj_t P, Q;                    //points used in the construction of {R1,R2}
	point_full_proj_t S_temp;
	point_proj_t temp1;
	point_proj_t Pnot, Qnot;
	point_t R1, R2;
	digit_t* comp = (digit_t*)CompressedPsiS;
	f2elm_t vec[2], Zinv[2];
	digit_t a[NWORDS_ORDER], b[NWORDS_ORDER];  //for pohlig-hellman results
	digit_t inv[NWORDS_ORDER];                 //for storing the inverse of alpha
	uint64_t Montgomery_Rprime[NWORDS64_ORDER] = {0x1A55482318541298, 0x070A6370DFA12A03, 0xCB1658E0E3823A40, 0xB3B7384EB5DEF3F9, 0xCBCA952F7006EA33, 0x00569EF8EC94864C}; // Value (2^384)^2 mod 3^239
	uint64_t Montgomery_rprime[NWORDS64_ORDER] = {0x48062A91D3AB563D, 0x6CE572751303C2F5, 0x5D1319F3F160EC9D, 0xE35554E8C2D5623A, 0xCA29300232BC79A5, 0x8AAD843D646D78C5}; // Value -(3^239)^-1 mod 2^384
	unsigned int bit;
	f2elm_t tmp, one = {0};
	f2elm_t A_temp, A24;
	int error;

	fp2copy751(A, A_temp);
	fpcopy751(CurveIsogeny->Montgomery_one, one[0]);
	to_fp2mont((felm_t*)comp, comp);

	// generate projective basis {P, Q} generating E[3^239] which gives affine basis {R1, R2} //
	generate_3_torsion_basis(A_temp, P, Q, CurveIsogeny);

	// check that P and Q have full order ----------------------------------------------//
	fp2copy751(P->X, Pnot->X);
	fp2copy751(P->Z, Pnot->Z);
	fp2copy751(Q->X, Qnot->X);
	fp2copy751(Q->Z, Qnot->Z);
	for (int i=0; i < 238; i++) {
		xTPL(Pnot, Pnot, A_temp, CurveIsogeny->C);
		xTPL(Qnot, Qnot, A_temp, CurveIsogeny->C);

		if (is_felm_zero(((felm_t*)Pnot->Z)[0]) && is_felm_zero(((felm_t*)Pnot->Z)[1])) {
      #ifdef TEST_RUN_PRINTS
      printf ("Error: order of P falls short of 3^239\n");
      #endif
			error++;
		}
		if (is_felm_zero(((felm_t*)Qnot->Z)[0]) && is_felm_zero(((felm_t*)Qnot->Z)[1])) {
      #ifdef TEST_RUN_PRINTS
      printf ("Error: order of Q falls short of 3^239\n");
      #endif
			error++;
		}
		if (error) {
			return CRYPTO_ERROR_INVALID_ORDER;
		}
	}
	//----------------------------------------------------------------------------------//

	fp2copy751(P->Z, vec[0]);
	fp2copy751(Q->Z, vec[1]);
	mont_n_way_inv(vec, 2, Zinv);

	fp2mul751_mont(P->X, Zinv[0], R1->x);
	fp2mul751_mont(P->Y, Zinv[0], R1->y);
	fp2mul751_mont(Q->X, Zinv[1], R2->x);
	fp2mul751_mont(Q->Y, Zinv[1], R2->y);

	//construct (A+2)/4 from A
	fp2add751(A_temp, one, A24);
	fp2add751(A24, one, A24);
	fp2div2_751(A24, A24);
	fp2div2_751(A24, A24);

	//need to swap R1 and R2 in the following function call depending on the order of a in psi(S) = [a]R1 + [b]R2
	if (compBit) {
		mont_twodim_scalarmult(comp, R2, R1, A_temp, A24, S_temp, CurveIsogeny);
		//Status = ladder_3_pt(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xPQ, const digit_t* m, const unsigned int AliceOrBob, temp1, A_temp, CurveIsogeny);
	} else {
		mont_twodim_scalarmult(comp, R1, R2, A_temp, A24, S_temp, CurveIsogeny);
	}

#ifdef DECOMP_PSIS_PRINTS
  from_fp2mont(A_temp, A_temp);
  from_fp2mont(R1->x, R1->x);
  from_fp2mont(R1->y, R1->y);
  from_fp2mont(R2->x, R2->x);
  from_fp2mont(R2->y, R2->y);
  from_fp2mont(S_temp->X, S_temp->X);
  from_fp2mont(S_temp->Y, S_temp->Y);
  from_fp2mont(S_temp->Z, S_temp->Z);
  from_fp2mont((felm_t*)comp, comp);

  printf_f2elm("A", A_temp);

  printf_f2elm("R1.x", R1->x);
  printf_f2elm("R1.y", R1->y);
  printf_f2elm("R2.x", R2->x);
  printf_f2elm("R2.y", R2->y);
  printf_digit_order("comp", a, NWORDS_ORDER);
  printf("bit :=  %d\n", compBit);

  to_fp2mont(A_temp, A_temp);
  to_fp2mont(R1->x, R1->x);
  to_fp2mont(R1->y, R1->y);
  to_fp2mont(R2->x, R2->x);
  to_fp2mont(R2->y, R2->y);
  to_fp2mont(S_temp->X, S_temp->X);
  to_fp2mont(S_temp->Y, S_temp->Y);
  to_fp2mont(S_temp->Z, S_temp->Z);
  to_fp2mont((felm_t*)comp, comp);
#endif

	//from_Montgomery_mod_order(&comp, &comp, CurveIsogeny->Border, (digit_t*)&Montgomery_rprime);

	fp2copy751(S_temp->X, S->X);
	fp2copy751(S_temp->Z, S->Z);

	return Status;
}
