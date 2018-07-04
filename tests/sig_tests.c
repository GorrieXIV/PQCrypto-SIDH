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


CRYPTO_STATUS cryptotest_signature() {
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

	PCurveIsogenyStruct CurveIsogeny = {0};

	CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}

	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, &CurveIsogeny_SIDHp751);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	//generate signing keypair using KeyGeneration_B
	Status = isogeny_keygen(CurveIsogeny, PrivateKey, PublicKey);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE KEYGEN ........... SUCCESSFUL\n");
		#endif
	}

	//signing procedure
	Status = isogeny_sign(CurveIsogeny, PrivateKey, PublicKey, &sig, 0, 0);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE SIGN ............. SUCCESSFUL\n");
		#endif
	}

	//verifying procedure
	Status = isogeny_verify(CurveIsogeny, PublicKey, &sig, 0, 0);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE VERIFY ........... SUCCESSFUL\n");
		#endif
	}

cleanup:
		SIDH_curve_free(CurveIsogeny);
		free(PrivateKey);
		free(PublicKey);

	return Status;
}


CRYPTO_STATUS cryptotest_signature_batchedinv() {
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

	PCurveIsogenyStruct CurveIsogeny = {0};

	CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}

	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, &CurveIsogeny_SIDHp751);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	//generate signing keypair using KeyGeneration_B
	Status = isogeny_keygen(CurveIsogeny, PrivateKey, PublicKey);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE KEYGEN ..................... SUCCESSFUL\n");
		#endif
	}

	//signing procedure
	Status = isogeny_sign(CurveIsogeny, PrivateKey, PublicKey, &sig, 1, 0);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE SIGN (batched) ............. SUCCESSFUL\n");
		#endif
	}

	//verifying procedure
	Status = isogeny_verify(CurveIsogeny, PublicKey, &sig, 1, 0);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE VERIFY (batched) ........... SUCCESSFUL\n");
		#endif
	}

cleanup:
		SIDH_curve_free(CurveIsogeny);
		free(PrivateKey);
		free(PublicKey);

	return Status;
}


CRYPTO_STATUS cryptotest_signature_compressed() {
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

	PCurveIsogenyStruct CurveIsogeny = {0};

	CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}

	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, &CurveIsogeny_SIDHp751);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	//generate signing keypair using KeyGeneration_B
	Status = isogeny_keygen(CurveIsogeny, PrivateKey, PublicKey);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE KEYGEN ........................ SUCCESSFUL\n");
		#endif
	}

	//signing procedure
	Status = isogeny_sign(CurveIsogeny, PrivateKey, PublicKey, &sig, 0, 1);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE SIGN (compressed) ............. SUCCESSFUL\n");
		#endif
	}

	//verifying procedure
	Status = isogeny_verify(CurveIsogeny, PublicKey, &sig, 0, 1);
	if (Status != CRYPTO_SUCCESS) {
		return Status;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("  SIGNATURE VERIFY (compressed) ........... SUCCESSFUL\n");
		#endif
	}

cleanup:
		SIDH_curve_free(CurveIsogeny);
		free(PrivateKey);
		free(PublicKey);

	return Status;
}


CRYPTO_STATUS cryptorun_signature() {
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

	PCurveIsogenyStruct CurveIsogeny = {0};

	CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}

	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, &CurveIsogeny_SIDHp751);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	#ifdef TEST_RUN_PRINTS
	printf("\n  BENCHMARKING ISOGENY-BASED SIGNATURE SCHEME \n");
	printf("  ---------------------------------------------------------\n");
	#endif

	cycles1 = cpucycles();
	Status = isogeny_keygen(CurveIsogeny, PrivateKey, PublicKey);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE KEYGEN RUNS IN ........... %10lld cycles\n", scycles);
	#endif

	cycles1 = cpucycles();
	Status = isogeny_sign(CurveIsogeny, PrivateKey, PublicKey, &sig, 0, 0);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE SIGN RUNS IN ............. %10lld cycles\n", scycles);
	#endif

	cycles1 = cpucycles();
	Status = isogeny_verify(CurveIsogeny, PublicKey, &sig, 0, 0);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE VERIFY RUNS IN ........... %10lld cycles\n", scycles);
	#endif

cleanup:
	SIDH_curve_free(CurveIsogeny);
	free(PrivateKey);
	free(PublicKey);

	return Status;

}


CRYPTO_STATUS cryptorun_signature_batchedinv() {
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

	PCurveIsogenyStruct CurveIsogeny = {0};

	CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}

	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, &CurveIsogeny_SIDHp751);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	#ifdef TEST_RUN_PRINTS
	printf("\n  BENCHMARKING ISOGENY-BASED SIGNATURE SCHEME \n");
	printf("  ---------------------------------------------------------\n");
	#endif

	cycles1 = cpucycles();
	Status = isogeny_keygen(CurveIsogeny, PrivateKey, PublicKey);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE KEYGEN RUNS IN ..................... %10lld cycles\n", scycles);
	#endif

	cycles1 = cpucycles();
	Status = isogeny_sign(CurveIsogeny, PrivateKey, PublicKey, &sig, 1, 0);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE SIGN (batched) RUNS IN ............. %10lld cycles\n", scycles);
	#endif

	cycles1 = cpucycles();
	Status = isogeny_verify(CurveIsogeny, PublicKey, &sig, 1, 0);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE VERIFY (batched) RUNS IN ........... %10lld cycles\n", scycles);
	#endif

cleanup:
	SIDH_curve_free(CurveIsogeny);
	free(PrivateKey);
	free(PublicKey);

	return Status;
}


CRYPTO_STATUS cryptorun_signature_compressed() {
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

	PCurveIsogenyStruct CurveIsogeny = {0};

	CurveIsogeny = SIDH_curve_allocate(&CurveIsogeny_SIDHp751);
	if (CurveIsogeny == NULL) {
		Status = CRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}

	Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, &CurveIsogeny_SIDHp751);
	if (Status != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	#ifdef TEST_RUN_PRINTS
	printf("\n  BENCHMARKING ISOGENY-BASED SIGNATURE SCHEME \n");
	printf("  ---------------------------------------------------------\n");
	#endif

	cycles1 = cpucycles();
	Status = isogeny_keygen(CurveIsogeny, PrivateKey, PublicKey);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE KEYGEN RUNS IN ........................ %10lld cycles\n", scycles);
	#endif

	cycles1 = cpucycles();
	Status = isogeny_sign(CurveIsogeny, PrivateKey, PublicKey, &sig, 0, 1);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE SIGN RUNS (compressed) IN ............. %10lld cycles\n", scycles);
	#endif

	cycles1 = cpucycles();
	Status = isogeny_verify(CurveIsogeny, PublicKey, &sig, 0, 1);
	cycles2 = cpucycles();
	scycles = cycles2 - cycles1;

	#ifdef TEST_RUN_PRINTS
	printf("  SIGNATURE VERIFY (compressed) RUNS IN ........... %10lld cycles\n", scycles);
	#endif

cleanup:
	SIDH_curve_free(CurveIsogeny);
	free(PrivateKey);
	free(PublicKey);

	return Status;
}


int main (int argc, char** argv) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;

	//signature tests --------------------------------------------------------------
	/*Status = cryptotest_signature();
	if (Status != CRYPTO_SUCCESS) {
		#ifdef TEST_RUN_PRINTS
		printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
		#endif
		return -1;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("\n  ISOGENY-BASED SIGNATURE RUN SUCCESSFUL\n\n");
		#endif
	}*/


	//signature benchmark ----------------------------------------------------------
/*	Status = cryptorun_signature();
	if (Status != CRYPTO_SUCCESS) {
		printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
		return -1;
	} */


	//signature test with batched inversions ---------------------------------------
	/*Status = cryptotest_signature_batchedinv();
	if (Status != CRYPTO_SUCCESS) {
		#ifdef TEST_RUN_PRINTS
		printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
		#endif
		return -1;
	} else {
		#ifdef TEST_RUN_PRINTS
		printf("\n  ISOGENY-BASED SIGNATURE WITH BATCHED INVERSIONS SUCCESSFUL\n\n");
		#endif
	}*/


	//signature benchmark with batched inversions ----------------------------------
	/*Status = cryptorun_signature_batchedinv();
	if (Status != CRYPTO_SUCCESS) {
		#ifdef TEST_RUN_PRINTS
		printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
		#endif
		return -1;
	}*/


	//signature tests with compressed psi(S) ---------------------------------------
	Status = cryptotest_signature_compressed();
	if (Status != CRYPTO_SUCCESS) {
		#ifdef TEST_RUN_PRINTS
		printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
		#endif
		return -1;
	} else {
	printf("\n  ISOGENY-BASED SIGNATURE RUN WITH COMPRESSION SUCCESSFUL\n\n");
		#ifdef TEST_RUN_PRINTS
		#endif
	}


	//signature benchmark with compressed psi(S) -----------------------------------
/*	Status = cryptorun_signature_batchedinv();
	if (Status != CRYPTO_SUCCESS) {
		printf("\n\n   Error detected: %s \n\n", SIDH_get_error_message(Status));
		return -1;
	} */

cleanup:

	return 0;

}
