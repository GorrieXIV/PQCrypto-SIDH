/*************************************************************************
* A Post-Quantum Digital Signature Scheme Based on Supersingular Isogenies
*
* Copyright (c) Youngho Yoo.
*
* Abstract: Testing the isogeny-based signature scheme.
*
* Ported to Microsoft's SIDH 2.0 Library by Robert Gorrie (gxiv)
*************************************************************************/

#include "SIDH_signature.h"
#include "tests/test_extras.h"
#include <malloc.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include "keccak.h"
#include <pthread.h>  
#include <semaphore.h>


int NUM_THREADS = 248;
int CUR_ROUND = 0;
int batchSize = 248;
invBatch* signBatchA;
invBatch* signBatchB;
invBatch* verifyBatchA;
invBatch* verifyBatchB;
invBatch* verifyBatchC;
pthread_mutex_t RLOCK;
pthread_mutex_t BLOCK;

void hashdata(unsigned int pbytes, unsigned char** comm1, unsigned char** comm2, uint8_t* HashResp, int hlen, int dlen, uint8_t *data, uint8_t *cHash, int cHashLength) {
    int r;
    for (r=0; r<NUM_ROUNDS; r++) {
        memcpy(data + (r * 2*pbytes), comm1[r], 2*pbytes);
        memcpy(data + (NUM_ROUNDS * 2*pbytes) + (r * 2*pbytes), comm2[r], 2*pbytes);
    }
    memcpy(data + (2 * NUM_ROUNDS * 2*pbytes), HashResp, 2 * NUM_ROUNDS * hlen);

    keccak(data, dlen, cHash, cHashLength);
}

CRYPTO_STATUS isogeny_keygen(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PrivateKey, unsigned char *PublicKey, int compressed) {
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    bool valid_PublicKey = false;
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;


    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    // Generate Peggy(Bob)'s keys
    passed = true;
    cycles1 = cpucycles();
    Status = KeyGeneration_B(PrivateKey, PublicKey, CurveIsogeny);
    if (Status != CRYPTO_SUCCESS) {                  
        passed = false;
    }
    cycles2 = cpucycles();
    cycles = cycles2 - cycles1;
    if (passed) {
        printf("  Key generated in ................... %10lld cycles", cycles);
    } else { 
        printf("  Key generation failed"); goto cleanup; 
    }

		printf("PublicKey size in bytes: %d\n", sizeof(PublicKey));
		printf("PrivateKey size in bytes: %d\n", sizeof(PrivateKey));
		printf("Curve size in bytes: %d\n", sizeof(CurveIsogeny));

    
cleanup:
    SIDH_curve_free(CurveIsogeny);

    return Status;
}

typedef struct thread_params_sign {
	PCurveIsogenyStruct *CurveIsogeny;
	unsigned char *PrivateKey;
	unsigned char *PublicKey;
	struct Signature *sig;
	
	unsigned int pbytes;
	unsigned int n;
	unsigned int obytes;
} thread_params_sign;


void *sign_thread(void *TPS, int compressed) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	thread_params_sign *tps = (thread_params_sign*) TPS;

	int r=0;

	while (1) {
		int stop=0;

		pthread_mutex_lock(&RLOCK);
		
		if (CUR_ROUND >= NUM_ROUNDS) {
			stop=1;
		} else {
			r = CUR_ROUND;
			CUR_ROUND++;
		}
		pthread_mutex_unlock(&RLOCK);

		if (stop) break;

		tps->sig->Randoms[r] = (unsigned char*)calloc(1, tps->obytes);
		tps->sig->Commitments1[r] = (unsigned char*)calloc(1, 2*tps->pbytes);
		tps->sig->Commitments2[r] = (unsigned char*)calloc(1, 2*tps->pbytes);
		tps->sig->psiS[r] = calloc(1, sizeof(point_proj));

		// Pick random point R and compute E/<R>
		f2elm_t A;

    unsigned char *TempPubKey;
    TempPubKey = (unsigned char*)calloc(1, 4*2*tps->pbytes);

    Status = KeyGeneration_A(tps->sig->Randoms[r], TempPubKey, *(tps->CurveIsogeny), true, signBatchA);
    if(Status != CRYPTO_SUCCESS) {
    	printf("Random point generation failed");
		}
        
    to_fp2mont(((f2elm_t*)TempPubKey)[0], A);
    fp2copy751(A, *(f2elm_t*)tps->sig->Commitments1[r]);     //commitment1[r] = A = tempPubKey[0]

		Status = SecretAgreement_B(tps->PrivateKey, TempPubKey, tps->sig->Commitments2[r], *(tps->CurveIsogeny), NULL, tps->sig->psiS[r], signBatchB);
    if(Status != CRYPTO_SUCCESS) {
			printf("Random point generation failed"); 
    }
	}
}


CRYPTO_STATUS isogeny_sign(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PrivateKey, unsigned char *PublicKey, struct Signature *sig, int compressed) {		
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2, totcycles=0;

    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        //goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        //goto cleanup;
    }	

    // Run the ZKP rounds
    int r;
    pthread_t sign_threads[NUM_THREADS];

    CUR_ROUND = 0;
    if (pthread_mutex_init(&RLOCK, NULL)) {
    	printf("ERROR: mutex init failed\n");
    	return 1;
    }
    thread_params_sign tps = {&CurveIsogeny, PrivateKey, PublicKey, sig, pbytes, n, obytes};
		
		signBatchA = (invBatch*) malloc (sizeof(invBatch));

		signBatchA->batchSize = 248;
		signBatchA->cntr = 0;
		signBatchA->invArray = (f2elm_t*) malloc (248 * sizeof(f2elm_t));
		signBatchA->invDest = (f2elm_t*) malloc (248 * sizeof(f2elm_t));
		pthread_mutex_init(&signBatchA->arrayLock, NULL);
		sem_init(&signBatchA->sign_sem, 0, 0);

		signBatchB = (invBatch*) malloc (sizeof(invBatch));

		signBatchB->batchSize = 248;
		signBatchB->cntr = 0;
		signBatchB->invArray = (f2elm_t*) malloc (248 * sizeof(f2elm_t));
		signBatchB->invDest = (f2elm_t*) malloc (248 * sizeof(f2elm_t));
		pthread_mutex_init(&signBatchB->arrayLock, NULL);
		sem_init(&signBatchB->sign_sem, 0, 0);

    int t;
    for (t=0; t<NUM_THREADS; t++) {
    	if (pthread_create(&sign_threads[t], NULL, sign_thread, &tps)) {
    		printf("ERROR: Failed to create thread %d\n", t);
    	}
    }

    for (t=0; t<NUM_THREADS; t++) {
    	pthread_join(sign_threads[t], NULL);
  	}

    //printf("Average time for ZKP round ...... %10lld cycles\n", totcycles/NUM_ROUNDS);


    // Commit to responses (hash)
    int HashLength = 32; //bytes
    sig->HashResp = calloc(2*NUM_ROUNDS, HashLength*sizeof(uint8_t));
    for (r=0; r<NUM_ROUNDS; r++) {
        keccak((uint8_t*) sig->Randoms[r], obytes, sig->HashResp+((2*r)*HashLength), HashLength);
        keccak((uint8_t*) sig->psiS[r], sizeof(point_proj), sig->HashResp+((2*r+1)*HashLength), HashLength);
    }

    // Create challenge hash (by hashing all the commitments and HashResps)
    uint8_t *datastring, *cHash;
    int DataLength = (2 * NUM_ROUNDS * 2*pbytes) + (2 * NUM_ROUNDS * HashLength*sizeof(uint8_t));
    int cHashLength = NUM_ROUNDS/8;
    datastring = calloc(1, DataLength);
    cHash = calloc(1, cHashLength);
    
    hashdata(pbytes, sig->Commitments1, sig->Commitments2, sig->HashResp, HashLength, DataLength, datastring, cHash, cHashLength);

cleanup:
    SIDH_curve_free(CurveIsogeny);
    free(signBatchA->invArray);
		free(signBatchA->invDest);
    free(signBatchB->invArray);
		free(signBatchB->invDest);
		
    return Status;
}



typedef struct thread_params_verify {
	PCurveIsogenyStruct *CurveIsogeny;
	unsigned char *PublicKey;
	struct Signature *sig;

	int cHashLength;
	uint8_t *cHash;
	
	unsigned int pbytes;
	unsigned int n;
	unsigned int obytes;
} thread_params_verify;

void *verify_thread(void *TPV, int compressed) {
	CRYPTO_STATUS Status = CRYPTO_SUCCESS;
	thread_params_verify *tpv = (thread_params_verify*) TPV;

	// iterate through cHash bits as challenge and verify
	bool verified = true;
	int r=0;
	int i,j;

	while (1) {
		int stop=0;

		pthread_mutex_lock(&RLOCK);
		if (CUR_ROUND >= NUM_ROUNDS) {
			stop=1;
		} else {
			r = CUR_ROUND;
			CUR_ROUND++;
		}
		pthread_mutex_unlock(&RLOCK);

		if (stop) break;

		//printf("\nround: %d ", CUR_ROUND);
		i = r/8;
		j = r%8;

		int bit = tpv->cHash[i] & (1 << j);  //challenge bit

		if (bit == 0) {
			pthread_mutex_lock(&BLOCK);
			verifyBatchA->batchSize++;
			verifyBatchB->batchSize++;
			pthread_mutex_unlock(&BLOCK);
			//printf("round %d: bit 0 - ", r);

			// Check R, phi(R) has order 2^372 (suffices to check that the random number is even)
			uint8_t lastbyte = ((uint8_t*) tpv->sig->Randoms[r])[0];
			if (lastbyte % 2) {
				printf("ERROR: R, phi(R) are not full order\n");
			} else {
				//printf("checked order. ");
			}

			// Check kernels
			f2elm_t A;
			unsigned char *TempPubKey;
			TempPubKey = (unsigned char*)calloc(1, 4*2*tpv->pbytes);

			Status = KeyGeneration_A(tpv->sig->Randoms[r], TempPubKey, *(tpv->CurveIsogeny), false, verifyBatchA);
			
			if(Status != CRYPTO_SUCCESS) {
				printf("Computing E -> E/<R> failed");
			} else {
				//printf("%s %d: thread success of KeyGenA\n", __FILE__, __LINE__);
			}
			
            
			to_fp2mont(((f2elm_t*)TempPubKey)[0], A);

			int cmp = memcmp(A, tpv->sig->Commitments1[r], sizeof(f2elm_t));
			if (cmp != 0) {
				verified = false;
				printf("verifying E -> E/<R> failed\n");
			}
            
			unsigned char *TempSharSec;
			TempSharSec = (unsigned char*)calloc(1, 2*tpv->pbytes);

			Status = SecretAgreement_A(tpv->sig->Randoms[r], tpv->PublicKey, TempSharSec, *(tpv->CurveIsogeny), NULL, verifyBatchB);
			if(Status != CRYPTO_SUCCESS) {
				printf("Computing E/<S> -> E/<R,S> failed");
			} else {
				//printf("%s %d: thread success of SecAgrA\n", __FILE__, __LINE__);
			}

			cmp = memcmp(TempSharSec, tpv->sig->Commitments2[r], 2*tpv->pbytes);
			if (cmp != 0) {
				verified = false;
				printf("verifying E/<S> -> E/<R,S> failed\n");
			}

		} else {
			pthread_mutex_lock(&BLOCK);
			verifyBatchC->batchSize++;
			pthread_mutex_unlock(&BLOCK);

			// Check psi(S) has order 3^239 (need to triple it 239 times)
			point_proj_t triple = {0};
			copy_words((digit_t*)tpv->sig->psiS[r], (digit_t*)triple, 2*2*NWORDS_FIELD);

			f2elm_t A,C={0};
			to_fp2mont(((f2elm_t*)tpv->PublicKey)[0],A);
			fpcopy751((*(tpv->CurveIsogeny))->C, C[0]);
			int t;
			for (t=0; t<238; t++) {
				xTPL(triple, triple, A, C);
				if (is_felm_zero(((felm_t*)triple->Z)[0]) && is_felm_zero(((felm_t*)triple->Z)[1])) {
					printf("ERROR: psi(S) has order 3^%d\n", t+1);
				}
			}

			unsigned char *TempSharSec, *TempPubKey;
			TempSharSec = calloc(1, 2*tpv->pbytes);
			TempPubKey = calloc(1, 4*2*tpv->pbytes);
			from_fp2mont(tpv->sig->Commitments1[r], ((f2elm_t*)TempPubKey)[0]);

			Status = SecretAgreement_B(NULL, TempPubKey, TempSharSec, *(tpv->CurveIsogeny), tpv->sig->psiS[r], NULL, verifyBatchC);
			if(Status != CRYPTO_SUCCESS) {
				printf("Computing E/<R> -> E/<R,S> failed");
			}

			int cmp = memcmp(TempSharSec, tpv->sig->Commitments2[r], 2*tpv->pbytes);
			if (cmp != 0) {
				verified = false;
				printf("verifying E/<R> -> E/<R,S> failed\n");
			}
		}
	}

	if (!verified) {
		printf("ERROR: verify failed.\n");
	}
}


CRYPTO_STATUS isogeny_verify(PCurveIsogenyStaticData CurveIsogenyData, unsigned char *PublicKey, struct Signature *sig, int compressed) {
    unsigned int pbytes = (CurveIsogenyData->pwordbits + 7)/8;      // Number of bytes in a field element 
    unsigned int n, obytes = (CurveIsogenyData->owordbits + 7)/8;   // Number of bytes in an element in [1, order]
    PCurveIsogenyStruct CurveIsogeny = {0};
    unsigned long long cycles, cycles1, cycles2, totcycles=0;
    CRYPTO_STATUS Status = CRYPTO_SUCCESS;
    bool passed;

    int r;


    // Curve isogeny system initialization
    CurveIsogeny = SIDH_curve_allocate(CurveIsogenyData);
    if (CurveIsogeny == NULL) {
        Status = CRYPTO_ERROR_NO_MEMORY;
        //goto cleanup;
    }
    Status = SIDH_curve_initialize(CurveIsogeny, &random_bytes_test, CurveIsogenyData);
    if (Status != CRYPTO_SUCCESS) {
        //goto cleanup;
    }

    // compute challenge hash
    int HashLength = 32;
    int cHashLength = NUM_ROUNDS/8;
    int DataLength = (2 * NUM_ROUNDS * 2*pbytes) + (2 * NUM_ROUNDS * HashLength*sizeof(uint8_t));
    uint8_t *datastring, *cHash;
    datastring = calloc(1, DataLength);
    cHash = calloc(1, cHashLength);

    hashdata(pbytes, sig->Commitments1, sig->Commitments2, sig->HashResp, HashLength, DataLength, datastring, cHash, cHashLength);


    // Run the verifying rounds
    pthread_t verify_threads[NUM_THREADS];
    CUR_ROUND = 0;
    if (pthread_mutex_init(&RLOCK, NULL)) {
    	printf("ERROR: mutex init failed\n");
    	return 1;
    }
    thread_params_verify tpv = {&CurveIsogeny, PublicKey, sig, cHashLength, cHash, pbytes, n, obytes};

		verifyBatchA = (invBatch*) malloc (sizeof(invBatch));

		verifyBatchA->batchSize = 0;
		verifyBatchA->cntr = 0;
		verifyBatchA->invArray = (f2elm_t*) malloc (batchSize * sizeof(f2elm_t));
		verifyBatchA->invDest = (f2elm_t*) malloc (batchSize * sizeof(f2elm_t));
		pthread_mutex_init(&verifyBatchA->arrayLock, NULL);
		sem_init(&verifyBatchA->sign_sem, 0, 0);

		verifyBatchB = (invBatch*) malloc (sizeof(invBatch));

		verifyBatchB->batchSize = 0;
		verifyBatchB->cntr = 0;
		verifyBatchB->invArray = (f2elm_t*) malloc (batchSize * sizeof(f2elm_t));
		verifyBatchB->invDest = (f2elm_t*) malloc (batchSize * sizeof(f2elm_t));
		pthread_mutex_init(&verifyBatchB->arrayLock, NULL);
		sem_init(&verifyBatchB->sign_sem, 0, 0);

		verifyBatchC = (invBatch*) malloc (sizeof(invBatch));

		verifyBatchC->batchSize = 0;
		verifyBatchC->cntr = 0;
		verifyBatchC->invArray = (f2elm_t*) malloc (batchSize * sizeof(f2elm_t));
		verifyBatchC->invDest = (f2elm_t*) malloc (batchSize * sizeof(f2elm_t));
		pthread_mutex_init(&verifyBatchC->arrayLock, NULL);
		sem_init(&verifyBatchC->sign_sem, 0, 0);

    int t;
    for (t=0; t<NUM_THREADS; t++) {
    	if (pthread_create(&verify_threads[t], NULL, verify_thread, &tpv)) {
    		printf("ERROR: Failed to create thread %d\n", t);
    	}
    }

    for (t=0; t<NUM_THREADS; t++) {
    	pthread_join(verify_threads[t], NULL);
  	}

cleanup:
    SIDH_curve_free(CurveIsogeny);
    free(verifyBatchA->invArray);
		free(verifyBatchA->invDest);
		free(verifyBatchB->invArray);
		free(verifyBatchB->invDest);
		free(verifyBatchC->invArray);
		free(verifyBatchC->invDest);

    return Status;
}

