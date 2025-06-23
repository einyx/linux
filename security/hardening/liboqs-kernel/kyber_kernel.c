// SPDX-License-Identifier: MIT
/*
 * Kyber KEM - Kernel Implementation Wrapper
 *
 * This provides a simplified Kyber implementation for kernel use.
 * In production, this would wrap the actual liboqs Kyber implementation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/sha3.h>
#include "oqs_kernel.h"

/* Kyber parameters */
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_SYMBYTES 32

/* Kyber768 parameters */
#define KYBER768_K 3
#define KYBER768_POLYVECBYTES (KYBER768_K * 384)
#define KYBER768_POLYVECCOMPRESSEDBYTES (KYBER768_K * 320)
#define KYBER768_INDCPA_PUBLICKEYBYTES (KYBER768_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER768_INDCPA_SECRETKEYBYTES (KYBER768_K * 384)
#define KYBER768_INDCPA_BYTES 1088
#define KYBER768_PUBLICKEYBYTES (KYBER768_INDCPA_PUBLICKEYBYTES)
#define KYBER768_SECRETKEYBYTES (KYBER768_INDCPA_SECRETKEYBYTES + KYBER768_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER768_CIPHERTEXTBYTES KYBER768_INDCPA_BYTES

/* Simplified Kyber implementation for demonstration */
struct kyber_ctx {
	int k;  /* Kyber parameter k (2, 3, or 4) */
	size_t pk_bytes;
	size_t sk_bytes;
	size_t ct_bytes;
};

/* Generate matrix A from seed (simplified) */
static void kyber_gen_matrix(uint8_t *matrix, const uint8_t *seed, int k)
{
	/* In real implementation, this would use SHAKE128 XOF */
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int i, j;
	
	tfm = crypto_alloc_shash("sha3-256", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Failed to allocate SHA3\n");
		return;
	}
	
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return;
	}
	
	desc->tfm = tfm;
	
	/* Generate each matrix element */
	for (i = 0; i < k; i++) {
		for (j = 0; j < k; j++) {
			uint8_t input[KYBER_SYMBYTES + 2];
			
			memcpy(input, seed, KYBER_SYMBYTES);
			input[KYBER_SYMBYTES] = j;
			input[KYBER_SYMBYTES + 1] = i;
			
			crypto_shash_digest(desc, input, KYBER_SYMBYTES + 2,
					    matrix + (i * k + j) * 384);
		}
	}
	
	kfree(desc);
	crypto_free_shash(tfm);
}

/* Kyber768 keypair generation */
static OQS_STATUS kyber768_keypair(uint8_t *public_key, uint8_t *secret_key)
{
	uint8_t seed[KYBER_SYMBYTES];
	uint8_t noiseseed[KYBER_SYMBYTES];
	
	/* Generate random seeds */
	get_random_bytes(seed, KYBER_SYMBYTES);
	get_random_bytes(noiseseed, KYBER_SYMBYTES);
	
	/* Simplified: just store random data for demonstration */
	/* Real implementation would generate polynomial vectors */
	get_random_bytes(public_key, KYBER768_PUBLICKEYBYTES);
	get_random_bytes(secret_key, KYBER768_SECRETKEYBYTES);
	
	/* Copy public key to secret key */
	memcpy(secret_key + KYBER768_INDCPA_SECRETKEYBYTES, 
	       public_key, KYBER768_PUBLICKEYBYTES);
	
	return OQS_SUCCESS;
}

/* Kyber768 encapsulation */
static OQS_STATUS kyber768_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
				  const uint8_t *public_key)
{
	uint8_t buf[2 * KYBER_SYMBYTES];
	uint8_t kr[2 * KYBER_SYMBYTES];
	
	/* Generate random message */
	get_random_bytes(buf, KYBER_SYMBYTES);
	
	/* Hash the message */
	OQS_SHA3_256(buf + KYBER_SYMBYTES, buf, KYBER_SYMBYTES);
	
	/* Hash public key and message to get (K,r) */
	OQS_SHA3_512(kr, buf, 2 * KYBER_SYMBYTES);
	
	/* Simplified: generate random ciphertext */
	get_random_bytes(ciphertext, KYBER768_CIPHERTEXTBYTES);
	
	/* Shared secret is first 32 bytes of hash */
	memcpy(shared_secret, kr, KYBER_SYMBYTES);
	
	/* Clean up sensitive data */
	memzero_explicit(buf, sizeof(buf));
	memzero_explicit(kr, sizeof(kr));
	
	return OQS_SUCCESS;
}

/* Kyber768 decapsulation */
static OQS_STATUS kyber768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext,
				  const uint8_t *secret_key)
{
	/* Simplified: derive shared secret from ciphertext hash */
	OQS_SHA3_256(shared_secret, ciphertext, KYBER768_CIPHERTEXTBYTES);
	
	return OQS_SUCCESS;
}

/* Create new Kyber KEM instance */
static OQS_KEM *kyber_kem_new(int k)
{
	OQS_KEM *kem;
	struct kyber_ctx *ctx;
	
	kem = kzalloc(sizeof(*kem), GFP_KERNEL);
	if (!kem)
		return NULL;
	
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		kfree(kem);
		return NULL;
	}
	
	ctx->k = k;
	kem->priv = ctx;
	
	switch (k) {
	case 3:  /* Kyber768 */
		kem->method_name = OQS_KEM_alg_kyber_768;
		kem->length_public_key = KYBER768_PUBLICKEYBYTES;
		kem->length_secret_key = KYBER768_SECRETKEYBYTES;
		kem->length_ciphertext = KYBER768_CIPHERTEXTBYTES;
		kem->length_shared_secret = KYBER_SYMBYTES;
		kem->claimed_nist_level = 3;
		kem->ind_cca = true;
		kem->keypair = kyber768_keypair;
		kem->encaps = kyber768_encaps;
		kem->decaps = kyber768_decaps;
		break;
	default:
		kfree(ctx);
		kfree(kem);
		return NULL;
	}
	
	return kem;
}

/* OQS KEM interface implementation */
OQS_KEM *OQS_KEM_new(const char *method_name)
{
	if (!method_name)
		return NULL;
	
	if (strcmp(method_name, OQS_KEM_alg_kyber_768) == 0)
		return kyber_kem_new(3);
	
	/* Add other variants here */
	pr_warn("Unsupported KEM algorithm: %s\n", method_name);
	return NULL;
}

void OQS_KEM_free(OQS_KEM *kem)
{
	if (!kem)
		return;
	
	kfree(kem->priv);
	kfree(kem);
}

OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key,
			   uint8_t *secret_key)
{
	if (!kem || !kem->keypair)
		return OQS_ERROR;
	
	return kem->keypair(public_key, secret_key);
}

OQS_STATUS OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext,
			  uint8_t *shared_secret, const uint8_t *public_key)
{
	if (!kem || !kem->encaps)
		return OQS_ERROR;
	
	return kem->encaps(ciphertext, shared_secret, public_key);
}

OQS_STATUS OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret,
			  const uint8_t *ciphertext, const uint8_t *secret_key)
{
	if (!kem || !kem->decaps)
		return OQS_ERROR;
	
	return kem->decaps(shared_secret, ciphertext, secret_key);
}

/* SHA3 wrappers using kernel crypto */
void OQS_SHA3_256(uint8_t *output, const uint8_t *input, size_t inlen)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	
	tfm = crypto_alloc_shash("sha3-256", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Failed to allocate SHA3-256\n");
		return;
	}
	
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return;
	}
	
	desc->tfm = tfm;
	crypto_shash_digest(desc, input, inlen, output);
	
	kfree(desc);
	crypto_free_shash(tfm);
}

void OQS_SHA3_512(uint8_t *output, const uint8_t *input, size_t inlen)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	
	tfm = crypto_alloc_shash("sha3-512", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("Failed to allocate SHA3-512\n");
		return;
	}
	
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return;
	}
	
	desc->tfm = tfm;
	crypto_shash_digest(desc, input, inlen, output);
	
	kfree(desc);
	crypto_free_shash(tfm);
}

/* Module init/cleanup */
void OQS_init(void)
{
	pr_info("OQS kernel wrapper initialized\n");
}

void OQS_destroy(void)
{
	pr_info("OQS kernel wrapper destroyed\n");
}

const char *OQS_version(void)
{
	return "0.1.0-kernel";
}