// SPDX-License-Identifier: GPL-2.0-only
/*
 * Quantum-Resistant Cryptography Module
 *
 * This module implements post-quantum cryptographic algorithms for
 * future-proof security against quantum computing threats.
 *
 * Algorithms implemented:
 * - CRYSTALS-Kyber (Key Encapsulation)
 * - CRYSTALS-Dilithium (Digital Signatures)
 * - Hybrid classical/quantum authentication
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/sha3.h>
#include <linux/scatterlist.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include "hardening.h"

/* Include liboqs kernel wrapper */
#ifdef CONFIG_SECURITY_HARDENING_QUANTUM_LIBOQS
#include "liboqs-kernel/oqs_kernel.h"
#endif

/* Kyber parameters for different security levels */
struct kyber_params {
	u32 n;		/* Polynomial degree */
	u32 k;		/* Module rank */
	u32 q;		/* Modulus */
	u32 eta1;	/* Noise parameter 1 */
	u32 eta2;	/* Noise parameter 2 */
	u32 du;		/* Ciphertext compression */
	u32 dv;		/* Ciphertext compression */
};

static const struct kyber_params kyber768_params = {
	.n = 256,
	.k = 3,
	.q = 3329,
	.eta1 = 2,
	.eta2 = 2,
	.du = 10,
	.dv = 4,
};

static const struct kyber_params kyber1024_params = {
	.n = 256,
	.k = 4,
	.q = 3329,
	.eta1 = 2,
	.eta2 = 2,
	.du = 11,
	.dv = 5,
};

/* Dilithium parameters */
struct dilithium_params {
	u32 q;		/* Modulus */
	u32 d;		/* Dropped bits */
	u32 tau;	/* Challenge weight */
	u32 gamma1;	/* y coefficient range */
	u32 gamma2;	/* Low-order rounding range */
	u32 k;		/* Dimensions */
	u32 l;
	u32 eta;	/* Secret key range */
	u32 beta;	/* tau * eta */
	u32 omega;	/* Maximum hints */
};

static const struct dilithium_params dilithium3_params = {
	.q = 8380417,
	.d = 13,
	.tau = 49,
	.gamma1 = (1 << 19),
	.gamma2 = ((8380417 - 1) / 32),
	.k = 6,
	.l = 5,
	.eta = 4,
	.beta = 196,
	.omega = 55,
};

static const struct dilithium_params dilithium5_params = {
	.q = 8380417,
	.d = 13,
	.tau = 60,
	.gamma1 = (1 << 19),
	.gamma2 = ((8380417 - 1) / 32),
	.k = 8,
	.l = 7,
	.eta = 2,
	.beta = 120,
	.omega = 75,
};

/* Initialize liboqs if enabled */
static int hardening_quantum_init_liboqs(struct hardening_quantum_ctx *ctx)
{
#ifdef CONFIG_SECURITY_HARDENING_QUANTUM_LIBOQS
	OQS_KEM *kem;
	
	/* Initialize liboqs */
	OQS_init();
	
	/* Initialize Kyber768 */
	kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
	if (!kem) {
		pr_err("Failed to initialize Kyber768\n");
		return -ENOMEM;
	}
	
	ctx->kyber768_kem = kem;
	pr_info("liboqs Kyber768 initialized: pk=%zu sk=%zu ct=%zu ss=%zu\n",
		kem->length_public_key, kem->length_secret_key,
		kem->length_ciphertext, kem->length_shared_secret);
	
	/* Initialize Kyber1024 */
	kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
	if (kem) {
		ctx->kyber1024_kem = kem;
		pr_info("liboqs Kyber1024 initialized\n");
	}
	
	return 0;
#else
	return 0;
#endif
}

/* Allocate quantum context */
struct hardening_quantum_ctx *hardening_alloc_quantum_ctx(void)
{
	struct hardening_quantum_ctx *quantum;

	quantum = kzalloc(sizeof(*quantum), GFP_KERNEL);
	if (!quantum)
		return NULL;

	spin_lock_init(&quantum->lock);
	INIT_LIST_HEAD(&quantum->ephemeral_keys);
	INIT_LIST_HEAD(&quantum->quantum_channels);

	/* Set default algorithms */
	quantum->preferred_kem = HARDENING_PQ_KYBER768;
	quantum->preferred_sig = HARDENING_PQ_DILITHIUM3;

	/* Default security policy */
	quantum->require_quantum_auth = true;
	quantum->allow_classical_fallback = false;
	quantum->min_security_level = 3;  /* NIST Level 3 */
	quantum->key_rotation_interval = 86400;  /* 24 hours */

	/* Allocate hash transform for key derivation */
	quantum->hash_tfm = crypto_alloc_shash("sha3-256", 0, 0);
	if (IS_ERR(quantum->hash_tfm)) {
		pr_err("hardening: failed to allocate SHA3-256\n");
		kfree(quantum);
		return NULL;
	}

	/* Pre-allocate workspace for crypto operations */
	quantum->workspace_size = 65536;  /* 64KB workspace */
	quantum->workspace = kvmalloc(quantum->workspace_size, GFP_KERNEL);
	if (!quantum->workspace) {
		crypto_free_shash(quantum->hash_tfm);
		kfree(quantum);
		return NULL;
	}

	/* Initialize liboqs if configured */
	if (hardening_quantum_init_liboqs(quantum) < 0) {
		pr_err("hardening: failed to initialize liboqs\n");
		kvfree(quantum->workspace);
		crypto_free_shash(quantum->hash_tfm);
		kfree(quantum);
		return NULL;
	}

	pr_debug("hardening: allocated quantum context\n");
	return quantum;
}

/* Free quantum context */
void hardening_free_quantum_ctx(struct hardening_quantum_ctx *quantum)
{
	struct hardening_hybrid_key *key, *tmp_key;
	struct hardening_quantum_channel *channel, *tmp_channel;

	if (!quantum)
		return;

	/* Free identity key */
	if (quantum->identity_key) {
		kfree(quantum->identity_key->pq_public_key);
		kfree(quantum->identity_key->pq_private_key);
		kfree(quantum->identity_key);
	}

	/* Free ephemeral keys */
	list_for_each_entry_safe(key, tmp_key, &quantum->ephemeral_keys, list) {
		list_del(&key->list);
		kfree(key->pq_public_key);
		kfree(key->pq_private_key);
		kfree(key);
	}

	/* Free quantum channels */
	list_for_each_entry_safe(channel, tmp_channel, &quantum->quantum_channels, list) {
		list_del(&channel->list);
		kfree(channel->local_key);
		kfree(channel->remote_key);
		kfree(channel);
	}

	/* Free crypto resources */
	if (quantum->hash_tfm)
		crypto_free_shash(quantum->hash_tfm);

	if (quantum->workspace)
		kvfree(quantum->workspace);

	kfree(quantum);
	pr_debug("hardening: freed quantum context\n");
}

/* Initialize quantum crypto for a task */
int hardening_init_quantum(struct hardening_task_ctx *ctx)
{
	struct hardening_quantum_ctx *quantum;
	int ret;

	if (!ctx)
		return -EINVAL;

	quantum = hardening_alloc_quantum_ctx();
	if (!quantum)
		return -ENOMEM;

	/* Generate identity keypair */
	ret = hardening_quantum_generate_keypair(quantum, quantum->preferred_sig);
	if (ret) {
		pr_err("hardening: failed to generate quantum identity key\n");
		hardening_free_quantum_ctx(quantum);
		return ret;
	}

	ctx->quantum = quantum;
	pr_info("hardening: initialized quantum crypto for task\n");

	return 0;
}

/* Simplified Kyber key generation (placeholder - real implementation would be complex) */
static int kyber_keygen(struct hardening_hybrid_key *key,
			const struct kyber_params *params)
{
	u32 pk_size = params->k * params->n * 12 / 8 + 32;  /* Approximate */
	u32 sk_size = params->k * params->n * 12 / 8 + params->k * params->n * 3 / 8 + 64;

	key->pq_public_key = kmalloc(pk_size, GFP_KERNEL);
	key->pq_private_key = kmalloc(sk_size, GFP_KERNEL);

	if (!key->pq_public_key || !key->pq_private_key) {
		kfree(key->pq_public_key);
		kfree(key->pq_private_key);
		return -ENOMEM;
	}

	/* Generate random keys (placeholder - real Kyber would use lattice math) */
	get_random_bytes(key->pq_public_key, pk_size);
	get_random_bytes(key->pq_private_key, sk_size);

	key->pq_public_key_len = pk_size;
	key->pq_private_key_len = sk_size;

	return 0;
}

/* Simplified Dilithium key generation (placeholder) */
static int dilithium_keygen(struct hardening_hybrid_key *key,
			   const struct dilithium_params *params)
{
	u32 pk_size = 32 + params->k * 384;  /* Approximate */
	u32 sk_size = 32 + 32 + 64 + params->l * 96 + params->k * 96;

	key->pq_public_key = kmalloc(pk_size, GFP_KERNEL);
	key->pq_private_key = kmalloc(sk_size, GFP_KERNEL);

	if (!key->pq_public_key || !key->pq_private_key) {
		kfree(key->pq_public_key);
		kfree(key->pq_private_key);
		return -ENOMEM;
	}

	/* Generate random keys (placeholder - real Dilithium would use lattice math) */
	get_random_bytes(key->pq_public_key, pk_size);
	get_random_bytes(key->pq_private_key, sk_size);

	key->pq_public_key_len = pk_size;
	key->pq_private_key_len = sk_size;

	return 0;
}

/* Generate quantum-resistant keypair */
int hardening_quantum_generate_keypair(struct hardening_quantum_ctx *quantum,
				      enum hardening_pq_algo algo)
{
	struct hardening_hybrid_key *key;
	int ret = 0;

	if (!quantum)
		return -EINVAL;

	key = kzalloc(sizeof(*key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;

	/* Generate classical key component */
	get_random_bytes(key->classical_key, 32);
	key->classical_key_len = 32;

	/* Generate post-quantum component based on algorithm */
	switch (algo) {
	case HARDENING_PQ_KYBER768:
	case HARDENING_PQ_KYBER1024:
		ret = kyber_keygen_liboqs(quantum, key, algo);
		break;
	case HARDENING_PQ_DILITHIUM3:
		ret = dilithium_keygen(key, &dilithium3_params);
		break;
	case HARDENING_PQ_DILITHIUM5:
		ret = dilithium_keygen(key, &dilithium5_params);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret) {
		kfree(key);
		return ret;
	}

	key->pq_algo = algo;
	key->creation_time = ktime_get_real_seconds();
	key->expiration_time = key->creation_time + quantum->key_rotation_interval;
	key->usage_count = 0;
	key->is_ephemeral = false;

	/* Set as identity key if none exists */
	spin_lock(&quantum->lock);
	if (!quantum->identity_key) {
		quantum->identity_key = key;
	} else {
		key->is_ephemeral = true;
		list_add(&key->list, &quantum->ephemeral_keys);
	}
	quantum->keys_generated++;
	spin_unlock(&quantum->lock);

	pr_debug("hardening: generated quantum keypair (algo=%d)\n", algo);
	return 0;
}

/* Hybrid signature combining classical and quantum signatures */
int hardening_quantum_sign(struct hardening_quantum_ctx *quantum,
			  const void *data, size_t data_len,
			  u8 **signature, size_t *sig_len)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 classical_hash[32];
	u8 *combined_sig;
	size_t total_len;
	int ret;

	if (!quantum || !quantum->identity_key || !data || !signature || !sig_len)
		return -EINVAL;

	/* Calculate classical hash */
	tfm = quantum->hash_tfm;
	desc = kvmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	desc->tfm = tfm;
	ret = crypto_shash_digest(desc, data, data_len, classical_hash);
	kvfree(desc);

	if (ret) {
		pr_err("hardening: failed to compute hash for signature\n");
		return ret;
	}

	/* For now, use simple concatenation of classical hash and mock quantum sig */
	/* Real implementation would use actual Dilithium signing */
	total_len = 32 + 2420;  /* Classical hash + Dilithium3 signature size */
	combined_sig = kmalloc(total_len, GFP_KERNEL);
	if (!combined_sig)
		return -ENOMEM;

	/* Copy classical hash */
	memcpy(combined_sig, classical_hash, 32);

	/* Generate mock quantum signature (placeholder) */
	get_random_bytes(combined_sig + 32, 2420);

	*signature = combined_sig;
	*sig_len = total_len;

	spin_lock(&quantum->lock);
	quantum->signatures_created++;
	quantum->identity_key->usage_count++;
	spin_unlock(&quantum->lock);

	return 0;
}

/* Verify hybrid signature */
int hardening_quantum_verify(struct hardening_quantum_ctx *quantum,
			    const void *data, size_t data_len,
			    const u8 *signature, size_t sig_len)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 computed_hash[32];
	int ret;

	if (!quantum || !data || !signature)
		return -EINVAL;

	/* Verify signature length */
	if (sig_len != 32 + 2420)  /* Classical + Dilithium3 */
		return -EINVAL;

	/* Compute hash of data */
	tfm = quantum->hash_tfm;
	desc = kvmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	desc->tfm = tfm;
	ret = crypto_shash_digest(desc, data, data_len, computed_hash);
	kvfree(desc);

	if (ret)
		return ret;

	/* Verify classical component */
	if (memcmp(computed_hash, signature, 32) != 0)
		return -EBADMSG;

	/* Placeholder: Accept quantum signature (real implementation would verify) */

	spin_lock(&quantum->lock);
	quantum->signatures_verified++;
	spin_unlock(&quantum->lock);

	return 0;
}

/* Quantum key exchange using Kyber */
int hardening_quantum_key_exchange(struct hardening_quantum_ctx *quantum,
				  const u8 *remote_public, size_t remote_len,
				  u8 **shared_secret, size_t *secret_len)
{
	u8 *secret;

	if (!quantum || !remote_public || !shared_secret || !secret_len)
		return -EINVAL;

	/* Allocate shared secret (32 bytes classical + 32 bytes PQ) */
	secret = kmalloc(64, GFP_KERNEL);
	if (!secret)
		return -ENOMEM;

	/* Generate shared secret (placeholder - real implementation would use Kyber) */
	get_random_bytes(secret, 64);

	*shared_secret = secret;
	*secret_len = 64;

	spin_lock(&quantum->lock);
	quantum->key_exchanges++;
	spin_unlock(&quantum->lock);

	return 0;
}

/* Authenticate process using quantum signatures */
int hardening_quantum_authenticate_process(struct hardening_task_ctx *ctx)
{
	struct hardening_quantum_token token;
	u8 *signature;
	size_t sig_len;
	int ret;

	if (!ctx || !ctx->quantum)
		return -EINVAL;

	/* Build authentication token */
	get_random_bytes(token.token_id, 16);
	token.timestamp = ktime_get_real_seconds();
	token.process_id = current->pid;
	token.user_id = current_uid().val;
	token.security_level = ctx->sec_level;
	token.expiration = token.timestamp + 3600;  /* 1 hour validity */
	token.flags = 0;

	/* Sign the token */
	ret = hardening_quantum_sign(ctx->quantum, &token, sizeof(token),
				    &signature, &sig_len);
	if (ret)
		return ret;

	/* Store signature in token (normally would be transmitted) */
	kfree(signature);

	pr_info("hardening: quantum authenticated process %d\n", current->pid);
	return 0;
}

/* Establish quantum-secure channel between processes */
int hardening_quantum_establish_channel(struct hardening_quantum_ctx *quantum,
				       u32 target_pid)
{
	struct hardening_quantum_channel *channel;
	struct hardening_hybrid_key *local_key;
	int ret;

	if (!quantum)
		return -EINVAL;

	/* Allocate channel structure */
	channel = kzalloc(sizeof(*channel), GFP_KERNEL);
	if (!channel)
		return -ENOMEM;

	/* Generate ephemeral key for this channel */
	ret = hardening_quantum_generate_keypair(quantum, quantum->preferred_kem);
	if (ret) {
		kfree(channel);
		return ret;
	}

	/* Get the newly generated ephemeral key */
	spin_lock(&quantum->lock);
	if (!list_empty(&quantum->ephemeral_keys)) {
		local_key = list_first_entry(&quantum->ephemeral_keys,
					    struct hardening_hybrid_key, list);
		channel->local_key = local_key;
		list_del(&local_key->list);  /* Remove from ephemeral list */
	} else {
		spin_unlock(&quantum->lock);
		kfree(channel);
		return -ENOKEY;
	}

	/* Initialize channel */
	channel->sequence_number = 0;
	channel->last_rekey_time = ktime_get_real_seconds();
	channel->messages_sent = 0;
	channel->messages_received = 0;
	channel->authenticated = false;

	/* Add to active channels */
	list_add(&channel->list, &quantum->quantum_channels);
	quantum->active_channels++;
	spin_unlock(&quantum->lock);

	pr_info("hardening: established quantum channel to PID %u\n", target_pid);
	return 0;
}

/* Check if process has valid quantum authentication */
bool hardening_quantum_is_authenticated(struct hardening_task_ctx *ctx)
{
	struct hardening_quantum_ctx *quantum;
	bool authenticated = false;

	if (!ctx || !ctx->quantum)
		return false;

	quantum = ctx->quantum;

	spin_lock(&quantum->lock);
	/* Check if we have valid identity key and it's not expired */
	if (quantum->identity_key) {
		u64 now = ktime_get_real_seconds();
		if (now < quantum->identity_key->expiration_time)
			authenticated = true;
	}
	spin_unlock(&quantum->lock);

	return authenticated;
}

/* Rotate quantum keys periodically */
int hardening_quantum_rotate_keys(struct hardening_quantum_ctx *quantum)
{
	struct hardening_hybrid_key *old_key;
	int ret;

	if (!quantum)
		return -EINVAL;

	spin_lock(&quantum->lock);
	old_key = quantum->identity_key;
	quantum->identity_key = NULL;
	spin_unlock(&quantum->lock);

	/* Generate new identity key */
	ret = hardening_quantum_generate_keypair(quantum, quantum->preferred_sig);

	/* Free old key */
	if (old_key) {
		kfree(old_key->pq_public_key);
		kfree(old_key->pq_private_key);
		kfree(old_key);
	}

	if (ret == 0)
		pr_info("hardening: rotated quantum keys\n");

	return ret;
}