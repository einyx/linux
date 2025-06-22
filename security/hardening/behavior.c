/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Enhanced Behavioral Anomaly Detection for Security Hardening Module
 *
 * Implements ML-inspired anomaly detection using:
 * - N-gram analysis
 * - Markov chains for transition probability
 * - Entropy calculation
 * - Sequence complexity analysis
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/log2.h>
#include <linux/cred.h>
#include "../security_ratelimit.h"
#include "../security_audit.h"
#include "hardening.h"

/* Pattern matching parameters */
#define NGRAM_SIZE		3
#define PATTERN_HASH_BITS	8
#define PATTERN_HASH_SIZE	(1 << PATTERN_HASH_BITS)
#define MIN_PROBABILITY		5	/* 5% minimum transition probability */
#define ENTROPY_WINDOW		32	/* Window for entropy calculation */
#define MAX_SYSCALLS		512	/* Maximum syscall number tracked */
#define PROBABILITY_SCALE	1000	/* Scale factor for probability calculations */
#define SYSCALL_SHIFT		16	/* Bit shift for combining syscalls */
#define SYSCALL_MASK		0xFFFF	/* Mask for syscall number */

static u32 calculate_transition_hash(u32 from, u32 to)
{
	u32 combined = (from << SYSCALL_SHIFT) | (to & SYSCALL_MASK);
	return jhash_1word(combined, 0) & (PATTERN_HASH_SIZE - 1);
}

/* Calculate Shannon entropy of syscall distribution */
int hardening_calculate_entropy(struct hardening_behavior_profile *behavior)
{
	u32 total = 0;
	u32 entropy = 0;
	int i;
	
	/* Count total syscalls in frequency table */
	for (i = 0; i < MAX_SYSCALLS; i++) {
		total += behavior->syscall_frequency[i];
	}
	
	if (total == 0)
		return 0;
	
	/* Calculate entropy: -sum(p * log2(p)) */
	for (i = 0; i < MAX_SYSCALLS; i++) {
		u32 freq = behavior->syscall_frequency[i];
		if (freq > 0) {
			u32 p = (freq * PROBABILITY_SCALE) / total;
			if (p > 0) {
				/* Approximate log2 using ilog2 */
				u32 log_p = ilog2(p);
				entropy += (p * log_p) / PROBABILITY_SCALE;
			}
		}
	}
	
	behavior->pattern_entropy = entropy;
	return entropy;
}

/* Update Markov chain with syscall transition */
int hardening_update_markov_chain(struct hardening_behavior_profile *behavior,
				  u32 from, u32 to)
{
	struct syscall_transition *trans;
	u32 hash = calculate_transition_hash(from, to);
	struct list_head *bucket = &behavior->markov_transitions[hash];
	bool found = false;
	
	/* Look for existing transition */
	list_for_each_entry(trans, bucket, list) {
		if (trans->from_syscall == from && trans->to_syscall == to) {
			trans->count++;
			found = true;
			break;
		}
	}
	
	/* Add new transition if not found */
	if (!found) {
		trans = kmalloc(sizeof(*trans), GFP_ATOMIC);
		if (!trans)
			return -ENOMEM;
			
		trans->from_syscall = from;
		trans->to_syscall = to;
		trans->count = 1;
		list_add(&trans->list, bucket);
	}
	
	behavior->total_transitions++;
	return 0;
}

/* Check if transition probability is anomalous */
static bool is_anomalous_transition(struct hardening_behavior_profile *behavior,
				   u32 from, u32 to)
{
	struct syscall_transition *trans;
	u32 hash = calculate_transition_hash(from, to);
	u32 total_from = 0;
	u32 transition_count = 0;
	
	/* Count total transitions from 'from' syscall */
	for (hash = 0; hash < PATTERN_HASH_SIZE; hash++) {
		list_for_each_entry(trans, &behavior->markov_transitions[hash], list) {
			if (trans->from_syscall == from) {
				total_from += trans->count;
				if (trans->to_syscall == to)
					transition_count = trans->count;
			}
		}
	}
	
	if (total_from == 0)
		return true;	/* Never seen this syscall before */
		
	/* Calculate transition probability */
	u32 probability = (transition_count * 100) / total_from;
	
	/* Anomalous if probability is too low */
	return probability < MIN_PROBABILITY;
}

/* Calculate sequence complexity using compression ratio approximation */
static u32 calculate_sequence_complexity(u32 *pattern, u32 len)
{
	u32 unique_count = 0;
	u32 repeat_count = 0;
	int i, j;
	
	/* Count unique elements and repetitions */
	for (i = 0; i < len; i++) {
		bool is_unique = true;
		for (j = 0; j < i; j++) {
			if (pattern[i] == pattern[j]) {
				is_unique = false;
				repeat_count++;
				break;
			}
		}
		if (is_unique)
			unique_count++;
	}
	
	/* Complexity score: ratio of unique to total */
	return (unique_count * 100) / len;
}

int hardening_update_behavior(struct hardening_task_ctx *ctx, int syscall_nr)
{
	struct hardening_behavior_profile *behavior;
	unsigned long flags;
	u32 old_syscall;
	u32 prev_syscall;
	static struct security_ratelimit_ctx *ratelimit_ctx = NULL;
	
	if (!ctx || !ctx->behavior)
		return 0;
		
	behavior = ctx->behavior;
	
	/* Initialize rate limiting on first use */
	if (!ratelimit_ctx) {
		ratelimit_ctx = security_ratelimit_init(
			200,	/* 200 checks per interval */
			1000);	/* 1 second interval */
		if (!ratelimit_ctx)
			pr_warn("hardening: failed to init behavior rate limiting\n");
	}
	
	/* Check rate limit */
	if (ratelimit_ctx) {
		int ret = security_ratelimit_check_log(ratelimit_ctx,
			from_kuid(&init_user_ns, current_uid()),
			"behavior_update");
		if (ret == -EBUSY)
			return 0; /* Skip this update due to rate limiting */
	}
	
	spin_lock_irqsave(&behavior->lock, flags);
	
	/* Add syscall to batch */
	behavior->syscall_batch[behavior->batch_count++] = syscall_nr;
	
	/* Process batch when full */
	if (behavior->batch_count >= SYSCALL_BATCH_SIZE) {
		int i;
		
		for (i = 0; i < behavior->batch_count; i++) {
			u32 batch_syscall = behavior->syscall_batch[i];
			
			/* Get previous syscall for Markov chain update */
			if (behavior->pattern_index > 0) {
				prev_syscall = behavior->syscall_pattern[behavior->pattern_index - 1];
			} else if (behavior->total_transitions > 0) {
				prev_syscall = behavior->syscall_pattern[HARDENING_BEHAVIOR_WINDOW - 1];
			} else {
				prev_syscall = 0;
			}
			
			/* Store syscall in circular buffer */
			old_syscall = behavior->syscall_pattern[behavior->pattern_index];
			behavior->syscall_pattern[behavior->pattern_index] = batch_syscall;
			behavior->pattern_index = (behavior->pattern_index + 1) % 
					  HARDENING_BEHAVIOR_WINDOW;
			
			/* Update syscall frequency */
			if (batch_syscall < 512)
				behavior->syscall_frequency[batch_syscall]++;
				
			/* Update Markov chain for batch */
			if (i > 0 && prev_syscall != 0) {
				spin_unlock_irqrestore(&behavior->lock, flags);
				hardening_update_markov_chain(behavior, 
					behavior->syscall_batch[i-1], batch_syscall);
				spin_lock_irqsave(&behavior->lock, flags);
			}
		}
		
		/* Reset batch */
		behavior->batch_count = 0;
		
		/* Update timestamp */
		behavior->last_update = ktime_get_ns();
	}
	
	spin_unlock_irqrestore(&behavior->lock, flags);
	
	/* Only check for anomalies when batch is processed */
	if (behavior->batch_count == 0 && behavior->pattern_index == 0) {
		hardening_check_anomaly(ctx);
	}
	
	return 0;
}

int hardening_check_anomaly(struct hardening_task_ctx *ctx)
{
	struct hardening_behavior_profile *behavior;
	u32 ngram[NGRAM_SIZE];
	u32 anomaly_count = 0;
	u32 complexity_score;
	int i, j;
	unsigned long flags;
	
	if (!ctx || !ctx->behavior)
		return 0;
		
	behavior = ctx->behavior;
	
	spin_lock_irqsave(&behavior->lock, flags);
	
	/* Calculate sequence complexity */
	complexity_score = calculate_sequence_complexity(behavior->syscall_pattern, 
						       HARDENING_BEHAVIOR_WINDOW);
	
	/* Analyze n-grams in the pattern */
	for (i = 0; i <= HARDENING_BEHAVIOR_WINDOW - NGRAM_SIZE; i++) {
		bool found_similar = false;
		
		/* Extract n-gram */
		for (j = 0; j < NGRAM_SIZE; j++) {
			ngram[j] = behavior->syscall_pattern[i + j];
		}
		
		/* Check if this n-gram appeared before in the window */
		for (j = 0; j < i; j++) {
			bool match = true;
			int k;
			
			for (k = 0; k < NGRAM_SIZE; k++) {
				if (behavior->syscall_pattern[j + k] != ngram[k]) {
					match = false;
					break;
				}
			}
			
			if (match) {
				found_similar = true;
				break;
			}
		}
		
		if (!found_similar) {
			anomaly_count++;
		}
	}
	
	/* Check for anomalous transitions */
	if (behavior->pattern_index > 0) {
		u32 prev_syscall = behavior->syscall_pattern[
			(behavior->pattern_index - 1 + HARDENING_BEHAVIOR_WINDOW) % 
			HARDENING_BEHAVIOR_WINDOW];
		u32 curr_syscall = behavior->syscall_pattern[behavior->pattern_index];
		
		if (is_anomalous_transition(behavior, prev_syscall, curr_syscall)) {
			anomaly_count += 5; /* Weight transition anomalies higher */
		}
	}
	
	/* Calculate anomaly score incorporating complexity */
	behavior->anomaly_score = (anomaly_count * 100) / 
				  (HARDENING_BEHAVIOR_WINDOW - NGRAM_SIZE + 1);
	
	/* Adjust score based on complexity - low complexity is more suspicious */
	if (complexity_score < 30) {
		behavior->anomaly_score += (30 - complexity_score) / 2;
	}
	
	spin_unlock_irqrestore(&behavior->lock, flags);
	
	/* Check if anomaly threshold exceeded */
	if (behavior->anomaly_score > HARDENING_ANOMALY_THRESHOLD) {
		uid_t uid = from_kuid(&init_user_ns, current_uid());
		
		/* Log to audit framework */
		security_audit_log(AUDIT_BEHAVIOR_ANOMALY, uid,
				   "process=%s pid=%d score=%u complexity=%u",
				   current->comm, current->pid,
				   behavior->anomaly_score, complexity_score);
		
		if (hardening_enforce) {
			/* Escalate security level */
			hardening_escalate_security(ctx);
			return -EACCES;
		}
	}
	
	return 0;
}

struct hardening_behavior_profile *hardening_alloc_behavior_profile(void)
{
	struct hardening_behavior_profile *behavior;
	int i;
	
	behavior = kzalloc(sizeof(*behavior), GFP_KERNEL);
	if (!behavior)
		return NULL;
		
	spin_lock_init(&behavior->lock);
	behavior->last_update = ktime_get_ns();
	
	/* Initialize Markov transition hash buckets */
	for (i = 0; i < PATTERN_HASH_SIZE; i++) {
		INIT_LIST_HEAD(&behavior->markov_transitions[i]);
	}
	
	return behavior;
}

void hardening_free_behavior_profile(
		struct hardening_behavior_profile *behavior)
{
	struct syscall_transition *trans, *tmp;
	int i;
	
	if (!behavior)
		return;
	
	/* Free all Markov chain transitions */
	for (i = 0; i < PATTERN_HASH_SIZE; i++) {
		list_for_each_entry_safe(trans, tmp, &behavior->markov_transitions[i], list) {
			list_del(&trans->list);
			kfree(trans);
		}
	}
	
	kfree(behavior);
}