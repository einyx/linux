// SPDX-License-Identifier: GPL-2.0-only
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
#include "hardening.h"

/* Pattern matching parameters */
#define NGRAM_SIZE		3
#define PATTERN_HASH_BITS	8
#define PATTERN_HASH_SIZE	(1 << PATTERN_HASH_BITS)
#define MIN_PROBABILITY		5	/* 5% minimum transition probability */
#define ENTROPY_WINDOW		32	/* Window for entropy calculation */

static u32 calculate_transition_hash(u32 from, u32 to)
{
	u32 combined = (from << 16) | (to & 0xFFFF);
	return jhash_1word(combined, 0) & (PATTERN_HASH_SIZE - 1);
}

/* Calculate Shannon entropy of syscall distribution */
int hardening_calculate_entropy(struct hardening_behavior_profile *behavior)
{
	u32 total = 0;
	u32 entropy = 0;
	int i;
	
	/* Count total syscalls in frequency table */
	for (i = 0; i < 512; i++) {
		total += behavior->syscall_frequency[i];
	}
	
	if (total == 0)
		return 0;
	
	/* Calculate entropy: -sum(p * log2(p)) */
	for (i = 0; i < 512; i++) {
		u32 freq = behavior->syscall_frequency[i];
		if (freq > 0) {
			u32 p = (freq * 1000) / total;	/* Probability * 1000 */
			if (p > 0) {
				/* Approximate log2 using ilog2 */
				u32 log_p = ilog2(p);
				entropy += (p * log_p) / 1000;
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
	struct list_head *bucket = &behavior->markov_transitions[hash];
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
	
	if (!ctx || !ctx->behavior)
		return 0;
		
	behavior = ctx->behavior;
	
	spin_lock_irqsave(&behavior->lock, flags);
	
	/* Store syscall in circular buffer */
	old_syscall = behavior->syscall_pattern[behavior->pattern_index];
	behavior->syscall_pattern[behavior->pattern_index] = syscall_nr;
	behavior->pattern_index = (behavior->pattern_index + 1) % 
				  HARDENING_BEHAVIOR_WINDOW;
	
	/* Update timestamp */
	behavior->last_update = ktime_get_ns();
	
	spin_unlock_irqrestore(&behavior->lock, flags);
	
	/* Check for anomalies if we have enough data */
	if (behavior->pattern_index == 0) {
		hardening_check_anomaly(ctx);
	}
	
	return 0;
}

int hardening_check_anomaly(struct hardening_task_ctx *ctx)
{
	struct hardening_behavior_profile *behavior;
	u32 ngram[NGRAM_SIZE];
	u32 anomaly_count = 0;
	int i, j;
	unsigned long flags;
	
	if (!ctx || !ctx->behavior)
		return 0;
		
	behavior = ctx->behavior;
	
	spin_lock_irqsave(&behavior->lock, flags);
	
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
	
	/* Calculate anomaly score */
	behavior->anomaly_score = (anomaly_count * 100) / 
				  (HARDENING_BEHAVIOR_WINDOW - NGRAM_SIZE + 1);
	
	spin_unlock_irqrestore(&behavior->lock, flags);
	
	/* Check if anomaly threshold exceeded */
	if (behavior->anomaly_score > HARDENING_ANOMALY_THRESHOLD) {
		if (hardening_enforce) {
			pr_notice("hardening: behavioral anomaly detected "
				  "(score: %u) for %s[%d]\n",
				  behavior->anomaly_score, 
				  current->comm, current->pid);
		}
		
		/* Escalate security level */
		hardening_escalate_security(ctx);
		
		return -EACCES;
	}
	
	return 0;
}

struct hardening_behavior_profile *hardening_alloc_behavior_profile(void)
{
	struct hardening_behavior_profile *behavior;
	
	behavior = kzalloc(sizeof(*behavior), GFP_KERNEL);
	if (!behavior)
		return NULL;
		
	spin_lock_init(&behavior->lock);
	behavior->last_update = ktime_get_ns();
	
	return behavior;
}

void hardening_free_behavior_profile(struct hardening_behavior_profile *behavior)
{
	kfree(behavior);
}