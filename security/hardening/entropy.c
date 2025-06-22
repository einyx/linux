/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Entropy-Based Randomization for Security Hardening Module
 *
 * Adds unpredictability to security decisions
 */

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/timekeeping.h>
#include "hardening.h"

/* Entropy sources */
#define ENTROPY_FROM_TIME	0x01
#define ENTROPY_FROM_PID	0x02
#define ENTROPY_FROM_INTERRUPTS	0x04
#define ENTROPY_FROM_MEMORY	0x08

/* Mix entropy into pool using simple LFSR */
static u32 mix_entropy(u32 pool, u32 input)
{
	u32 lfsr = pool;
	u32 bit;
	int i;
	
	/* Mix input with existing pool */
	lfsr ^= input;
	
	/* Run LFSR for several rounds */
	for (i = 0; i < 8; i++) {
		/* Polynomial: x^32 + x^22 + x^2 + x^1 + 1 */
		bit = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 22) ^ (lfsr >> 31)) & 1;
		lfsr = (lfsr >> 1) | (bit << 31);
	}
	
	return lfsr;
}

/* Gather entropy from various sources */
static u32 gather_entropy(void)
{
	u32 entropy = 0;
	u64 time_ns;
	
	/* Time-based entropy */
	time_ns = ktime_get_ns();
	entropy ^= (u32)(time_ns & 0xFFFFFFFF);
	entropy ^= (u32)(time_ns >> 32);
	
	/* Process-based entropy */
	entropy ^= current->pid << 16;
	entropy ^= current->tgid << 8;
	
	/* CPU-based entropy */
	entropy ^= raw_smp_processor_id() << 24;
	entropy ^= preempt_count() << 20;
	
	/* Memory address entropy */
	entropy ^= (unsigned long)&entropy >> 12;
	
	/* Mix with kernel random pool */
	get_random_bytes(&entropy, sizeof(entropy));
	
	return entropy;
}

/* Add entropy to task's pool */
void hardening_add_entropy(struct hardening_task_ctx *ctx, u32 value)
{
	unsigned long flags;
	
	if (!ctx)
		return;
		
	spin_lock_irqsave(&ctx->lock, flags);
	
	/* Mix new entropy into pool */
	ctx->entropy_pool = mix_entropy(ctx->entropy_pool, value);
	
	/* Also mix in fresh entropy */
	ctx->entropy_pool = mix_entropy(ctx->entropy_pool, gather_entropy());
	
	spin_unlock_irqrestore(&ctx->lock, flags);
}

/* Get random value from task's entropy pool */
u32 hardening_get_random(struct hardening_task_ctx *ctx)
{
	unsigned long flags;
	u32 random_val;
	
	if (!ctx)
		return get_random_u32();
		
	spin_lock_irqsave(&ctx->lock, flags);
	
	/* Update entropy pool */
	ctx->entropy_pool = mix_entropy(ctx->entropy_pool, gather_entropy());
	
	/* Generate random value */
	random_val = ctx->entropy_pool;
	
	/* Update seed for next iteration */
	ctx->random_seed = mix_entropy(ctx->random_seed, random_val);
	
	spin_unlock_irqrestore(&ctx->lock, flags);
	
	return random_val;
}

/* Make randomized security decision */
int hardening_randomize_decision(struct hardening_task_ctx *ctx, int probability)
{
	u32 random_val;
	u32 threshold;
	
	/* Probability is 0-100 */
	if (probability <= 0)
		return 0;
	if (probability >= 100)
		return 1;
		
	/* Get random value */
	random_val = hardening_get_random(ctx);
	
	/* Calculate threshold */
	threshold = (0xFFFFFFFF / 100) * probability;
	
	/* Make decision */
	return random_val < threshold;
}

/* Randomize delay for anti-timing attacks */
void hardening_random_delay(struct hardening_task_ctx *ctx, u32 max_delay_us)
{
	u32 delay_ns;
	ktime_t start, end;
	
	if (!ctx || max_delay_us == 0)
		return;
		
	/* Get random delay up to max_delay_us microseconds */
	delay_ns = (hardening_get_random(ctx) % max_delay_us) * NSEC_PER_USEC;
	
	/* Busy wait for random delay */
	start = ktime_get();
	end = ktime_add_ns(start, delay_ns);
	
	while (ktime_before(ktime_get(), end)) {
		cpu_relax();
	}
}

/* Initialize entropy for new task */
void hardening_init_entropy(struct hardening_task_ctx *ctx)
{
	if (!ctx)
		return;
		
	/* Initialize with fresh entropy */
	ctx->entropy_pool = gather_entropy();
	ctx->random_seed = get_random_u32();
	
	/* Mix in task-specific data */
	hardening_add_entropy(ctx, (u32)(unsigned long)current);
	hardening_add_entropy(ctx, current->pid);
}

/* Entropy-based security level adjustment */
void hardening_entropy_security_adjust(struct hardening_task_ctx *ctx, u32 factor)
{
	u32 random_factor;
	
	if (!ctx || factor == 0)
		return;
		
	/* Get random factor */
	random_factor = hardening_get_random(ctx) % 100;
	
	/* Randomly adjust security checks */
	if (random_factor < factor) {
		/* Adjust security level based on factor */
		if (ctx->sec_level < HARDENING_LEVEL_MAX) {
			ctx->sec_level++;
		}
	} else if (random_factor > 95) {
		/* 5% chance to add random delay */
		hardening_random_delay(ctx, 100);
	}
}

/* Randomize anomaly thresholds to prevent gaming */
u32 hardening_randomize_threshold(struct hardening_task_ctx *ctx,
				  u32 base, u32 range)
{
	u32 variance;
	u32 random_val;
	
	if (!ctx || range == 0)
		return base;
		
	/* Get random value within range */
	random_val = hardening_get_random(ctx);
	variance = random_val % range;
	
	/* Return base plus random variance */
	return base + variance;
}