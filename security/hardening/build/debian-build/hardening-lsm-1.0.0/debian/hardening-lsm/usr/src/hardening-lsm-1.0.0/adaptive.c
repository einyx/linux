// SPDX-License-Identifier: GPL-2.0-only
/*
 * Adaptive Security Levels for Security Hardening Module
 *
 * Dynamically adjusts security restrictions based on threat detection
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include "hardening.h"

#define VIOLATION_DECAY_TIME_NS		(60 * NSEC_PER_SEC)	/* 1 minute */
#define VIOLATIONS_FOR_ESCALATION	3
#define VIOLATIONS_FOR_CRITICAL		10

static const char *security_level_names[] = {
	[HARDENING_LEVEL_NORMAL] = "normal",
	[HARDENING_LEVEL_ELEVATED] = "elevated",
	[HARDENING_LEVEL_HIGH] = "high",
	[HARDENING_LEVEL_CRITICAL] = "critical"
};

/* Restrictions per security level */
struct security_level_policy {
	u32 denied_capabilities;	/* Capabilities to deny */
	bool block_module_loading;	/* Block kernel module loading */
	bool block_kexec;		/* Block kexec */
	bool block_user_namespaces;	/* Block user namespace creation */
	bool restrict_network;		/* Restrict network operations */
	bool restrict_mount;		/* Restrict mount operations */
	u32 max_file_descriptors;	/* Limit file descriptors */
	u32 max_processes;		/* Limit process creation */
};

static const struct security_level_policy level_policies[] = {
	[HARDENING_LEVEL_NORMAL] = {
		.denied_capabilities = 0,
		.block_module_loading = false,
		.block_kexec = false,
		.block_user_namespaces = false,
		.restrict_network = false,
		.restrict_mount = false,
		.max_file_descriptors = 0,	/* No limit */
		.max_processes = 0,		/* No limit */
	},
	[HARDENING_LEVEL_ELEVATED] = {
		.denied_capabilities = CAP_TO_MASK(CAP_SYS_MODULE) |
				      CAP_TO_MASK(CAP_SYS_RAWIO),
		.block_module_loading = true,
		.block_kexec = true,
		.block_user_namespaces = false,
		.restrict_network = false,
		.restrict_mount = true,
		.max_file_descriptors = 1024,
		.max_processes = 100,
	},
	[HARDENING_LEVEL_HIGH] = {
		.denied_capabilities = CAP_TO_MASK(CAP_SYS_MODULE) |
				      CAP_TO_MASK(CAP_SYS_RAWIO) |
				      CAP_TO_MASK(CAP_SYS_BOOT) |
				      CAP_TO_MASK(CAP_SYS_ADMIN),
		.block_module_loading = true,
		.block_kexec = true,
		.block_user_namespaces = true,
		.restrict_network = true,
		.restrict_mount = true,
		.max_file_descriptors = 256,
		.max_processes = 50,
	},
	[HARDENING_LEVEL_CRITICAL] = {
		.denied_capabilities = ~0U,	/* Deny all capabilities */
		.block_module_loading = true,
		.block_kexec = true,
		.block_user_namespaces = true,
		.restrict_network = true,
		.restrict_mount = true,
		.max_file_descriptors = 64,
		.max_processes = 10,
	},
};

void hardening_escalate_security(struct hardening_task_ctx *ctx)
{
	unsigned long flags;
	u64 now = ktime_get_ns();
	
	if (!ctx)
		return;
		
	spin_lock_irqsave(&ctx->lock, flags);
	
	/* Update violation tracking */
	ctx->violation_count++;
	ctx->last_violation_time = now;
	
	/* Determine new security level based on violations */
	if (ctx->violation_count >= VIOLATIONS_FOR_CRITICAL) {
		ctx->sec_level = HARDENING_LEVEL_CRITICAL;
	} else if (ctx->violation_count >= VIOLATIONS_FOR_ESCALATION) {
		if (ctx->sec_level < HARDENING_LEVEL_HIGH)
			ctx->sec_level++;
	} else if (ctx->violation_count >= 1) {
		if (ctx->sec_level == HARDENING_LEVEL_NORMAL)
			ctx->sec_level = HARDENING_LEVEL_ELEVATED;
	}
	
	spin_unlock_irqrestore(&ctx->lock, flags);
	
	pr_notice("hardening: security level escalated to %s for %s[%d] "
		  "(violations: %u)\n",
		  security_level_names[ctx->sec_level],
		  current->comm, current->pid,
		  ctx->violation_count);
}

void hardening_deescalate_security(struct hardening_task_ctx *ctx)
{
	unsigned long flags;
	u64 now = ktime_get_ns();
	u64 time_since_violation;
	
	if (!ctx)
		return;
		
	spin_lock_irqsave(&ctx->lock, flags);
	
	/* Check if enough time has passed since last violation */
	time_since_violation = now - ctx->last_violation_time;
	if (time_since_violation > VIOLATION_DECAY_TIME_NS) {
		/* Decay violations */
		if (ctx->violation_count > 0)
			ctx->violation_count--;
			
		/* Lower security level if appropriate */
		if (ctx->violation_count == 0 && ctx->sec_level > HARDENING_LEVEL_NORMAL) {
			ctx->sec_level--;
			pr_debug("hardening: security level lowered to %s for %s[%d]\n",
				 security_level_names[ctx->sec_level],
				 current->comm, current->pid);
		}
		
		ctx->last_violation_time = now;
	}
	
	spin_unlock_irqrestore(&ctx->lock, flags);
}

int hardening_check_capability(struct hardening_task_ctx *ctx, int cap)
{
	const struct security_level_policy *policy;
	
	if (!ctx || ctx->sec_level >= HARDENING_LEVEL_MAX)
		return 0;
		
	policy = &level_policies[ctx->sec_level];
	
	/* Check if capability is denied at current level */
	if (policy->denied_capabilities & CAP_TO_MASK(cap)) {
		pr_notice("hardening: capability %d denied at security level %s\n",
			  cap, security_level_names[ctx->sec_level]);
		return -EPERM;
	}
	
	return 0;
}

int hardening_check_resource_limit(struct hardening_task_ctx *ctx,
				   int resource_type, u32 value)
{
	const struct security_level_policy *policy;
	
	if (!ctx || ctx->sec_level >= HARDENING_LEVEL_MAX)
		return 0;
		
	policy = &level_policies[ctx->sec_level];
	
	switch (resource_type) {
	case 0:	/* File descriptors */
		if (policy->max_file_descriptors > 0 &&
		    value > policy->max_file_descriptors)
			return -EMFILE;
		break;
	case 1:	/* Processes */
		if (policy->max_processes > 0 &&
		    value > policy->max_processes)
			return -EAGAIN;
		break;
	}
	
	return 0;
}

const struct security_level_policy *hardening_get_level_policy(
					enum hardening_security_level level)
{
	if (level >= HARDENING_LEVEL_MAX)
		return NULL;
	return &level_policies[level];
}