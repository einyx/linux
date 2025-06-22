/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SecurityFS interface for Security Hardening Module
 */

#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/cred.h>
#include "hardening.h"

static struct dentry *hardening_dir;
static struct dentry *status_file;
static struct dentry *stats_file;
static struct dentry *policy_file;
static struct dentry *quantum_file;

/* Show current module status */
static int hardening_status_show(struct seq_file *m, void *v)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;
	const char *sec_level_names[] = {
		"Normal", "Elevated", "High", "Critical"
	};

	seq_printf(m, "Security Hardening Module Status\n");
	seq_printf(m, "================================\n\n");

	seq_printf(m, "Global Settings:\n");
	seq_printf(m, "  Module enabled: %s\n",
		   hardening_enabled ? "yes" : "no");
	seq_printf(m, "  Enforcement mode: %s\n",
		   hardening_enforce ? "enforcing" : "permissive");

	cred = current_cred();
	ctx = cred->security;
	if (ctx) {
		seq_printf(m, "\nCurrent Process [%s:%d]:\n",
			   current->comm, current->pid);
		seq_printf(m, "  Security level: %s (%d)\n",
			   ctx->sec_level < HARDENING_LEVEL_MAX ?
			   sec_level_names[ctx->sec_level] : "Unknown",
			   ctx->sec_level);
		seq_printf(m, "  Violations: %u\n", ctx->violation_count);
		seq_printf(m, "  Flags: 0x%08x\n", ctx->flags);

#ifdef CONFIG_SECURITY_HARDENING_TEMPORAL
		seq_printf(m, "\nTemporal Control:\n");
		seq_printf(m, "  Time restricted: %s\n",
			   ctx->time_restricted ? "yes" : "no");
#endif

#ifdef CONFIG_SECURITY_HARDENING_BEHAVIOR
		if (ctx->behavior) {
			seq_printf(m, "\nBehavioral Analysis:\n");
			seq_printf(m, "  Anomaly score: %u%%\n",
				   ctx->behavior->anomaly_score);
			seq_printf(m, "  Pattern entropy: %u\n",
				   ctx->behavior->pattern_entropy);
			seq_printf(m, "  Total transitions: %u\n",
				   ctx->behavior->total_transitions);
		}
#endif

#ifdef CONFIG_SECURITY_HARDENING_RESOURCES
		if (ctx->resources) {
			seq_printf(m, "\nResource Monitoring:\n");
			seq_printf(m, "  Learning mode: %s\n",
				   ctx->resources->learning_mode ? "yes" : "no");
			seq_printf(m, "  Deviation count: %u\n",
				   ctx->resources->deviation_count);
		}
#endif

#ifdef CONFIG_SECURITY_HARDENING_LINEAGE
		if (ctx->lineage) {
			seq_printf(m, "\nProcess Lineage:\n");
			seq_printf(m, "  Depth: %u\n", ctx->lineage->depth);
			seq_printf(m, "  Suspicious: %s\n",
				   ctx->lineage->suspicious_chain ? "yes" : "no");
		}
#endif

#ifdef CONFIG_SECURITY_HARDENING_CONTAINER
		if (ctx->container) {
			seq_printf(m, "\nContainer Context:\n");
			seq_printf(m, "  Container ID: 0x%llx\n",
				   ctx->container->container_id);
			seq_printf(m, "  Runtime: %s\n",
				   ctx->container->container_name);
		}
#endif

#ifdef CONFIG_SECURITY_HARDENING_NETWORK
		if (ctx->network) {
			seq_printf(m, "\nNetwork Profile:\n");
			seq_printf(m, "  Total connections: %u\n",
				   ctx->network->total_connections);
			seq_printf(m, "  Failed connections: %u\n",
				   ctx->network->failed_connections);
			seq_printf(m, "  Network anomaly score: %u\n",
				   ctx->network->network_anomaly_score);
		}
#endif

#ifdef CONFIG_SECURITY_HARDENING_MEMORY
		if (ctx->memory) {
			seq_printf(m, "\nMemory Profile:\n");
			seq_printf(m, "  Executable mappings: %u\n",
				   ctx->memory->executable_mappings);
			seq_printf(m, "  RWX mappings: %u\n",
				   ctx->memory->rwx_mappings);
			seq_printf(m, "  Heap spray detected: %s\n",
				   ctx->memory->heap_spray_detected ? "yes" : "no");
		}
#endif

		if (ctx->profile) {
			seq_printf(m, "\nSecurity Profile:\n");
			seq_printf(m, "  Name: %s\n", ctx->profile->name);
			seq_printf(m, "  ID: %u\n", ctx->profile->profile_id);
		}

#ifdef CONFIG_SECURITY_HARDENING_QUANTUM
		if (ctx->quantum) {
			seq_printf(m, "\nQuantum-Resistant Crypto:\n");
			seq_printf(m, "  Authenticated: %s\n",
				   hardening_quantum_is_authenticated(ctx) ? "yes" : "no");
			seq_printf(m, "  Active channels: %u\n",
				   ctx->quantum->active_channels);
			seq_printf(m, "  Keys generated: %llu\n",
				   ctx->quantum->keys_generated);
			seq_printf(m, "  Signatures created: %llu\n",
				   ctx->quantum->signatures_created);
			seq_printf(m, "  Signatures verified: %llu\n",
				   ctx->quantum->signatures_verified);
			seq_printf(m, "  Key exchanges: %llu\n",
				   ctx->quantum->key_exchanges);
		}
#endif
	}

	return 0;
}

static int hardening_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, hardening_status_show, NULL);
}

static const struct file_operations hardening_status_fops = {
	.open		= hardening_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* Show system-wide statistics */
static int hardening_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Security Hardening Module Statistics\n");
	seq_printf(m, "====================================\n\n");

	seq_printf(m, "Global Statistics:\n");
	seq_printf(m, "  Module enabled: %s\n",
		   hardening_enabled ? "yes" : "no");
	seq_printf(m, "  Enforcement mode: %s\n",
		   hardening_enforce ? "enforcing" : "permissive");

	/* TODO: Add more global statistics */

	return 0;
}

static int hardening_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, hardening_stats_show, NULL);
}

static const struct file_operations hardening_stats_fops = {
	.open		= hardening_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* Policy configuration interface */
static ssize_t hardening_policy_write(struct file *file,
				      const char __user *buf,
				      size_t count, loff_t *ppos)
{
	char *kbuf;
	char *p, *cmd, *arg;
	int ret = count;

	if (count > PAGE_SIZE)
		return -E2BIG;

	kbuf = memdup_user_nul(buf, count);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	/* Simple command parser */
	p = kbuf;
	cmd = strsep(&p, " \t");
	if (!cmd) {
		ret = -EINVAL;
		goto out;
	}

	arg = strsep(&p, " \t\n");

	if (strcmp(cmd, "enable") == 0) {
		hardening_enabled = 1;
		pr_info("hardening: module enabled\n");
	} else if (strcmp(cmd, "disable") == 0) {
		hardening_enabled = 0;
		pr_info("hardening: module disabled\n");
	} else if (strcmp(cmd, "enforce") == 0) {
		hardening_enforce = 1;
		pr_info("hardening: enforcement enabled\n");
	} else if (strcmp(cmd, "permissive") == 0) {
		hardening_enforce = 0;
		pr_info("hardening: enforcement disabled (permissive mode)\n");
	} else {
		pr_err("hardening: unknown command '%s'\n", cmd);
		ret = -EINVAL;
	}

out:
	kfree(kbuf);
	return ret;
}

static const struct file_operations hardening_policy_fops = {
	.write		= hardening_policy_write,
	.llseek		= generic_file_llseek,
};

#ifdef CONFIG_SECURITY_HARDENING_QUANTUM
/* Show quantum crypto status */
static int hardening_quantum_show(struct seq_file *m, void *v)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;
	const char *algo_names[] = {
		"KYBER768", "KYBER1024", "DILITHIUM3", "DILITHIUM5",
		"FALCON512", "SPHINCS+"
	};

	cred = current_cred();
	ctx = cred->security;

	seq_printf(m, "Quantum-Resistant Cryptography Status\n");
	seq_printf(m, "====================================\n\n");

	if (!ctx || !ctx->quantum) {
		seq_printf(m, "Quantum crypto not initialized for this process\n");
		return 0;
	}

	seq_printf(m, "Configuration:\n");
	seq_printf(m, "  Preferred KEM: %s\n",
		   algo_names[ctx->quantum->preferred_kem]);
	seq_printf(m, "  Preferred Signature: %s\n",
		   algo_names[ctx->quantum->preferred_sig]);
	seq_printf(m, "  Require quantum auth: %s\n",
		   ctx->quantum->require_quantum_auth ? "yes" : "no");
	seq_printf(m, "  Classical fallback: %s\n",
		   ctx->quantum->allow_classical_fallback ? "yes" : "no");
	seq_printf(m, "  Min security level: %u\n",
		   ctx->quantum->min_security_level);

	seq_printf(m, "\nStatistics:\n");
	seq_printf(m, "  Keys generated: %llu\n", ctx->quantum->keys_generated);
	seq_printf(m, "  Signatures created: %llu\n", ctx->quantum->signatures_created);
	seq_printf(m, "  Signatures verified: %llu\n", ctx->quantum->signatures_verified);
	seq_printf(m, "  Key exchanges: %llu\n", ctx->quantum->key_exchanges);
	seq_printf(m, "  Active channels: %u\n", ctx->quantum->active_channels);

	if (ctx->quantum->identity_key) {
		u64 now = ktime_get_real_seconds();
		u64 remaining = ctx->quantum->identity_key->expiration_time > now ?
				ctx->quantum->identity_key->expiration_time - now : 0;

		seq_printf(m, "\nIdentity Key:\n");
		seq_printf(m, "  Algorithm: %s\n",
			   algo_names[ctx->quantum->identity_key->pq_algo]);
		seq_printf(m, "  Expires in: %llu seconds\n", remaining);
		seq_printf(m, "  Usage count: %u\n",
			   ctx->quantum->identity_key->usage_count);
	}

	return 0;
}

static int hardening_quantum_open(struct inode *inode, struct file *file)
{
	return single_open(file, hardening_quantum_show, NULL);
}

/* Handle quantum crypto commands */
static ssize_t hardening_quantum_write(struct file *file, const char __user *ubuf,
				      size_t count, loff_t *ppos)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;
	char *kbuf, *cmd;
	ssize_t ret = count;

	if (count > PAGE_SIZE)
		return -E2BIG;

	kbuf = memdup_user_nul(ubuf, count);
	if (IS_ERR(kbuf))
		return PTR_ERR(kbuf);

	cmd = strstrip(kbuf);

	cred = current_cred();
	ctx = cred->security;

	if (!ctx || !ctx->quantum) {
		pr_err("hardening: quantum crypto not initialized\n");
		ret = -EINVAL;
		goto out;
	}

	if (strcmp(cmd, "rotate") == 0) {
		ret = hardening_quantum_rotate_keys(ctx->quantum);
		if (ret == 0) {
			pr_info("hardening: quantum keys rotated\n");
			ret = count;
		}
	} else if (strcmp(cmd, "authenticate") == 0) {
		ret = hardening_quantum_authenticate_process(ctx);
		if (ret == 0) {
			pr_info("hardening: process quantum authenticated\n");
			ret = count;
		}
	} else if (strncmp(cmd, "channel ", 8) == 0) {
		u32 target_pid;
		if (sscanf(cmd + 8, "%u", &target_pid) == 1) {
			ret = hardening_quantum_establish_channel(ctx->quantum, target_pid);
			if (ret == 0) {
				pr_info("hardening: quantum channel established to PID %u\n",
					target_pid);
				ret = count;
			}
		} else {
			ret = -EINVAL;
		}
	} else {
		pr_err("hardening: unknown quantum command '%s'\n", cmd);
		ret = -EINVAL;
	}

out:
	kfree(kbuf);
	return ret;
}

static const struct file_operations hardening_quantum_fops = {
	.open		= hardening_quantum_open,
	.read		= seq_read,
	.write		= hardening_quantum_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

int hardening_init_securityfs(void)
{
	pr_info("hardening: initializing securityfs interface\n");

	hardening_dir = securityfs_create_dir("hardening", NULL);
	if (IS_ERR(hardening_dir)) {
		pr_err("hardening: failed to create securityfs directory (err=%ld)\n",
		       PTR_ERR(hardening_dir));
		return PTR_ERR(hardening_dir);
	}

	pr_info("hardening: created securityfs directory successfully\n");

	status_file = securityfs_create_file("status", 0444,
					     hardening_dir, NULL,
					     &hardening_status_fops);
	if (IS_ERR(status_file)) {
		pr_err("hardening: failed to create status file\n");
		goto err;
	}

	stats_file = securityfs_create_file("stats", 0444,
					    hardening_dir, NULL,
					    &hardening_stats_fops);
	if (IS_ERR(stats_file)) {
		pr_err("hardening: failed to create stats file\n");
		goto err;
	}

	policy_file = securityfs_create_file("policy", 0600,
					     hardening_dir, NULL,
					     &hardening_policy_fops);
	if (IS_ERR(policy_file)) {
		pr_err("hardening: failed to create policy file\n");
		goto err;
	}

#ifdef CONFIG_SECURITY_HARDENING_QUANTUM
	quantum_file = securityfs_create_file("quantum", 0600,
					      hardening_dir, NULL,
					      &hardening_quantum_fops);
	if (IS_ERR(quantum_file)) {
		pr_err("hardening: failed to create quantum file\n");
		goto err;
	}
#endif

	pr_info("hardening: securityfs interface initialized successfully\n");
	return 0;

err:
	hardening_exit_securityfs();
	return -ENOMEM;
}

void hardening_exit_securityfs(void)
{
#ifdef CONFIG_SECURITY_HARDENING_QUANTUM
	securityfs_remove(quantum_file);
#endif
	securityfs_remove(policy_file);
	securityfs_remove(stats_file);
	securityfs_remove(status_file);
	securityfs_remove(hardening_dir);
}