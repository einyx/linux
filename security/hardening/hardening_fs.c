// SPDX-License-Identifier: GPL-2.0-only
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
	
	pr_info("hardening: securityfs interface initialized successfully\n");
	return 0;
	
err:
	hardening_exit_securityfs();
	return -ENOMEM;
}

void hardening_exit_securityfs(void)
{
	securityfs_remove(policy_file);
	securityfs_remove(stats_file);
	securityfs_remove(status_file);
	securityfs_remove(hardening_dir);
}