// SPDX-License-Identifier: GPL-2.0-only
/*
 * Process Lineage Tracking for Security Hardening Module
 *
 * Tracks process ancestry to detect suspicious process chains
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include "hardening.h"

/* Known suspicious process chains */
static const char *suspicious_chains[][3] = {
	/* Web server spawning shell */
	{"httpd", "sh", NULL},
	{"nginx", "bash", NULL},
	{"apache2", "sh", NULL},
	
	/* Database spawning shell */
	{"mysqld", "sh", NULL},
	{"postgres", "bash", NULL},
	
	/* Scripting engine chains */
	{"php", "sh", "wget"},
	{"python", "sh", "curl"},
	
	/* Container escape patterns */
	{"containerd", "nsenter", "sh"},
	{"docker", "nsenter", "bash"},
};

/* Initialize process lineage tracking */
int hardening_init_lineage(struct hardening_task_ctx *ctx)
{
	struct hardening_lineage *lineage;
	struct task_struct *task, *parent;
	int depth = 0;
	
	lineage = kzalloc(sizeof(*lineage), GFP_KERNEL);
	if (!lineage)
		return -ENOMEM;
	
	/* Walk up process tree */
	task = current;
	rcu_read_lock();
	
	while (task && depth < HARDENING_MAX_LINEAGE_DEPTH) {
		lineage->ancestors[depth] = task->pid;
		
		parent = rcu_dereference(task->real_parent);
		if (!parent || parent == task || parent->pid == 1)
			break;
			
		task = parent;
		depth++;
	}
	
	rcu_read_unlock();
	
	lineage->depth = depth;
	
	/* Calculate lineage hash for quick comparison */
	lineage->lineage_hash = jhash(lineage->ancestors, 
				      depth * sizeof(pid_t), 0);
	
	/* Check if this is a suspicious chain */
	lineage->suspicious_chain = hardening_is_suspicious_lineage(lineage);
	
	ctx->lineage = lineage;
	
	if (lineage->suspicious_chain) {
		pr_notice("hardening: suspicious process lineage detected for %s[%d]\n",
			  current->comm, current->pid);
	}
	
	return 0;
}

/* Check if process lineage matches known suspicious patterns */
bool hardening_is_suspicious_lineage(struct hardening_lineage *lineage)
{
	struct task_struct *task;
	char comm[TASK_COMM_LEN];
	int i, j, depth;
	
	if (!lineage || lineage->depth < 2)
		return false;
	
	/* Build command name array for current lineage */
	for (i = 0; i < lineage->depth && i < 3; i++) {
		task = find_task_by_vpid(lineage->ancestors[i]);
		if (!task)
			continue;
			
		get_task_comm(comm, task);
		
		/* Check against suspicious patterns */
		for (j = 0; j < ARRAY_SIZE(suspicious_chains); j++) {
			const char **pattern = suspicious_chains[j];
			int match_count = 0;
			
			/* Match pattern against lineage */
			for (depth = 0; pattern[depth] && depth < 3; depth++) {
				if (i + depth >= lineage->depth)
					break;
					
				task = find_task_by_vpid(lineage->ancestors[i + depth]);
				if (!task)
					break;
					
				get_task_comm(comm, task);
				if (strstr(comm, pattern[depth]))
					match_count++;
			}
			
			/* If all pattern elements matched, it's suspicious */
			if (match_count > 0 && match_count == depth)
				return true;
		}
	}
	
	return false;
}

/* Check lineage-based security policy */
int hardening_check_lineage(struct hardening_task_ctx *ctx)
{
	struct hardening_lineage *lineage;
	struct task_struct *parent;
	int depth_score = 0;
	
	if (!ctx || !ctx->lineage)
		return 0;
		
	lineage = ctx->lineage;
	
	/* Check if lineage is suspicious */
	if (lineage->suspicious_chain && hardening_enforce) {
		pr_notice("hardening: blocking operation due to suspicious lineage\n");
		return -EPERM;
	}
	
	/* Calculate depth score - deeper chains are more suspicious */
	if (lineage->depth > 10)
		depth_score = 10;
	else if (lineage->depth > 5)
		depth_score = 5;
		
	/* Check for rapid process creation (fork bomb) */
	rcu_read_lock();
	parent = current->real_parent;
	if (parent && time_before(jiffies, parent->start_time + HZ)) {
		/* Parent created less than 1 second ago */
		depth_score += 20;
	}
	rcu_read_unlock();
	
	/* Update anomaly score based on lineage */
	if (depth_score > 15) {
		hardening_escalate_security(ctx);
	}
	
	return 0;
}

/* Free lineage tracking structure */
void hardening_free_lineage(struct hardening_lineage *lineage)
{
	kfree(lineage);
}