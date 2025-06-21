// SPDX-License-Identifier: GPL-2.0-only
/*
 * Container-Aware Security for Hardening Module
 *
 * Provides enhanced security policies for containerized workloads
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cgroup.h>
#include <linux/nsproxy.h>
#include <linux/ipc_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/jhash.h>
#include <linux/string.h>
#include <net/net_namespace.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include "hardening.h"

/* Container security policies */
#define CONTAINER_POLICY_STRICT		0x00000001
#define CONTAINER_POLICY_NO_PRIVILEGE	0x00000002
#define CONTAINER_POLICY_NO_RAWIO	0x00000004
#define CONTAINER_POLICY_NO_NEWNS	0x00000008
#define CONTAINER_POLICY_READONLY_ROOT	0x00000010

/* Get container ID from cgroup path */
int hardening_get_container_id(u64 *container_id)
{
	/* Use PID namespace as a simple container indicator */
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	
	if (!pid_ns)
		return -EINVAL;
		
	/* Use namespace level as simple container ID */
	/* Level 0 = host, > 0 = container */
	*container_id = pid_ns->level;
	
	return 0;
}

/* Initialize container context */
int hardening_init_container_ctx(struct hardening_task_ctx *ctx)
{
	struct hardening_container_ctx *container;
	u64 container_id = 0;
	bool in_container = false;
	
	/* Check if we're in a container by examining namespaces */
	if (current->nsproxy) {
		/* Different PID namespace indicates container */
		if (current->nsproxy->pid_ns_for_children != &init_pid_ns)
			in_container = true;
			
		/* Different network namespace */
		if (current->nsproxy->net_ns != &init_net)
			in_container = true;
			
		/* User namespace (excluding init) */
		if (current->cred->user_ns != &init_user_ns)
			in_container = true;
	}
	
	if (!in_container)
		return 0;	/* Not in container */
		
	container = kzalloc(sizeof(*container), GFP_KERNEL);
	if (!container)
		return -ENOMEM;
		
	/* Get container ID */
	if (hardening_get_container_id(&container_id) == 0) {
		container->container_id = container_id;
	}
	
	/* Detect container runtime */
	if (strstr(current->comm, "docker"))
		strscpy(container->container_name, "docker", 64);
	else if (strstr(current->comm, "containerd"))
		strscpy(container->container_name, "containerd", 64);
	else if (strstr(current->comm, "runc"))
		strscpy(container->container_name, "runc", 64);
	else
		strscpy(container->container_name, "unknown", 64);
		
	/* Set default container policies */
	container->container_flags = CONTAINER_POLICY_STRICT |
				    CONTAINER_POLICY_NO_RAWIO;
				    
	ctx->container = container;
	
	pr_debug("hardening: container context initialized (id: %llx, runtime: %s)\n",
		 container_id, container->container_name);
		 
	return 0;
}

/* Apply container-specific security policies */
int hardening_apply_container_policy(struct hardening_task_ctx *ctx)
{
	struct hardening_container_ctx *container;
	
	if (!ctx || !ctx->container)
		return 0;
		
	container = ctx->container;
	
	/* Escalate security level for containers */
	if (ctx->sec_level < HARDENING_LEVEL_ELEVATED) {
		ctx->sec_level = HARDENING_LEVEL_ELEVATED;
		pr_debug("hardening: elevated security for container %llx\n",
			 container->container_id);
	}
	
	/* Apply strict policies */
	if (container->container_flags & CONTAINER_POLICY_STRICT) {
		/* Restrict dangerous capabilities */
		ctx->flags |= HARDENING_FLAG_BEHAVIOR_CHECK |
			      HARDENING_FLAG_RESOURCE_CHECK;
	}
	
	return 0;
}

/* Check container-specific operations */
int hardening_check_container_operation(struct hardening_task_ctx *ctx,
					int operation)
{
	struct hardening_container_ctx *container;
	
	if (!ctx || !ctx->container)
		return 0;
		
	container = ctx->container;
	
	/* Check namespace operations */
	switch (operation) {
	case 1:	/* CLONE_NEWNS */
		if (container->container_flags & CONTAINER_POLICY_NO_NEWNS) {
			pr_notice("hardening: blocked namespace creation in container\n");
			return -EPERM;
		}
		break;
		
	case 2:	/* CAP_SYS_ADMIN operations */
		if (container->container_flags & CONTAINER_POLICY_NO_PRIVILEGE) {
			pr_notice("hardening: blocked privileged operation in container\n");
			return -EPERM;
		}
		break;
		
	case 3:	/* Raw I/O operations */
		if (container->container_flags & CONTAINER_POLICY_NO_RAWIO) {
			pr_notice("hardening: blocked raw I/O in container\n");
			return -EPERM;
		}
		break;
	}
	
	return 0;
}

/* Container escape detection */
bool hardening_detect_container_escape(struct hardening_task_ctx *ctx)
{
	struct hardening_container_ctx *container;
	bool escape_detected = false;
	
	if (!ctx || !ctx->container)
		return false;
		
	container = ctx->container;
	
	/* Check if process is trying to access host filesystem */
	/* Note: get_fs_root requires proper locking in newer kernels */
	
	/* Check for suspicious behavior patterns */
	/* Container processes shouldn't have certain capabilities */
	
	/* Check for namespace manipulation */
	if (capable(CAP_SYS_ADMIN) && capable(CAP_SYS_CHROOT)) {
		/* Process has dangerous capabilities */
		escape_detected = true;
	}
	
	if (escape_detected) {
		pr_alert("hardening: potential container escape detected for %s[%d]\n",
			 current->comm, current->pid);
		hardening_escalate_security(ctx);
	}
	
	return escape_detected;
}

/* Free container context */
void hardening_free_container_ctx(struct hardening_container_ctx *container)
{
	kfree(container);
}