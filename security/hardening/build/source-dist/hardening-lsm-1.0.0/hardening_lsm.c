// SPDX-License-Identifier: GPL-2.0-only
/*
 * Security Hardening Module
 *
 * This module provides unique security controls:
 * - Temporal Access Control (time-based policies)
 * - Behavioral Anomaly Detection
 * - Resource Usage Fingerprinting
 * - Adaptive Security Levels
 */

#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include "hardening.h"

int hardening_enabled = 1;
int hardening_enforce = 0;

/* Forward declarations */
extern struct hardening_behavior_profile *hardening_alloc_behavior_profile(void);
extern void hardening_free_behavior_profile(struct hardening_behavior_profile *behavior);
extern struct hardening_resource_baseline *hardening_alloc_resource_baseline(void);
extern void hardening_free_resource_baseline(struct hardening_resource_baseline *res);
extern void hardening_cleanup_time_rules(struct hardening_task_ctx *ctx);
extern void hardening_free_lineage(struct hardening_lineage *lineage);
extern void hardening_free_container_ctx(struct hardening_container_ctx *container);
extern void hardening_free_network_profile(struct hardening_network_profile *network);
extern void hardening_free_memory_profile(struct hardening_memory_profile *memory);
extern void hardening_free_crypto(struct hardening_crypto_ctx *crypto);
extern void hardening_init_entropy(struct hardening_task_ctx *ctx);
extern int hardening_init_profiles(void);
extern void hardening_cleanup_profiles(void);

static struct hardening_task_ctx *hardening_alloc_task_ctx(void)
{
	struct hardening_task_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	spin_lock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->time_rules);
	ctx->sec_level = HARDENING_LEVEL_NORMAL;

#ifdef CONFIG_SECURITY_HARDENING_BEHAVIOR
	/* Allocate behavior profile */
	ctx->behavior = hardening_alloc_behavior_profile();
	if (!ctx->behavior)
		goto err_behavior;
#endif

#ifdef CONFIG_SECURITY_HARDENING_RESOURCES
	/* Allocate resource baseline */
	ctx->resources = hardening_alloc_resource_baseline();
	if (!ctx->resources)
		goto err_resources;
#endif

#ifdef CONFIG_SECURITY_HARDENING_LINEAGE
	/* Initialize lineage tracking */
	if (hardening_init_lineage(ctx) < 0)
		pr_warn("hardening: failed to init lineage for %s[%d]\n",
			current->comm, current->pid);
#endif

#ifdef CONFIG_SECURITY_HARDENING_CONTAINER
	/* Initialize container context if applicable */
	hardening_init_container_ctx(ctx);
#endif

#ifdef CONFIG_SECURITY_HARDENING_NETWORK
	/* Initialize network profile */
	hardening_init_network_profile(ctx);
#endif

#ifdef CONFIG_SECURITY_HARDENING_MEMORY
	/* Initialize memory profile */
	hardening_init_memory_profile(ctx);
#endif

#ifdef CONFIG_SECURITY_HARDENING_ENTROPY
	/* Initialize entropy */
	hardening_init_entropy(ctx);
#endif

#ifdef CONFIG_SECURITY_HARDENING_CRYPTO
	/* Initialize crypto context */
	hardening_init_crypto(ctx);
#endif

	return ctx;

#ifdef CONFIG_SECURITY_HARDENING_RESOURCES
err_resources:
#ifdef CONFIG_SECURITY_HARDENING_BEHAVIOR
	hardening_free_behavior_profile(ctx->behavior);
#endif
#endif
#ifdef CONFIG_SECURITY_HARDENING_BEHAVIOR
err_behavior:
#endif
	kfree(ctx);
	return NULL;
}

static void hardening_free_task_ctx(struct hardening_task_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef CONFIG_SECURITY_HARDENING_TEMPORAL
	hardening_cleanup_time_rules(ctx);
#endif
	
#ifdef CONFIG_SECURITY_HARDENING_BEHAVIOR
	if (ctx->behavior)
		hardening_free_behavior_profile(ctx->behavior);
#endif
	
#ifdef CONFIG_SECURITY_HARDENING_RESOURCES
	if (ctx->resources)
		hardening_free_resource_baseline(ctx->resources);
#endif

#ifdef CONFIG_SECURITY_HARDENING_LINEAGE
	if (ctx->lineage)
		hardening_free_lineage(ctx->lineage);
#endif

#ifdef CONFIG_SECURITY_HARDENING_CONTAINER
	if (ctx->container)
		hardening_free_container_ctx(ctx->container);
#endif

#ifdef CONFIG_SECURITY_HARDENING_NETWORK
	if (ctx->network)
		hardening_free_network_profile(ctx->network);
#endif

#ifdef CONFIG_SECURITY_HARDENING_MEMORY
	if (ctx->memory)
		hardening_free_memory_profile(ctx->memory);
#endif

#ifdef CONFIG_SECURITY_HARDENING_CRYPTO
	if (ctx->crypto)
		hardening_free_crypto(ctx->crypto);
#endif
	
	kfree(ctx);
}

static int hardening_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct hardening_task_ctx *ctx;

	if (!hardening_enabled)
		return 0;

	ctx = hardening_alloc_task_ctx();
	if (!ctx)
		return -ENOMEM;

	cred->security = ctx;
	return 0;
}

static void hardening_cred_free(struct cred *cred)
{
	struct hardening_task_ctx *ctx = cred->security;
	
	if (ctx) {
		hardening_free_task_ctx(ctx);
		cred->security = NULL;
	}
}

static int hardening_bprm_creds_for_exec(struct linux_binprm *bprm)
{
	struct hardening_task_ctx *ctx;

	if (!hardening_enabled)
		return 0;

	/* Get or create context */
	ctx = bprm->cred->security;
	if (!ctx) {
		ctx = hardening_alloc_task_ctx();
		if (!ctx)
			return -ENOMEM;
		bprm->cred->security = ctx;
	}

	/* Initialize for new process */
	ctx->flags |= HARDENING_FLAG_LEARNING;

	pr_debug("hardening: initialized task context for %s\n", bprm->filename);
	return 0;
}

static int hardening_task_prctl(int option, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5)
{
	struct hardening_task_ctx *ctx;
	struct cred *cred;

	if (!hardening_enabled)
		return -ENOSYS;

	cred = (struct cred *)current_cred();
	ctx = cred->security;

	switch (option) {
	case PR_HARDENING_STATUS:
		return hardening_enforce ? 1 : 0;
	default:
		return -ENOSYS;
	}
}

static int hardening_ptrace_access_check(struct task_struct *child,
					 unsigned int mode)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;

	if (!hardening_enabled || !hardening_enforce)
		return 0;

	cred = get_task_cred(child);
	ctx = cred->security;
	put_cred(cred);

	if (ctx && ctx->sec_level >= HARDENING_LEVEL_HIGH) {
		pr_notice("hardening: blocked ptrace attach to %s[%d] "
			  "(security level: %d)\n",
			  child->comm, child->pid, ctx->sec_level);
		return -EPERM;
	}

	return 0;
}

static int hardening_capable(const struct cred *cred,
			     struct user_namespace *ns,
			     int cap, unsigned int opts)
{
	struct hardening_task_ctx *ctx;

	if (!hardening_enabled || !hardening_enforce)
		return 0;

	ctx = cred->security;
	if (!ctx)
		return 0;

	/* Check capability against current security level */
	return hardening_check_capability(ctx, cap);
}

static int hardening_file_open(struct file *file)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;

	if (!hardening_enabled)
		return 0;

	cred = current_cred();
	ctx = cred->security;
	if (!ctx)
		return 0;

	/* Check temporal access control */
	return hardening_check_time_access(ctx);
}

/* File permission check - use this as periodic check point */
static int hardening_file_permission(struct file *file, int mask)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;

	if (!hardening_enabled)
		return 0;

	cred = current_cred();
	ctx = cred->security;
	if (!ctx)
		return 0;

	/* Update resource usage periodically */
	hardening_update_resources(ctx);

	/* Check for resource deviations */
	hardening_check_resource_deviation(ctx);

	/* Auto-deescalate security if appropriate */
	hardening_deescalate_security(ctx);

	return 0;
}

static const struct lsm_id hardening_lsmid = {
	.name = "hardening",
	.id = 110,	/* Arbitrary ID for our module */
};

/* Memory operation hooks */
static int hardening_mmap_addr(unsigned long addr)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;
	
	if (!hardening_enabled)
		return 0;
		
	cred = current_cred();
	ctx = cred->security;
	if (!ctx)
		return 0;

#ifdef CONFIG_SECURITY_HARDENING_MEMORY
	return hardening_track_memory_operation(ctx, MEM_OP_MMAP, addr, 0, 0);
#else
	return 0;
#endif
}

static int hardening_file_mprotect(struct vm_area_struct *vma,
				   unsigned long reqprot, unsigned long prot)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;
	
	if (!hardening_enabled)
		return 0;
		
	cred = current_cred();
	ctx = cred->security;
	if (!ctx)
		return 0;

#ifdef CONFIG_SECURITY_HARDENING_MEMORY
	return hardening_track_memory_operation(ctx, MEM_OP_MPROTECT,
						vma->vm_start,
						vma->vm_end - vma->vm_start,
						prot);
#else
	return 0;
#endif
}

/* Network hooks */
#ifdef CONFIG_SECURITY_HARDENING_NETWORK
extern int hardening_socket_create(int family, int type, int protocol);
extern int hardening_socket_connect(struct socket *sock,
				    struct sockaddr *address, int addrlen);

static int hardening_socket_create_hook(int family, int type,
					int protocol, int kern)
{
	if (kern)	/* Kernel socket */
		return 0;
	return hardening_socket_create(family, type, protocol);
}

static int hardening_socket_connect_hook(struct socket *sock,
					 struct sockaddr *address, int addrlen)
{
	return hardening_socket_connect(sock, address, addrlen);
}
#endif

static struct security_hook_list hardening_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(ptrace_access_check, hardening_ptrace_access_check),
	LSM_HOOK_INIT(capable, hardening_capable),
	LSM_HOOK_INIT(file_open, hardening_file_open),
	LSM_HOOK_INIT(file_permission, hardening_file_permission),
	LSM_HOOK_INIT(cred_alloc_blank, hardening_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, hardening_cred_free),
	LSM_HOOK_INIT(bprm_creds_for_exec, hardening_bprm_creds_for_exec),
	LSM_HOOK_INIT(task_prctl, hardening_task_prctl),
	LSM_HOOK_INIT(mmap_addr, hardening_mmap_addr),
	LSM_HOOK_INIT(file_mprotect, hardening_file_mprotect),
#ifdef CONFIG_SECURITY_HARDENING_NETWORK
	LSM_HOOK_INIT(socket_create, hardening_socket_create_hook),
	LSM_HOOK_INIT(socket_connect, hardening_socket_connect_hook),
#endif
};

#ifdef CONFIG_SYSCTL
static struct ctl_table hardening_sysctl_table[] = {
	{
		.procname       = "enabled",
		.data           = &hardening_enabled,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
	{
		.procname       = "enforce",
		.data           = &hardening_enforce,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1         = SYSCTL_ZERO,
		.extra2         = SYSCTL_ONE,
	},
};

static void __init hardening_init_sysctl(void)
{
	if (!register_sysctl("kernel/hardening", hardening_sysctl_table))
		panic("Hardening: sysctl registration failed.\n");
}
#else
static inline void hardening_init_sysctl(void) { }
#endif

static int __init hardening_init(void)
{
	pr_info("Security Hardening Module initializing\n");

	security_add_hooks(hardening_hooks, ARRAY_SIZE(hardening_hooks),
			   &hardening_lsmid);
	
	hardening_init_sysctl();
	
#ifdef CONFIG_SECURITYFS
	if (hardening_init_securityfs() < 0)
		pr_warn("hardening: failed to initialize securityfs\n");
#endif

#ifdef CONFIG_SECURITY_HARDENING_SYSCALL_FILTER
	if (syscall_filter_init() < 0)
		pr_warn("hardening: failed to initialize syscall filter\n");
#endif

	pr_info("Security Hardening Module initialized\n");
	return 0;
}

DEFINE_LSM(hardening) = {
	.name = "hardening",
	.init = hardening_init,
};