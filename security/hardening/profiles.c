/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Security Profile Management for Hardening Module
 *
 * Manages per-process security profiles
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include "hardening.h"

/* Global profile tree */
struct rb_root hardening_profiles = RB_ROOT;
DEFINE_RWLOCK(hardening_profiles_lock);

/* Predefined security profiles */
static struct hardening_security_profile builtin_profiles[] = {
	{
		.name = "web_server",
		.profile_id = 1,
		.allowed_capabilities = CAP_TO_MASK(CAP_NET_BIND_SERVICE) |
				       CAP_TO_MASK(CAP_SETUID) |
				       CAP_TO_MASK(CAP_SETGID),
		.network_policy = 0x0001,	/* Allow incoming connections */
		.filesystem_policy = 0x0002,	/* Read-only except logs */
		.max_memory_mb = 2048,
		.max_cpu_percent = 80,
		.max_file_descriptors = 4096,
		.max_threads = 200,
	},
	{
		.name = "database",
		.profile_id = 2,
		.allowed_capabilities = CAP_TO_MASK(CAP_NET_BIND_SERVICE) |
				       CAP_TO_MASK(CAP_IPC_LOCK),
		.network_policy = 0x0003,	/* Local connections only */
		.filesystem_policy = 0x0004,	/* Database files only */
		.max_memory_mb = 8192,
		.max_cpu_percent = 90,
		.max_file_descriptors = 8192,
		.max_threads = 500,
	},
	{
		.name = "container",
		.profile_id = 3,
		.allowed_capabilities = 0,	/* No special capabilities */
		.network_policy = 0x0002,	/* Outgoing only */
		.filesystem_policy = 0x0001,	/* Restricted filesystem */
		.max_memory_mb = 1024,
		.max_cpu_percent = 50,
		.max_file_descriptors = 1024,
		.max_threads = 100,
	},
	{
		.name = "developer",
		.profile_id = 4,
		.allowed_capabilities = ~0U,	/* All capabilities for dev */
		.network_policy = 0xFFFF,	/* Unrestricted */
		.filesystem_policy = 0xFFFF,	/* Unrestricted */
		.max_memory_mb = 16384,
		.max_cpu_percent = 100,
		.max_file_descriptors = 16384,
		.max_threads = 1000,
	},
};

/* Find profile by name in RB tree */
struct hardening_security_profile *hardening_find_profile(const char *name)
{
	struct rb_node *node;
	struct hardening_security_profile *profile;

	read_lock(&hardening_profiles_lock);

	node = hardening_profiles.rb_node;
	while (node) {
		profile = rb_entry(node, struct hardening_security_profile, node);
		int cmp = strcmp(name, profile->name);

		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else {
			read_unlock(&hardening_profiles_lock);
			return profile;
		}
	}

	read_unlock(&hardening_profiles_lock);

	/* Check builtin profiles */
	for (int i = 0; i < ARRAY_SIZE(builtin_profiles); i++) {
		if (strcmp(name, builtin_profiles[i].name) == 0)
			return &builtin_profiles[i];
	}

	return NULL;
}

/* Insert profile into RB tree */
static int insert_profile(struct hardening_security_profile *profile)
{
	struct rb_node **new = &hardening_profiles.rb_node;
	struct rb_node *parent = NULL;
	struct hardening_security_profile *this;

	write_lock(&hardening_profiles_lock);

	while (*new) {
		this = rb_entry(*new, struct hardening_security_profile, node);
		int cmp = strcmp(profile->name, this->name);

		parent = *new;
		if (cmp < 0)
			new = &((*new)->rb_left);
		else if (cmp > 0)
			new = &((*new)->rb_right);
		else {
			write_unlock(&hardening_profiles_lock);
			return -EEXIST;	/* Profile already exists */
		}
	}

	rb_link_node(&profile->node, parent, new);
	rb_insert_color(&profile->node, &hardening_profiles);

	write_unlock(&hardening_profiles_lock);
	return 0;
}

/* Load a new security profile */
int hardening_load_profile(const char *name,
			   struct hardening_security_profile *new_profile)
{
	struct hardening_security_profile *profile;
	static u32 next_profile_id = 1000;	/* IDs 1000+ for custom profiles */

	if (!name || !new_profile)
		return -EINVAL;

	/* Check profile limit */
	if (rb_first(&hardening_profiles)) {
		int count = 0;
		struct rb_node *node;

		read_lock(&hardening_profiles_lock);
		for (node = rb_first(&hardening_profiles); node; node = rb_next(node))
			count++;
		read_unlock(&hardening_profiles_lock);

		if (count >= CONFIG_SECURITY_HARDENING_PROFILES_MAX)
			return -ENOSPC;
	}

	/* Allocate new profile */
	profile = kmalloc(sizeof(*profile), GFP_KERNEL);
	if (!profile)
		return -ENOMEM;

	/* Copy profile data */
	*profile = *new_profile;
	strscpy(profile->name, name, sizeof(profile->name));
	profile->profile_id = next_profile_id++;

	/* Insert into tree */
	if (insert_profile(profile) < 0) {
		kfree(profile);
		return -EEXIST;
	}

	pr_info("hardening: loaded security profile '%s' (id: %u)\n",
		name, profile->profile_id);

	return 0;
}

/* Apply security profile to task */
int hardening_apply_profile(struct hardening_task_ctx *ctx,
			    const char *profile_name)
{
	struct hardening_security_profile *profile;

	if (!ctx || !profile_name)
		return -EINVAL;

	/* Find profile */
	profile = hardening_find_profile(profile_name);
	if (!profile) {
		pr_err("hardening: profile '%s' not found\n", profile_name);
		return -ENOENT;
	}

	/* Apply profile */
	ctx->profile = profile;

	/* Apply profile-specific time rules if any */
	if (profile->time_rules) {
		for (u32 i = 0; i < profile->time_rule_count; i++) {
			hardening_add_time_rule(ctx, &profile->time_rules[i]);
		}
	}

	pr_info("hardening: applied profile '%s' to %s[%d]\n",
		profile_name, current->comm, current->pid);

	return 0;
}

/* Check if operation is allowed by profile */
int hardening_check_profile_policy(struct hardening_task_ctx *ctx,
				   int policy_type, u32 value)
{
	struct hardening_security_profile *profile;

	if (!ctx || !ctx->profile)
		return 0;	/* No profile, allow */

	profile = ctx->profile;

	switch (policy_type) {
	case 0:	/* Capability check */
		if (!(profile->allowed_capabilities & value)) {
			pr_notice("hardening: capability %u denied by profile '%s'\n",
				  value, profile->name);
			return -EPERM;
		}
		break;

	case 1:	/* Network policy */
		if (!(profile->network_policy & value)) {
			pr_notice("hardening: network operation denied by profile '%s'\n",
				  profile->name);
			return -EPERM;
		}
		break;

	case 2:	/* Filesystem policy */
		if (!(profile->filesystem_policy & value)) {
			pr_notice("hardening: filesystem operation denied by profile '%s'\n",
				  profile->name);
			return -EPERM;
		}
		break;

	case 3:	/* Resource limits */
		/* Check various resource limits */
		if (current->mm) {
			unsigned long memory_mb = get_mm_rss(current->mm) >> 8;
			if (memory_mb > profile->max_memory_mb) {
				pr_notice("hardening: memory limit exceeded (%lu > %u MB)\n",
					  memory_mb, profile->max_memory_mb);
				return -ENOMEM;
			}
		}
		break;
	}

	return 0;
}

/* Initialize builtin profiles */
int hardening_init_profiles(void)
{
	int i;

	pr_info("hardening: initializing security profiles\n");

	/* Builtin profiles are statically allocated */
	for (i = 0; i < ARRAY_SIZE(builtin_profiles); i++) {
		pr_debug("hardening: registered builtin profile '%s'\n",
			 builtin_profiles[i].name);
	}

	return 0;
}

/* Cleanup profiles */
void hardening_cleanup_profiles(void)
{
	struct rb_node *node;
	struct hardening_security_profile *profile;

	write_lock(&hardening_profiles_lock);

	/* Free all custom profiles */
	while ((node = rb_first(&hardening_profiles))) {
		profile = rb_entry(node, struct hardening_security_profile, node);
		rb_erase(node, &hardening_profiles);

		/* Don't free builtin profiles */
		if (profile->profile_id >= 1000) {
			kfree(profile->time_rules);
			kfree(profile);
		}
	}

	write_unlock(&hardening_profiles_lock);
}