/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Security module rate limiting framework
 *
 * Copyright (C) 2024 Linux Security Module Rate Limiting
 *
 * This provides a generic rate limiting mechanism for security modules
 * to prevent denial of service attacks through excessive security checks.
 */

#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include "security_ratelimit.h"

#define SECURITY_RATELIMIT_BUCKETS	256
#define SECURITY_RATELIMIT_INTERVAL	(HZ * 5)	/* 5 seconds */
#define SECURITY_RATELIMIT_BURST	100		/* max events per interval */
#define SECURITY_RATELIMIT_CLEANUP	(HZ * 60)	/* cleanup every minute */

struct security_ratelimit_entry {
	struct list_head list;
	struct rcu_head rcu;
	uid_t uid;
	unsigned long last_time;
	unsigned int count;
	bool blocked;
};

struct security_ratelimit_ctx {
	struct list_head buckets[SECURITY_RATELIMIT_BUCKETS];
	spinlock_t locks[SECURITY_RATELIMIT_BUCKETS];
	struct delayed_work cleanup_work;
	unsigned int max_burst;
	unsigned int interval_jiffies;
};

static struct security_ratelimit_ctx *global_ratelimit_ctx;

static u32 security_ratelimit_hash(uid_t uid)
{
	return jhash_1word(uid, 0) & (SECURITY_RATELIMIT_BUCKETS - 1);
}

static struct security_ratelimit_entry *
security_ratelimit_find_entry(struct security_ratelimit_ctx *ctx, uid_t uid)
{
	u32 hash = security_ratelimit_hash(uid);
	struct security_ratelimit_entry *entry;

	list_for_each_entry_rcu(entry, &ctx->buckets[hash], list) {
		if (entry->uid == uid)
			return entry;
	}
	return NULL;
}

static void security_ratelimit_cleanup(struct work_struct *work)
{
	struct security_ratelimit_ctx *ctx = container_of(work,
		struct security_ratelimit_ctx, cleanup_work.work);
	unsigned long now = jiffies;
	int i;

	for (i = 0; i < SECURITY_RATELIMIT_BUCKETS; i++) {
		struct security_ratelimit_entry *entry, *tmp;
		unsigned long flags;

		spin_lock_irqsave(&ctx->locks[i], flags);
		list_for_each_entry_safe(entry, tmp, &ctx->buckets[i], list) {
			if (time_after(now, entry->last_time + ctx->interval_jiffies * 2)) {
				list_del_rcu(&entry->list);
				kfree_rcu(entry, rcu);
			}
		}
		spin_unlock_irqrestore(&ctx->locks[i], flags);
	}

	schedule_delayed_work(&ctx->cleanup_work, SECURITY_RATELIMIT_CLEANUP);
}

/**
 * security_ratelimit_check - Check if an action should be rate limited
 * @ctx: rate limit context
 * @uid: user ID to check
 *
 * Returns: 0 if action is allowed, -EBUSY if rate limited
 */
int security_ratelimit_check(struct security_ratelimit_ctx *ctx, uid_t uid)
{
	struct security_ratelimit_entry *entry;
	unsigned long now = jiffies;
	u32 hash = security_ratelimit_hash(uid);
	unsigned long flags;
	int ret = 0;

	if (!ctx)
		return 0;

	rcu_read_lock();
	entry = security_ratelimit_find_entry(ctx, uid);
	if (entry) {
		if (entry->blocked) {
			rcu_read_unlock();
			return -EBUSY;
		}

		if (time_after(now, entry->last_time + ctx->interval_jiffies)) {
			/* New interval, reset counter */
			spin_lock_irqsave(&ctx->locks[hash], flags);
			entry->count = 1;
			entry->last_time = now;
			entry->blocked = false;
			spin_unlock_irqrestore(&ctx->locks[hash], flags);
		} else if (entry->count >= ctx->max_burst) {
			/* Rate limit exceeded */
			spin_lock_irqsave(&ctx->locks[hash], flags);
			entry->blocked = true;
			spin_unlock_irqrestore(&ctx->locks[hash], flags);
			ret = -EBUSY;
		} else {
			/* Increment counter */
			spin_lock_irqsave(&ctx->locks[hash], flags);
			entry->count++;
			spin_unlock_irqrestore(&ctx->locks[hash], flags);
		}
	} else {
		/* Create new entry */
		struct security_ratelimit_entry *new_entry;

		rcu_read_unlock();

		new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC);
		if (!new_entry)
			return 0; /* Allow on allocation failure */

		new_entry->uid = uid;
		new_entry->last_time = now;
		new_entry->count = 1;
		new_entry->blocked = false;

		spin_lock_irqsave(&ctx->locks[hash], flags);
		list_add_rcu(&new_entry->list, &ctx->buckets[hash]);
		spin_unlock_irqrestore(&ctx->locks[hash], flags);

		return 0;
	}

	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(security_ratelimit_check);

/**
 * security_ratelimit_init - Initialize rate limiting context
 * @max_burst: maximum events per interval
 * @interval_ms: interval in milliseconds
 *
 * Returns: rate limit context or NULL on failure
 */
struct security_ratelimit_ctx *security_ratelimit_init(unsigned int max_burst,
							unsigned int interval_ms)
{
	struct security_ratelimit_ctx *ctx;
	int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->max_burst = max_burst;
	ctx->interval_jiffies = msecs_to_jiffies(interval_ms);

	for (i = 0; i < SECURITY_RATELIMIT_BUCKETS; i++) {
		INIT_LIST_HEAD(&ctx->buckets[i]);
		spin_lock_init(&ctx->locks[i]);
	}

	INIT_DELAYED_WORK(&ctx->cleanup_work, security_ratelimit_cleanup);
	schedule_delayed_work(&ctx->cleanup_work, SECURITY_RATELIMIT_CLEANUP);

	return ctx;
}
EXPORT_SYMBOL_GPL(security_ratelimit_init);

/**
 * security_ratelimit_destroy - Destroy rate limiting context
 * @ctx: rate limit context to destroy
 */
void security_ratelimit_destroy(struct security_ratelimit_ctx *ctx)
{
	int i;

	if (!ctx)
		return;

	cancel_delayed_work_sync(&ctx->cleanup_work);

	for (i = 0; i < SECURITY_RATELIMIT_BUCKETS; i++) {
		struct security_ratelimit_entry *entry, *tmp;

		list_for_each_entry_safe(entry, tmp, &ctx->buckets[i], list) {
			list_del(&entry->list);
			kfree(entry);
		}
	}

	kfree(ctx);
}
EXPORT_SYMBOL_GPL(security_ratelimit_destroy);

static int __init security_ratelimit_module_init(void)
{
	global_ratelimit_ctx = security_ratelimit_init(
		SECURITY_RATELIMIT_BURST,
		jiffies_to_msecs(SECURITY_RATELIMIT_INTERVAL));

	if (!global_ratelimit_ctx) {
		pr_err("Failed to initialize security rate limiting\n");
		return -ENOMEM;
	}

	pr_info("Security rate limiting initialized\n");
	return 0;
}

static void __exit security_ratelimit_module_exit(void)
{
	security_ratelimit_destroy(global_ratelimit_ctx);
	pr_info("Security rate limiting destroyed\n");
}

module_init(security_ratelimit_module_init);
module_exit(security_ratelimit_module_exit);

MODULE_DESCRIPTION("Security module rate limiting framework");
MODULE_LICENSE("GPL");