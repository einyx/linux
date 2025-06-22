/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Enhanced Security Audit Framework with Flood Protection
 *
 * Copyright (C) 2024 Linux Security Module Audit Framework
 *
 * Provides comprehensive audit logging with automatic flood detection
 * and mitigation for security modules.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <linux/ratelimit.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/security.h>

#define AUDIT_FLOOD_THRESHOLD		1000	/* msgs per interval */
#define AUDIT_FLOOD_INTERVAL		(HZ * 10) /* 10 seconds */
#define AUDIT_BUCKET_COUNT		64
#define AUDIT_SUMMARY_INTERVAL		(HZ * 60) /* 1 minute */

struct audit_flood_entry {
	struct list_head list;
	struct rcu_head rcu;
	u32 hash;
	char *event_type;
	uid_t uid;
	unsigned long count;
	unsigned long first_time;
	unsigned long last_time;
	bool suppressed;
};

struct security_audit_ctx {
	struct list_head buckets[AUDIT_BUCKET_COUNT];
	spinlock_t bucket_locks[AUDIT_BUCKET_COUNT];
	struct delayed_work summary_work;
	struct ratelimit_state ratelimit;
	
	/* Statistics */
	atomic64_t total_events;
	atomic64_t suppressed_events;
	atomic64_t unique_events;
};

static struct security_audit_ctx *global_audit_ctx;

static u32 audit_event_hash(const char *event_type, uid_t uid)
{
	u32 hash = jhash(event_type, strlen(event_type), 0);
	return jhash_2words(hash, uid, 0) & (AUDIT_BUCKET_COUNT - 1);
}

static struct audit_flood_entry *
find_flood_entry(struct security_audit_ctx *ctx, const char *event_type,
		 uid_t uid)
{
	u32 bucket = audit_event_hash(event_type, uid);
	struct audit_flood_entry *entry;
	
	list_for_each_entry_rcu(entry, &ctx->buckets[bucket], list) {
		if (entry->uid == uid && !strcmp(entry->event_type, event_type))
			return entry;
	}
	
	return NULL;
}

static void audit_summary_work(struct work_struct *work)
{
	struct security_audit_ctx *ctx = container_of(work,
		struct security_audit_ctx, summary_work.work);
	struct audit_flood_entry *entry;
	unsigned long now = jiffies;
	int i;
	
	pr_info("Security audit summary:\n");
	pr_info("  Total events: %llu\n", atomic64_read(&ctx->total_events));
	pr_info("  Suppressed events: %llu\n", atomic64_read(&ctx->suppressed_events));
	pr_info("  Unique event types: %llu\n", atomic64_read(&ctx->unique_events));
	
	/* Print top flooding events */
	pr_info("  Top flooding events:\n");
	
	for (i = 0; i < AUDIT_BUCKET_COUNT; i++) {
		unsigned long flags;
		
		spin_lock_irqsave(&ctx->bucket_locks[i], flags);
		list_for_each_entry(entry, &ctx->buckets[i], list) {
			if (entry->suppressed && entry->count > 100) {
				pr_info("    %s (uid:%u): %lu events suppressed\n",
					entry->event_type, entry->uid, entry->count);
			}
			
			/* Reset old entries */
			if (time_after(now, entry->last_time + AUDIT_FLOOD_INTERVAL * 6)) {
				entry->count = 0;
				entry->suppressed = false;
			}
		}
		spin_unlock_irqrestore(&ctx->bucket_locks[i], flags);
	}
	
	/* Schedule next summary */
	schedule_delayed_work(&ctx->summary_work, AUDIT_SUMMARY_INTERVAL);
}

/**
 * security_audit_log - Log a security event with flood protection
 * @event_type: type of security event
 * @uid: user ID associated with event
 * @fmt: format string for additional details
 * @...: format arguments
 *
 * Returns: 0 on success, -EBUSY if rate limited
 */
int security_audit_log(const char *event_type, uid_t uid, const char *fmt, ...)
{
	struct security_audit_ctx *ctx = global_audit_ctx;
	struct audit_flood_entry *entry;
	unsigned long now = jiffies;
	u32 bucket;
	unsigned long flags;
	va_list args;
	char buf[256];
	int ret = 0;
	
	if (!ctx)
		return -EINVAL;
		
	atomic64_inc(&ctx->total_events);
	
	/* Check global rate limit first */
	if (!__ratelimit(&ctx->ratelimit)) {
		atomic64_inc(&ctx->suppressed_events);
		return -EBUSY;
	}
	
	/* Find or create flood entry */
	rcu_read_lock();
	entry = find_flood_entry(ctx, event_type, uid);
	rcu_read_unlock();
	
	if (!entry) {
		/* Create new entry */
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry)
			goto out_log; /* Log anyway on allocation failure */
			
		entry->event_type = kstrdup(event_type, GFP_ATOMIC);
		if (!entry->event_type) {
			kfree(entry);
			goto out_log;
		}
		
		entry->uid = uid;
		entry->first_time = now;
		entry->hash = audit_event_hash(event_type, uid);
		
		bucket = entry->hash;
		spin_lock_irqsave(&ctx->bucket_locks[bucket], flags);
		list_add_rcu(&entry->list, &ctx->buckets[bucket]);
		atomic64_inc(&ctx->unique_events);
		spin_unlock_irqrestore(&ctx->bucket_locks[bucket], flags);
	}
	
	/* Update flood entry */
	bucket = audit_event_hash(event_type, uid);
	spin_lock_irqsave(&ctx->bucket_locks[bucket], flags);
	
	entry->count++;
	entry->last_time = now;
	
	/* Check if this event type is flooding */
	if (time_before(now, entry->first_time + AUDIT_FLOOD_INTERVAL)) {
		if (entry->count > AUDIT_FLOOD_THRESHOLD) {
			entry->suppressed = true;
			atomic64_inc(&ctx->suppressed_events);
			ret = -EBUSY;
		}
	} else {
		/* Reset flood detection window */
		entry->first_time = now;
		entry->count = 1;
		entry->suppressed = false;
	}
	
	spin_unlock_irqrestore(&ctx->bucket_locks[bucket], flags);
	
	if (ret == -EBUSY) {
		/* Log summary message periodically */
		if (entry->count % 1000 == 0) {
			pr_warn_ratelimited("Security event '%s' (uid:%u) flooding "
					    "(%lu events suppressed)\n",
					    event_type, uid, entry->count);
		}
		return ret;
	}

out_log:
	/* Format and log the message */
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	
	pr_info("SECURITY[%s]: uid=%u %s\n", event_type, uid, buf);
	
	/* Also log to audit subsystem if available */
	if (audit_enabled) {
		struct audit_buffer *ab;
		
		ab = audit_log_start(NULL, GFP_ATOMIC, AUDIT_AVC);
		if (ab) {
			audit_log_format(ab, "security_event=%s uid=%u msg=", 
					 event_type, uid);
			va_start(args, fmt);
			audit_log_vformat(ab, fmt, args);
			va_end(args);
			audit_log_end(ab);
		}
	}
	
	return 0;
}
EXPORT_SYMBOL_GPL(security_audit_log);

/**
 * security_audit_log_simple - Log a simple security event
 * @event_type: type of security event
 * @uid: user ID associated with event
 *
 * Returns: 0 on success, -EBUSY if rate limited
 */
int security_audit_log_simple(const char *event_type, uid_t uid)
{
	return security_audit_log(event_type, uid, "event occurred");
}
EXPORT_SYMBOL_GPL(security_audit_log_simple);

static int __init security_audit_init(void)
{
	struct security_audit_ctx *ctx;
	int i;
	
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
		
	/* Initialize buckets */
	for (i = 0; i < AUDIT_BUCKET_COUNT; i++) {
		INIT_LIST_HEAD(&ctx->buckets[i]);
		spin_lock_init(&ctx->bucket_locks[i]);
	}
	
	/* Initialize rate limiter */
	ratelimit_state_init(&ctx->ratelimit, 
			     AUDIT_FLOOD_INTERVAL,
			     AUDIT_FLOOD_THRESHOLD);
	
	/* Initialize summary work */
	INIT_DELAYED_WORK(&ctx->summary_work, audit_summary_work);
	schedule_delayed_work(&ctx->summary_work, AUDIT_SUMMARY_INTERVAL);
	
	global_audit_ctx = ctx;
	
	pr_info("Security audit framework initialized\n");
	return 0;
}

static void __exit security_audit_exit(void)
{
	struct security_audit_ctx *ctx = global_audit_ctx;
	struct audit_flood_entry *entry, *tmp;
	int i;
	
	if (!ctx)
		return;
		
	cancel_delayed_work_sync(&ctx->summary_work);
	
	/* Clean up entries */
	for (i = 0; i < AUDIT_BUCKET_COUNT; i++) {
		list_for_each_entry_safe(entry, tmp, &ctx->buckets[i], list) {
			list_del(&entry->list);
			kfree(entry->event_type);
			kfree(entry);
		}
	}
	
	kfree(ctx);
	pr_info("Security audit framework destroyed\n");
}

module_init(security_audit_init);
module_exit(security_audit_exit);

MODULE_DESCRIPTION("Enhanced Security Audit Framework");
MODULE_LICENSE("GPL");