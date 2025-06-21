// SPDX-License-Identifier: GPL-2.0-only
/*
 * Temporal Access Control for Security Hardening Module
 *
 * Implements time-based access control policies
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/rtc.h>
#include "hardening.h"

/* Days of week bitmask */
#define HARDENING_DAY_SUNDAY	(1 << 0)
#define HARDENING_DAY_MONDAY	(1 << 1)
#define HARDENING_DAY_TUESDAY	(1 << 2)
#define HARDENING_DAY_WEDNESDAY	(1 << 3)
#define HARDENING_DAY_THURSDAY	(1 << 4)
#define HARDENING_DAY_FRIDAY	(1 << 5)
#define HARDENING_DAY_SATURDAY	(1 << 6)

static int get_current_hour_and_day(u8 *hour, u8 *day)
{
	struct timespec64 ts;
	struct tm tm;
	
	ktime_get_real_ts64(&ts);
	time64_to_tm(ts.tv_sec, 0, &tm);
	
	*hour = tm.tm_hour;
	*day = tm.tm_wday;
	
	return 0;
}

int hardening_check_time_access(struct hardening_task_ctx *ctx)
{
	struct hardening_time_rule *rule;
	u8 current_hour, current_day;
	bool access_allowed = false;
	unsigned long flags;
	
	if (!ctx || !ctx->time_restricted)
		return 0;
	
	get_current_hour_and_day(&current_hour, &current_day);
	
	spin_lock_irqsave(&ctx->lock, flags);
	
	/* Check if current time matches any rule */
	list_for_each_entry(rule, &ctx->time_rules, list) {
		/* Check day mask */
		if (!(rule->days_mask & (1 << current_day)))
			continue;
			
		/* Check hour range */
		if (rule->hour_start <= rule->hour_end) {
			/* Normal range (e.g., 9-17) */
			if (current_hour >= rule->hour_start && 
			    current_hour <= rule->hour_end) {
				access_allowed = true;
				break;
			}
		} else {
			/* Overnight range (e.g., 22-6) */
			if (current_hour >= rule->hour_start || 
			    current_hour <= rule->hour_end) {
				access_allowed = true;
				break;
			}
		}
	}
	
	spin_unlock_irqrestore(&ctx->lock, flags);
	
	if (!access_allowed && hardening_enforce) {
		pr_notice("hardening: temporal access denied at hour %d day %d\n",
			  current_hour, current_day);
		return -EPERM;
	}
	
	return 0;
}

int hardening_add_time_rule(struct hardening_task_ctx *ctx,
			    struct hardening_time_rule *new_rule)
{
	struct hardening_time_rule *rule;
	unsigned long flags;
	int count = 0;
	
	if (!ctx || !new_rule)
		return -EINVAL;
		
	/* Validate rule */
	if (new_rule->hour_start > 23 || new_rule->hour_end > 23)
		return -EINVAL;
		
	spin_lock_irqsave(&ctx->lock, flags);
	
	/* Check rule limit */
	list_for_each_entry(rule, &ctx->time_rules, list) {
		if (++count >= HARDENING_MAX_TIME_RULES) {
			spin_unlock_irqrestore(&ctx->lock, flags);
			return -ENOSPC;
		}
	}
	
	/* Add new rule */
	rule = kmalloc(sizeof(*rule), GFP_ATOMIC);
	if (!rule) {
		spin_unlock_irqrestore(&ctx->lock, flags);
		return -ENOMEM;
	}
	
	*rule = *new_rule;
	list_add_tail(&rule->list, &ctx->time_rules);
	ctx->time_restricted = true;
	
	spin_unlock_irqrestore(&ctx->lock, flags);
	
	pr_debug("hardening: added time rule %d-%d days=0x%x\n",
		 rule->hour_start, rule->hour_end, rule->days_mask);
		 
	return 0;
}

void hardening_cleanup_time_rules(struct hardening_task_ctx *ctx)
{
	struct hardening_time_rule *rule, *tmp;
	unsigned long flags;
	
	if (!ctx)
		return;
		
	spin_lock_irqsave(&ctx->lock, flags);
	
	list_for_each_entry_safe(rule, tmp, &ctx->time_rules, list) {
		list_del(&rule->list);
		kfree(rule);
	}
	
	ctx->time_restricted = false;
	
	spin_unlock_irqrestore(&ctx->lock, flags);
}