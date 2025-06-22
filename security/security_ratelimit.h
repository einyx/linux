/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Security module rate limiting framework
 *
 * Copyright (C) 2024 Linux Security Module Rate Limiting
 */

#ifndef _SECURITY_RATELIMIT_H
#define _SECURITY_RATELIMIT_H

#include <linux/types.h>

struct security_ratelimit_ctx;

/**
 * security_ratelimit_check - Check if an action should be rate limited
 * @ctx: rate limit context
 * @uid: user ID to check
 *
 * Returns: 0 if action is allowed, -EBUSY if rate limited
 */
int security_ratelimit_check(struct security_ratelimit_ctx *ctx, uid_t uid);

/**
 * security_ratelimit_init - Initialize rate limiting context
 * @max_burst: maximum events per interval
 * @interval_ms: interval in milliseconds
 *
 * Returns: rate limit context or NULL on failure
 */
struct security_ratelimit_ctx *security_ratelimit_init(unsigned int max_burst,
							unsigned int interval_ms);

/**
 * security_ratelimit_destroy - Destroy rate limiting context
 * @ctx: rate limit context to destroy
 */
void security_ratelimit_destroy(struct security_ratelimit_ctx *ctx);

/* Helper macros for common configurations */
#define SECURITY_RATELIMIT_DEFAULT_BURST	100
#define SECURITY_RATELIMIT_DEFAULT_INTERVAL	5000  /* 5 seconds */

/* Rate limit check with audit logging */
static inline int security_ratelimit_check_log(struct security_ratelimit_ctx *ctx,
						uid_t uid, const char *op)
{
	int ret = security_ratelimit_check(ctx, uid);
	
	if (ret == -EBUSY) {
		pr_warn_ratelimited("Security operation '%s' rate limited for uid %u\n",
				    op, uid);
	}
	
	return ret;
}

#endif /* _SECURITY_RATELIMIT_H */