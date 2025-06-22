/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Enhanced Security Audit Framework with Flood Protection
 *
 * Copyright (C) 2024 Linux Security Module Audit Framework
 */

#ifndef _SECURITY_AUDIT_H
#define _SECURITY_AUDIT_H

#include <linux/types.h>

/**
 * security_audit_log - Log a security event with flood protection
 * @event_type: type of security event
 * @uid: user ID associated with event
 * @fmt: format string for additional details
 * @...: format arguments
 *
 * Returns: 0 on success, -EBUSY if rate limited
 */
int security_audit_log(const char *event_type, uid_t uid, const char *fmt, ...);

/**
 * security_audit_log_simple - Log a simple security event
 * @event_type: type of security event
 * @uid: user ID associated with event
 *
 * Returns: 0 on success, -EBUSY if rate limited
 */
int security_audit_log_simple(const char *event_type, uid_t uid);

/* Common security event types */
#define AUDIT_POLICY_VIOLATION		"policy_violation"
#define AUDIT_ANOMALY_DETECTED		"anomaly_detected"
#define AUDIT_ACCESS_DENIED		"access_denied"
#define AUDIT_PRIVILEGE_ESCALATION	"privilege_escalation"
#define AUDIT_EXPLOIT_ATTEMPT		"exploit_attempt"
#define AUDIT_RATE_LIMIT		"rate_limit_exceeded"
#define AUDIT_TEMPORAL_VIOLATION	"temporal_violation"
#define AUDIT_BEHAVIOR_ANOMALY		"behavior_anomaly"
#define AUDIT_MEMORY_ANOMALY		"memory_anomaly"
#define AUDIT_NETWORK_ANOMALY		"network_anomaly"

/* Helper macros */
#define security_audit_denied(op, uid) \
	security_audit_log(AUDIT_ACCESS_DENIED, uid, "operation=%s", op)

#define security_audit_anomaly(type, uid, score) \
	security_audit_log(AUDIT_ANOMALY_DETECTED, uid, \
			   "type=%s score=%u", type, score)

#define security_audit_exploit(type, uid) \
	security_audit_log(AUDIT_EXPLOIT_ATTEMPT, uid, "type=%s", type)

#endif /* _SECURITY_AUDIT_H */