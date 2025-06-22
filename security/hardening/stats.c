/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Statistics Collection for Security Hardening Module
 */

#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include "hardening.h"

/* Global statistics structure */
struct hardening_stats hardening_global_stats = {
	.total_syscalls = ATOMIC64_INIT(0),
	.blocked_syscalls = ATOMIC64_INIT(0),
	.anomalies_detected = ATOMIC64_INIT(0),
	.policy_violations = ATOMIC64_INIT(0),
	.total_checks = ATOMIC64_INIT(0),
	.check_time_ns = ATOMIC64_INIT(0),
	.temporal_violations = ATOMIC64_INIT(0),
	.behavior_anomalies = ATOMIC64_INIT(0),
	.resource_violations = ATOMIC64_INIT(0),
	.network_anomalies = ATOMIC64_INIT(0),
	.memory_anomalies = ATOMIC64_INIT(0),
};

/**
 * hardening_show_stats - Display security module statistics
 * @m: seq_file to write output to
 * @v: private data (unused)
 *
 * Outputs detailed statistics about security checks, anomalies detected,
 * and performance metrics to the provided seq_file.
 *
 * Return: 0 on success
 */
int hardening_show_stats(struct seq_file *m, void *v)
{
	u64 total_checks = atomic64_read(&hardening_global_stats.total_checks);
	u64 check_time = atomic64_read(&hardening_global_stats.check_time_ns);
	u64 avg_check_time = 0;
	
	if (total_checks > 0)
		avg_check_time = check_time / total_checks;
	
	seq_printf(m, "Security Hardening Module Statistics\n");
	seq_printf(m, "====================================\n\n");
	
	seq_printf(m, "General Statistics:\n");
	seq_printf(m, "  Total syscalls monitored: %llu\n",
		   atomic64_read(&hardening_global_stats.total_syscalls));
	seq_printf(m, "  Blocked syscalls: %llu\n",
		   atomic64_read(&hardening_global_stats.blocked_syscalls));
	seq_printf(m, "  Total security checks: %llu\n", total_checks);
	seq_printf(m, "  Average check time: %llu ns\n", avg_check_time);
	
	seq_printf(m, "\nAnomaly Detection:\n");
	seq_printf(m, "  Total anomalies detected: %llu\n",
		   atomic64_read(&hardening_global_stats.anomalies_detected));
	seq_printf(m, "  Behavioral anomalies: %llu\n",
		   atomic64_read(&hardening_global_stats.behavior_anomalies));
	seq_printf(m, "  Resource anomalies: %llu\n",
		   atomic64_read(&hardening_global_stats.resource_violations));
	seq_printf(m, "  Network anomalies: %llu\n",
		   atomic64_read(&hardening_global_stats.network_anomalies));
	seq_printf(m, "  Memory anomalies: %llu\n",
		   atomic64_read(&hardening_global_stats.memory_anomalies));
	
	seq_printf(m, "\nPolicy Violations:\n");
	seq_printf(m, "  Total violations: %llu\n",
		   atomic64_read(&hardening_global_stats.policy_violations));
	seq_printf(m, "  Temporal violations: %llu\n",
		   atomic64_read(&hardening_global_stats.temporal_violations));
	
	return 0;
}

/**
 * hardening_reset_stats - Reset all security module statistics
 *
 * Resets all statistical counters to zero. This is typically used
 * for testing or when starting a new monitoring period.
 */
void hardening_reset_stats(void)
{
	atomic64_set(&hardening_global_stats.total_syscalls, 0);
	atomic64_set(&hardening_global_stats.blocked_syscalls, 0);
	atomic64_set(&hardening_global_stats.anomalies_detected, 0);
	atomic64_set(&hardening_global_stats.policy_violations, 0);
	atomic64_set(&hardening_global_stats.total_checks, 0);
	atomic64_set(&hardening_global_stats.check_time_ns, 0);
	atomic64_set(&hardening_global_stats.temporal_violations, 0);
	atomic64_set(&hardening_global_stats.behavior_anomalies, 0);
	atomic64_set(&hardening_global_stats.resource_violations, 0);
	atomic64_set(&hardening_global_stats.network_anomalies, 0);
	atomic64_set(&hardening_global_stats.memory_anomalies, 0);
	
	pr_info("hardening: statistics reset\n");
}

/**
 * hardening_update_check_time - Update security check timing statistics
 * @start_ns: Start time of the check in nanoseconds
 *
 * Updates the total check count and cumulative check time for
 * performance monitoring purposes.
 */
void hardening_update_check_time(u64 start_ns)
{
	u64 duration = ktime_get_ns() - start_ns;
	
	atomic64_inc(&hardening_global_stats.total_checks);
	atomic64_add(duration, &hardening_global_stats.check_time_ns);
}