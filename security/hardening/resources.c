/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Resource Usage Fingerprinting for Security Hardening Module
 *
 * Monitors and detects abnormal resource usage patterns
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/cputime.h>
#include <linux/mm.h>
#include <linux/fdtable.h>
#include "hardening.h"

#define RESOURCE_CHECK_INTERVAL_NS	(5 * NSEC_PER_SEC)
#define RESOURCE_DEVIATION_THRESHOLD	50	/* 50% deviation */
#define RESOURCE_LEARNING_SAMPLES	10

static void get_task_resources(struct task_struct *task,
			       struct hardening_resource_stats *stats)
{
	struct files_struct *files;
	struct mm_struct *mm;
	u64 utime, stime;
	
	/* CPU time */
	task_cputime_adjusted(task, &utime, &stime);
	stats->cpu_time_ns = (utime + stime) * NSEC_PER_USEC;
	
	/* Memory usage */
	mm = get_task_mm(task);
	if (mm) {
		stats->memory_peak_kb = mm->hiwater_rss << (PAGE_SHIFT - 10);
		mmput(mm);
	}
	
	/* File descriptors */
	files = task->files;
	if (files) {
		stats->file_descriptors = files->next_fd;
	}
	
	/* I/O stats (simplified) */
	if (task->ioac.read_bytes || task->ioac.write_bytes) {
		stats->io_bytes_read = task->ioac.read_bytes;
		stats->io_bytes_written = task->ioac.write_bytes;
	}
}

static int calculate_deviation(u64 baseline, u64 current_val)
{
	u64 diff;
	
	if (baseline == 0)
		return current_val > 0 ? 100 : 0;
		
	diff = current_val > baseline ? current_val - baseline : baseline - current_val;
	return (diff * 100) / baseline;
}

int hardening_update_resources(struct hardening_task_ctx *ctx)
{
	struct hardening_resource_baseline *res;
	struct hardening_resource_stats current_stats = {0};
	u64 now;
	
	if (!ctx || !ctx->resources)
		return 0;
		
	res = ctx->resources;
	now = ktime_get_ns();
	
	/* Check if enough time has passed */
	if (now - res->current_stats.last_checkpoint < RESOURCE_CHECK_INTERVAL_NS)
		return 0;
		
	/* Get current resource usage */
	get_task_resources(current, &current_stats);
	current_stats.last_checkpoint = now;
	
	/* In learning mode, update baseline */
	if (res->learning_mode) {
		res->baseline.cpu_time_ns = 
			(res->baseline.cpu_time_ns + current_stats.cpu_time_ns) / 2;
		res->baseline.memory_peak_kb = 
			(res->baseline.memory_peak_kb + current_stats.memory_peak_kb) / 2;
		res->baseline.io_bytes_read = 
			(res->baseline.io_bytes_read + current_stats.io_bytes_read) / 2;
		res->baseline.io_bytes_written = 
			(res->baseline.io_bytes_written + current_stats.io_bytes_written) / 2;
		res->baseline.file_descriptors = 
			(res->baseline.file_descriptors + current_stats.file_descriptors) / 2;
			
		/* Exit learning mode after enough samples */
		if (++res->deviation_count >= RESOURCE_LEARNING_SAMPLES) {
			res->learning_mode = false;
			res->deviation_count = 0;
			pr_debug("hardening: resource baseline established for %s[%d]\n",
				 current->comm, current->pid);
		}
	}
	
	/* Store current stats */
	res->current_stats = current_stats;
	
	return 0;
}

int hardening_check_resource_deviation(struct hardening_task_ctx *ctx)
{
	struct hardening_resource_baseline *res;
	int cpu_dev, mem_dev, io_dev, fd_dev;
	int max_deviation = 0;
	
	if (!ctx || !ctx->resources || ctx->resources->learning_mode)
		return 0;
		
	res = ctx->resources;
	
	/* Calculate deviations */
	cpu_dev = calculate_deviation(res->baseline.cpu_time_ns,
				      res->current_stats.cpu_time_ns);
	mem_dev = calculate_deviation(res->baseline.memory_peak_kb,
				      res->current_stats.memory_peak_kb);
	io_dev = calculate_deviation(res->baseline.io_bytes_read + 
				     res->baseline.io_bytes_written,
				     res->current_stats.io_bytes_read + 
				     res->current_stats.io_bytes_written);
	fd_dev = calculate_deviation(res->baseline.file_descriptors,
				     res->current_stats.file_descriptors);
	
	/* Find maximum deviation */
	max_deviation = max(max(cpu_dev, mem_dev), max(io_dev, fd_dev));
	
	if (max_deviation > RESOURCE_DEVIATION_THRESHOLD) {
		res->deviation_count++;
		
		if (hardening_enforce && res->deviation_count > 3) {
			pr_notice("hardening: resource anomaly detected for %s[%d] "
				  "(cpu:%d%% mem:%d%% io:%d%% fd:%d%%)\n",
				  current->comm, current->pid,
				  cpu_dev, mem_dev, io_dev, fd_dev);
			
			/* Escalate security level */
			hardening_escalate_security(ctx);
			
			return -EACCES;
		}
	} else {
		/* Reset deviation count on normal behavior */
		res->deviation_count = 0;
	}
	
	return 0;
}

struct hardening_resource_baseline *hardening_alloc_resource_baseline(void)
{
	struct hardening_resource_baseline *res;
	
	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return NULL;
		
	res->learning_mode = true;
	res->current_stats.last_checkpoint = ktime_get_ns();
	
	return res;
}

void hardening_free_resource_baseline(struct hardening_resource_baseline *res)
{
	kfree(res);
}