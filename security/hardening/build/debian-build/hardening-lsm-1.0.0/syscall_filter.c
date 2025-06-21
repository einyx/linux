// SPDX-License-Identifier: GPL-2.0-only
/*
 * Syscall filtering for Security Hardening Module
 */

#include <linux/kernel.h>
#include "hardening.h"

int syscall_filter_init(void)
{
	pr_info("hardening: syscall filter initialized\n");
	return 0;
}

int syscall_filter_check(int syscall_nr, struct hardening_task_ctx *ctx)
{
	/* TODO: Implement syscall filtering logic */
	return 0;
}