// SPDX-License-Identifier: GPL-2.0-only
/*
 * Memory Access Pattern Analysis for Security Hardening Module
 *
 * Detects exploitation attempts through memory access patterns
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/random.h>
#include "hardening.h"

/* Memory operation types */
#define MEM_OP_MMAP		1
#define MEM_OP_MPROTECT		2
#define MEM_OP_BRK		3
#define MEM_OP_MUNMAP		4

/* Thresholds for suspicious activity */
#define MAX_MMAP_PER_SECOND	10
#define MAX_MPROTECT_CHANGES	20
#define MAX_RWX_MAPPINGS	2
#define HEAP_SPRAY_THRESHOLD	100	/* MB */
#define STACK_PIVOT_DISTANCE	0x10000	/* 64KB from stack */

/* ROP gadget signatures (simplified) */
static const u8 rop_gadget_sigs[][4] = {
	{0xc3, 0x00, 0x00, 0x00},	/* ret */
	{0xc2, 0x00, 0x00, 0x00},	/* ret imm16 */
	{0xcb, 0x00, 0x00, 0x00},	/* retf */
	{0xca, 0x00, 0x00, 0x00},	/* retf imm16 */
	{0x5d, 0xc3, 0x00, 0x00},	/* pop rbp; ret */
	{0x58, 0xc3, 0x00, 0x00},	/* pop rax; ret */
	{0x5f, 0xc3, 0x00, 0x00},	/* pop rdi; ret */
};

/* Initialize memory profile */
int hardening_init_memory_profile(struct hardening_task_ctx *ctx)
{
	struct hardening_memory_profile *memory;
	
	memory = kzalloc(sizeof(*memory), GFP_KERNEL);
	if (!memory)
		return -ENOMEM;
		
	/* Initialize with current memory state */
	if (current->mm) {
		memory->brk_changes = 0;
		memory->allocation_entropy = get_random_u32() & 0xFF;
	}
	
	ctx->memory = memory;
	return 0;
}

/* Track memory operations */
int hardening_track_memory_operation(struct hardening_task_ctx *ctx,
				    int operation, unsigned long addr,
				    size_t len, int prot)
{
	struct hardening_memory_profile *memory;
	static u64 last_mmap_time = 0;
	u64 now;
	
	if (!ctx || !ctx->memory)
		return 0;
		
	memory = ctx->memory;
	now = ktime_get_ns();
	
	switch (operation) {
	case MEM_OP_MMAP:
		memory->mmap_count++;
		
		/* Check mmap frequency */
		if (last_mmap_time && (now - last_mmap_time) < NSEC_PER_SEC) {
			/* Multiple mmaps within 1 second */
			if (memory->mmap_count > MAX_MMAP_PER_SECOND) {
				pr_notice("hardening: excessive mmap rate detected\n");
				memory->heap_spray_detected = true;
			}
		}
		last_mmap_time = now;
		
		/* Track executable mappings */
		if (prot & PROT_EXEC) {
			memory->executable_mappings++;
			
			/* Check for RWX mappings */
			if ((prot & PROT_READ) && (prot & PROT_WRITE)) {
				memory->rwx_mappings++;
				pr_notice("hardening: RWX mapping detected at %lx\n", addr);
			}
		}
		
		/* Update allocation entropy */
		memory->allocation_entropy ^= (addr >> 12) & 0xFF;
		break;
		
	case MEM_OP_MPROTECT:
		memory->mprotect_count++;
		
		/* Detect W^X violations */
		if ((prot & PROT_EXEC) && (prot & PROT_WRITE)) {
			pr_notice("hardening: mprotect W^X violation at %lx\n", addr);
			memory->rwx_mappings++;
		}
		break;
		
	case MEM_OP_BRK:
		memory->brk_changes++;
		break;
	}
	
	/* Check for exploitation attempts */
	return hardening_detect_exploit_attempt(ctx);
}

/* Detect heap spray attempts */
static bool detect_heap_spray(struct hardening_memory_profile *memory)
{
	struct mm_struct *mm = current->mm;
	unsigned long total_heap = 0;
	
	if (!mm)
		return false;
		
	/* Calculate approximate heap size */
	if (mm->brk > mm->start_brk) {
		total_heap = (mm->brk - mm->start_brk) >> 20;	/* Convert to MB */
	}
	
	/* Check for excessive heap allocation */
	if (total_heap > HEAP_SPRAY_THRESHOLD) {
		/* Check allocation pattern entropy */
		if (memory->allocation_entropy < 50) {
			/* Low entropy suggests repeated allocations */
			return true;
		}
	}
	
	return memory->heap_spray_detected;
}

/* Detect ROP chain attempts */
static bool detect_rop_chain(unsigned long addr, size_t len)
{
	void __user *uaddr = (void __user *)addr;
	u8 buf[256];
	size_t check_len;
	int gadget_count = 0;
	int i, j;
	
	/* Only check executable memory */
	if (!access_ok(uaddr, len))
		return false;
		
	/* Read a sample of memory */
	check_len = min(len, sizeof(buf));
	if (copy_from_user(buf, uaddr, check_len))
		return false;
		
	/* Look for ROP gadget signatures */
	for (i = 0; i < check_len - 4; i++) {
		for (j = 0; j < ARRAY_SIZE(rop_gadget_sigs); j++) {
			if (memcmp(&buf[i], rop_gadget_sigs[j], 2) == 0) {
				gadget_count++;
				if (gadget_count > 5) {
					/* Multiple gadgets found */
					return true;
				}
			}
		}
	}
	
	return false;
}

/* Detect stack pivot attempts */
static bool detect_stack_pivot(struct hardening_memory_profile *memory,
			       unsigned long addr)
{
	unsigned long stack_start, stack_end;
	struct mm_struct *mm = current->mm;
	
	if (!mm)
		return false;
		
	/* Get current stack boundaries */
	stack_start = current->stack_start;
	stack_end = stack_start - THREAD_SIZE;
	
	/* Check if address is suspiciously far from stack */
	if (addr < stack_end - STACK_PIVOT_DISTANCE ||
	    addr > stack_start + STACK_PIVOT_DISTANCE) {
		/* Potential stack pivot */
		memory->stack_pivots++;
		return true;
	}
	
	return false;
}

/* Main exploit detection routine */
int hardening_detect_exploit_attempt(struct hardening_task_ctx *ctx)
{
	struct hardening_memory_profile *memory;
	bool exploit_detected = false;
	
	if (!ctx || !ctx->memory)
		return 0;
		
	memory = ctx->memory;
	
	/* Check for heap spray */
	if (detect_heap_spray(memory)) {
		pr_alert("hardening: heap spray attack detected\n");
		exploit_detected = true;
	}
	
	/* Check for excessive RWX mappings */
	if (memory->rwx_mappings > MAX_RWX_MAPPINGS) {
		pr_alert("hardening: excessive RWX mappings (%u)\n",
			 memory->rwx_mappings);
		memory->rop_chain_suspected = true;
		exploit_detected = true;
	}
	
	/* Check for suspicious mprotect changes */
	if (memory->mprotect_count > MAX_MPROTECT_CHANGES) {
		pr_alert("hardening: excessive mprotect calls (%u)\n",
			 memory->mprotect_count);
		exploit_detected = true;
	}
	
	/* Check for stack pivots */
	if (memory->stack_pivots > 0) {
		pr_alert("hardening: stack pivot attempt detected\n");
		exploit_detected = true;
	}
	
	if (exploit_detected) {
		/* Escalate to critical security level */
		ctx->sec_level = HARDENING_LEVEL_CRITICAL;
		atomic64_inc(&hardening_global_stats.memory_anomalies);
		
		if (hardening_enforce)
			return -EPERM;
	}
	
	return 0;
}

/* Free memory profile */
void hardening_free_memory_profile(struct hardening_memory_profile *memory)
{
	kfree(memory);
}