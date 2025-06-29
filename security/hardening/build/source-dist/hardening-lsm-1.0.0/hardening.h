/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_HARDENING_H
#define _SECURITY_HARDENING_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/time64.h>
#include <linux/rbtree.h>
#include <linux/hash.h>
#include <crypto/hash.h>

/* Module configuration */
extern int hardening_enabled;
extern int hardening_enforce;

/* Temporal Access Control - Time-based security policies */
#define HARDENING_TIME_WINDOW_SIZE	24	/* hours */
#define HARDENING_MAX_TIME_RULES	128

struct hardening_time_rule {
	u8 hour_start;		/* 0-23 */
	u8 hour_end;		/* 0-23 */
	u8 days_mask;		/* Bitmask for days of week */
	u32 allowed_caps;	/* Capabilities allowed during this time */
	struct list_head list;
};

/* Behavioral Anomaly Detection */
#ifdef CONFIG_SECURITY_HARDENING_BEHAVIOR_WINDOW
#define HARDENING_BEHAVIOR_WINDOW	CONFIG_SECURITY_HARDENING_BEHAVIOR_WINDOW
#else
#define HARDENING_BEHAVIOR_WINDOW	128
#endif
#define HARDENING_ANOMALY_THRESHOLD	10	/* Deviation threshold */
#define HARDENING_MARKOV_ORDER		3	/* Markov chain order */

struct syscall_transition {
	u32 from_syscall;
	u32 to_syscall;
	u32 count;
	struct list_head list;
};

struct hardening_behavior_profile {
	/* Basic pattern tracking */
	u32 syscall_pattern[HARDENING_BEHAVIOR_WINDOW];
	u32 pattern_index;
	
	/* Markov chain for transition probabilities */
	struct list_head markov_transitions[256];	/* Hash buckets */
	u32 total_transitions;
	
	/* Frequency analysis */
	u32 syscall_frequency[512];	/* Syscall frequency counters */
	
	/* Anomaly detection */
	u32 anomaly_score;
	u32 anomaly_events;
	u64 last_update;
	
	/* ML-inspired features */
	u32 pattern_entropy;
	u32 sequence_complexity;
	
	spinlock_t lock;
};

/* Resource Usage Fingerprinting */
struct hardening_resource_stats {
	u64 cpu_time_ns;
	u64 memory_peak_kb;
	u64 io_bytes_read;
	u64 io_bytes_written;
	u32 network_connections;
	u32 file_descriptors;
	u64 last_checkpoint;
};

struct hardening_resource_baseline {
	struct hardening_resource_stats baseline;
	struct hardening_resource_stats current;
	u32 deviation_count;
	bool learning_mode;
};

/* Adaptive Security Levels */
enum hardening_security_level {
	HARDENING_LEVEL_NORMAL = 0,
	HARDENING_LEVEL_ELEVATED,
	HARDENING_LEVEL_HIGH,
	HARDENING_LEVEL_CRITICAL,
	HARDENING_LEVEL_MAX
};

/* Process Lineage Tracking */
#define HARDENING_MAX_LINEAGE_DEPTH	16

struct hardening_lineage {
	pid_t ancestors[HARDENING_MAX_LINEAGE_DEPTH];
	u8 depth;
	u32 lineage_hash;	/* Quick comparison hash */
	bool suspicious_chain;
};

/* Container Context */
struct hardening_container_ctx {
	u64 container_id;	/* From cgroup */
	char container_name[64];
	u32 container_flags;
	struct list_head list;
};

/* Network Behavior Profile */
struct hardening_network_profile {
	/* Connection tracking */
	u32 total_connections;
	u32 failed_connections;
	u32 unique_destinations;
	
	/* Port usage */
	DECLARE_BITMAP(used_ports, 65536);
	u32 port_scan_score;
	
	/* Traffic patterns */
	u64 bytes_sent;
	u64 bytes_received;
	u32 packet_rate;
	
	/* Anomaly detection */
	u32 network_anomaly_score;
	u64 last_activity;
};

/* Memory Access Patterns */
struct hardening_memory_profile {
	/* Access pattern tracking */
	u32 mmap_count;
	u32 mprotect_count;
	u32 brk_changes;
	
	/* Suspicious patterns */
	u32 executable_mappings;
	u32 rwx_mappings;
	u32 stack_pivots;
	
	/* Entropy analysis */
	u32 allocation_entropy;
	bool heap_spray_detected;
	bool rop_chain_suspected;
};

/* Cryptographic Integrity */
struct hardening_crypto_ctx {
	/* Process integrity */
	u8 process_hash[32];	/* SHA-256 */
	u8 memory_hash[32];
	
	/* File integrity */
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	
	/* Verification timestamps */
	u64 last_verification;
	bool integrity_verified;
};

/* Security Profile */
struct hardening_security_profile {
	char name[64];
	u32 profile_id;
	
	/* Policy flags */
	u32 allowed_syscalls[16];	/* Bitmap: 512 syscalls */
	u32 allowed_capabilities;
	u32 network_policy;
	u32 filesystem_policy;
	
	/* Resource limits */
	u32 max_memory_mb;
	u32 max_cpu_percent;
	u32 max_file_descriptors;
	u32 max_threads;
	
	/* Time restrictions */
	struct hardening_time_rule *time_rules;
	u32 time_rule_count;
	
	struct rb_node node;
	struct rcu_head rcu;
};

/* Statistics */
struct hardening_stats {
	/* Events */
	atomic64_t total_syscalls;
	atomic64_t blocked_syscalls;
	atomic64_t anomalies_detected;
	atomic64_t policy_violations;
	
	/* Performance */
	atomic64_t total_checks;
	atomic64_t check_time_ns;
	
	/* By category */
	atomic64_t temporal_violations;
	atomic64_t behavior_anomalies;
	atomic64_t resource_violations;
	atomic64_t network_anomalies;
	atomic64_t memory_anomalies;
};

/* Per-task security context */
struct hardening_task_ctx {
	/* Temporal access control */
	struct list_head time_rules;
	bool time_restricted;
	
	/* Behavioral anomaly detection */
	struct hardening_behavior_profile *behavior;
	
	/* Resource fingerprinting */
	struct hardening_resource_baseline *resources;
	
	/* Process lineage */
	struct hardening_lineage *lineage;
	
	/* Container context */
	struct hardening_container_ctx *container;
	
	/* Network profile */
	struct hardening_network_profile *network;
	
	/* Memory profile */
	struct hardening_memory_profile *memory;
	
	/* Cryptographic context */
	struct hardening_crypto_ctx *crypto;
	
	/* Security profile */
	struct hardening_security_profile *profile;
	
	/* Adaptive security */
	enum hardening_security_level sec_level;
	u32 violation_count;
	u64 last_violation_time;
	
	/* Entropy pool for randomization */
	u32 entropy_pool;
	u32 random_seed;
	
	/* General */
	u32 flags;
	spinlock_t lock;
};

/* Module flags */
#define HARDENING_FLAG_LEARNING		0x00000001
#define HARDENING_FLAG_TIME_ENFORCED	0x00000002
#define HARDENING_FLAG_BEHAVIOR_CHECK	0x00000004
#define HARDENING_FLAG_RESOURCE_CHECK	0x00000008

/* Global statistics */
extern struct hardening_stats hardening_global_stats;

/* Profile management */
extern struct rb_root hardening_profiles;
extern rwlock_t hardening_profiles_lock;

/* Function declarations */
int hardening_init_securityfs(void);
void hardening_exit_securityfs(void);

/* Temporal access control */
int hardening_check_time_access(struct hardening_task_ctx *ctx);
int hardening_add_time_rule(struct hardening_task_ctx *ctx,
			    struct hardening_time_rule *rule);

/* Behavioral anomaly detection */
int hardening_update_behavior(struct hardening_task_ctx *ctx, int syscall_nr);
int hardening_check_anomaly(struct hardening_task_ctx *ctx);
int hardening_calculate_entropy(struct hardening_behavior_profile *behavior);
int hardening_update_markov_chain(struct hardening_behavior_profile *behavior,
				  u32 from, u32 to);

/* Resource fingerprinting */
int hardening_update_resources(struct hardening_task_ctx *ctx);
int hardening_check_resource_deviation(struct hardening_task_ctx *ctx);

/* Process lineage */
int hardening_init_lineage(struct hardening_task_ctx *ctx);
int hardening_check_lineage(struct hardening_task_ctx *ctx);
bool hardening_is_suspicious_lineage(struct hardening_lineage *lineage);

/* Container support */
int hardening_init_container_ctx(struct hardening_task_ctx *ctx);
int hardening_get_container_id(u64 *container_id);
int hardening_apply_container_policy(struct hardening_task_ctx *ctx);

/* Network profiling */
int hardening_init_network_profile(struct hardening_task_ctx *ctx);
int hardening_update_network_activity(struct hardening_task_ctx *ctx,
				     int sock_type, int result);
int hardening_check_network_anomaly(struct hardening_task_ctx *ctx);

/* Memory analysis */
int hardening_init_memory_profile(struct hardening_task_ctx *ctx);
int hardening_track_memory_operation(struct hardening_task_ctx *ctx,
				    int operation, unsigned long addr,
				    size_t len, int prot);
int hardening_detect_exploit_attempt(struct hardening_task_ctx *ctx);

/* Cryptographic integrity */
int hardening_init_crypto(struct hardening_task_ctx *ctx);
int hardening_compute_process_hash(struct hardening_task_ctx *ctx);
int hardening_verify_integrity(struct hardening_task_ctx *ctx);

/* Profile management */
int hardening_load_profile(const char *name, 
			  struct hardening_security_profile *profile);
struct hardening_security_profile *hardening_find_profile(const char *name);
int hardening_apply_profile(struct hardening_task_ctx *ctx, const char *profile_name);

/* Entropy and randomization */
void hardening_add_entropy(struct hardening_task_ctx *ctx, u32 value);
u32 hardening_get_random(struct hardening_task_ctx *ctx);
int hardening_randomize_decision(struct hardening_task_ctx *ctx, int probability);

/* Adaptive security */
void hardening_escalate_security(struct hardening_task_ctx *ctx);
void hardening_deescalate_security(struct hardening_task_ctx *ctx);
int hardening_check_capability(struct hardening_task_ctx *ctx, int cap);
int hardening_check_resource_limit(struct hardening_task_ctx *ctx,
				   int resource_type, u32 value);

/* Memory operation types */
#define MEM_OP_MMAP		1
#define MEM_OP_MPROTECT		2
#define MEM_OP_BRK		3
#define MEM_OP_MUNMAP		4

/* prctl definitions */
#define PR_HARDENING_STATUS			0x48415244

/* Syscall filter */
#ifdef CONFIG_SECURITY_HARDENING_SYSCALL_FILTER
#define HARDENING_DEFAULT_ALLOWED_SYSCALLS	0xFFFFFFFF

int syscall_filter_init(void);
int syscall_filter_check(int syscall_nr, struct hardening_task_ctx *ctx);
#endif

#endif /* _SECURITY_HARDENING_H */