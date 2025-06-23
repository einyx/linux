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

/* Forward declarations */
struct socket;
struct sockaddr;

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
	
	/* Batch optimization */
	#define SYSCALL_BATCH_SIZE 16
	u32 syscall_batch[SYSCALL_BATCH_SIZE];
	u8 batch_count;
	
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
	struct hardening_resource_stats current_stats;
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
	u64 container_id;		/* From cgroup */
	char container_name[64];
	u32 container_flags;
	struct list_head list;
	
	/* Runtime detection */
	enum container_runtime_type {
		RUNTIME_NONE = 0,
		RUNTIME_DOCKER,
		RUNTIME_CONTAINERD,
		RUNTIME_PODMAN,
		RUNTIME_K8S,
	} runtime;
	
	/* Security configuration */
	bool privileged;
	bool host_network;
	bool host_pid;
	bool host_ipc;
	
	/* Isolation level */
	enum container_isolation_level {
		CONTAINER_ISOLATION_NONE = 0,
		CONTAINER_ISOLATION_NORMAL,
		CONTAINER_ISOLATION_STRICT,
	} isolation_level;
	
	/* Resource limits */
	u64 memory_limit;
	u32 cpu_quota;
	u32 mount_count;
	
	/* Syscall filtering */
	const int *syscall_whitelist;
	u32 syscall_count;
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
	
	/* Quantum-resistant crypto context */
	struct hardening_quantum_ctx *quantum;
	
	/* Malware detection stats */
	struct malware_stats *malware;
	
	/* Security profile */
	struct hardening_security_profile *profile;
	
	/* Adaptive security */
	enum hardening_security_level sec_level;
	u32 violation_count;
	u64 last_violation_time;
	
	/* Entropy pool for randomization */
	u32 entropy_pool;
	u32 random_seed;
	
	/* Performance optimization */
	u64 last_resource_check;
	u64 last_behavior_check;
	
	/* General */
	u32 flags;
	spinlock_t lock;
};

/* Module flags */
#define HARDENING_FLAG_LEARNING		0x00000001
#define HARDENING_FLAG_TIME_ENFORCED	0x00000002
#define HARDENING_FLAG_BEHAVIOR_CHECK	0x00000004
#define HARDENING_FLAG_RESOURCE_CHECK	0x00000008

/* Quantum-Resistant Cryptography structures */
#ifdef CONFIG_SECURITY_HARDENING_QUANTUM

/* Post-quantum algorithm types */
enum hardening_pq_algo {
	HARDENING_PQ_KYBER768,		/* NIST Level 3 security */
	HARDENING_PQ_KYBER1024,		/* NIST Level 5 security */
	HARDENING_PQ_DILITHIUM3,	/* Digital signatures */
	HARDENING_PQ_DILITHIUM5,	/* Higher security signatures */
	HARDENING_PQ_FALCON512,		/* Alternative signature scheme */
	HARDENING_PQ_SPHINCS_PLUS,	/* Hash-based signatures */
};

/* Hybrid key structure (classical + quantum) */
struct hardening_hybrid_key {
	/* List management */
	struct list_head list;
	
	/* Classical component */
	u8 classical_key[32];		/* AES-256 or similar */
	u32 classical_key_len;
	
	/* Quantum-resistant component */
	u8 *pq_public_key;
	u8 *pq_private_key;
	u32 pq_public_key_len;
	u32 pq_private_key_len;
	enum hardening_pq_algo pq_algo;
	
	/* Key metadata */
	u64 creation_time;
	u64 expiration_time;
	u32 usage_count;
	bool is_ephemeral;
};

/* Quantum-secure channel */
struct hardening_quantum_channel {
	struct hardening_hybrid_key *local_key;
	struct hardening_hybrid_key *remote_key;
	
	/* Shared secrets */
	u8 shared_secret[64];		/* Combined classical + PQ */
	u8 session_key[32];		/* Derived session key */
	
	/* Channel state */
	u64 sequence_number;
	u64 last_rekey_time;
	u32 messages_sent;
	u32 messages_received;
	
	/* Authentication */
	u8 auth_tag[32];
	bool authenticated;
	
	struct list_head list;
};

/* Quantum context per task */
struct hardening_quantum_ctx {
	/* Key management */
	struct hardening_hybrid_key *identity_key;
	struct list_head ephemeral_keys;
	u32 key_rotation_interval;
	
	/* Active channels */
	struct list_head quantum_channels;
	u32 active_channels;
	
	/* Algorithm preferences */
	enum hardening_pq_algo preferred_kem;		/* Key encapsulation */
	enum hardening_pq_algo preferred_sig;		/* Signatures */
	
	/* Security policy */
	bool require_quantum_auth;
	bool allow_classical_fallback;
	u32 min_security_level;		/* NIST level 1-5 */
	
	/* Performance optimization */
	struct crypto_shash *hash_tfm;		/* For key derivation */
	u8 *workspace;				/* Pre-allocated workspace */
	u32 workspace_size;
	
#ifdef CONFIG_SECURITY_HARDENING_QUANTUM_LIBOQS
	/* liboqs algorithm instances */
	void *kyber768_kem;			/* OQS_KEM pointer */
	void *kyber1024_kem;			/* OQS_KEM pointer */
	void *dilithium3_sig;			/* OQS_SIG pointer */
	void *dilithium5_sig;			/* OQS_SIG pointer */
#endif
	
	/* Statistics */
	u64 keys_generated;
	u64 signatures_created;
	u64 signatures_verified;
	u64 key_exchanges;
	
	spinlock_t lock;
};

/* Quantum authentication token */
struct hardening_quantum_token {
	/* Token data */
	u8 token_id[16];
	u64 timestamp;
	u32 flags;
	
	/* Hybrid signature */
	u8 *classical_sig;
	u8 *quantum_sig;
	u32 classical_sig_len;
	u32 quantum_sig_len;
	
	/* Claims */
	u32 process_id;
	u32 user_id;
	u32 security_level;
	u64 expiration;
};

#endif /* CONFIG_SECURITY_HARDENING_QUANTUM */

/* Global statistics */
extern struct hardening_stats hardening_global_stats;

/* Statistics functions */
int hardening_show_stats(struct seq_file *m, void *v);
void hardening_reset_stats(void);
void hardening_update_check_time(u64 start_ns);

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
void hardening_cleanup_time_rules(struct hardening_task_ctx *ctx);

/* Behavioral anomaly detection */
struct hardening_behavior_profile *hardening_alloc_behavior_profile(void);
void hardening_free_behavior_profile(
		struct hardening_behavior_profile *behavior);
int hardening_update_behavior(struct hardening_task_ctx *ctx, int syscall_nr);
int hardening_check_anomaly(struct hardening_task_ctx *ctx);
int hardening_calculate_entropy(struct hardening_behavior_profile *behavior);
int hardening_update_markov_chain(struct hardening_behavior_profile *behavior,
				  u32 from, u32 to);

/* Resource fingerprinting */
struct hardening_resource_baseline *hardening_alloc_resource_baseline(void);
void hardening_free_resource_baseline(
		struct hardening_resource_baseline *baseline);
int hardening_update_resources(struct hardening_task_ctx *ctx);
int hardening_check_resource_deviation(struct hardening_task_ctx *ctx);

/* Process lineage */
int hardening_init_lineage(struct hardening_task_ctx *ctx);
int hardening_check_lineage(struct hardening_task_ctx *ctx);
bool hardening_is_suspicious_lineage(struct hardening_lineage *lineage);
void hardening_free_lineage(struct hardening_lineage *lineage);

/* Container support */
int hardening_init_container_context(struct hardening_task_ctx *ctx);
int hardening_get_container_id(u64 *container_id);
int hardening_apply_container_policy(struct hardening_task_ctx *ctx);
void hardening_free_container_ctx(struct hardening_container_ctx *container);
int hardening_check_container_operation(struct hardening_task_ctx *ctx,
					int op_type);
bool hardening_detect_container_escape(struct hardening_task_ctx *ctx);
bool hardening_is_container_process(void);
int hardening_container_file_open(struct file *file);
int hardening_container_capable(int cap);
int hardening_container_sb_mount(const char *dev_name, const struct path *path,
				 const char *type, unsigned long flags);
int hardening_container_socket_connect(struct socket *sock,
				       struct sockaddr *address, int addrlen);
int hardening_docker_socket_access(struct file *file);

/* Network profiling */
int hardening_init_network_profile(struct hardening_task_ctx *ctx);
int hardening_update_network_activity(struct hardening_task_ctx *ctx,
				     int sock_type, int result);
int hardening_check_network_anomaly(struct hardening_task_ctx *ctx);
void hardening_free_network_profile(struct hardening_network_profile *network);
int hardening_socket_create(int family, int type, int protocol);
int hardening_socket_connect(struct socket *sock, struct sockaddr *address,
			     int addrlen);

/* Memory analysis */
int hardening_init_memory_profile(struct hardening_task_ctx *ctx);
int hardening_track_memory_operation(struct hardening_task_ctx *ctx,
				    int operation, unsigned long addr,
				    size_t len, int prot);
int hardening_detect_exploit_attempt(struct hardening_task_ctx *ctx);
void hardening_free_memory_profile(struct hardening_memory_profile *memory);

/* Cryptographic integrity */
int hardening_init_crypto(struct hardening_task_ctx *ctx);
int hardening_compute_process_hash(struct hardening_task_ctx *ctx);
int hardening_verify_integrity(struct hardening_task_ctx *ctx);
void hardening_free_crypto(struct hardening_crypto_ctx *crypto);

/* Quantum-resistant cryptography */
#ifdef CONFIG_SECURITY_HARDENING_QUANTUM
struct hardening_quantum_ctx *hardening_alloc_quantum_ctx(void);
void hardening_free_quantum_ctx(struct hardening_quantum_ctx *quantum);
int hardening_init_quantum(struct hardening_task_ctx *ctx);
int hardening_quantum_generate_keypair(struct hardening_quantum_ctx *quantum,
				      enum hardening_pq_algo algo);
int hardening_quantum_sign(struct hardening_quantum_ctx *quantum,
			  const void *data, size_t data_len,
			  u8 **signature, size_t *sig_len);
int hardening_quantum_verify(struct hardening_quantum_ctx *quantum,
			    const void *data, size_t data_len,
			    const u8 *signature, size_t sig_len);
int hardening_quantum_key_exchange(struct hardening_quantum_ctx *quantum,
				  const u8 *remote_public, size_t remote_len,
				  u8 **shared_secret, size_t *secret_len);
int hardening_quantum_authenticate_process(struct hardening_task_ctx *ctx);
int hardening_quantum_establish_channel(struct hardening_quantum_ctx *quantum,
				       u32 target_pid);
bool hardening_quantum_is_authenticated(struct hardening_task_ctx *ctx);
int hardening_quantum_rotate_keys(struct hardening_quantum_ctx *quantum);
#endif

/* Profile management */
int hardening_load_profile(const char *name, 
			  struct hardening_security_profile *profile);
struct hardening_security_profile *hardening_find_profile(const char *name);
int hardening_apply_profile(struct hardening_task_ctx *ctx,
			    const char *profile_name);
int hardening_check_profile_policy(struct hardening_task_ctx *ctx,
				   int policy_type, u32 value);
int hardening_init_profiles(void);
void hardening_cleanup_profiles(void);

/* Entropy and randomization */
void hardening_add_entropy(struct hardening_task_ctx *ctx, u32 value);
u32 hardening_get_random(struct hardening_task_ctx *ctx);
int hardening_randomize_decision(struct hardening_task_ctx *ctx,
				 int probability);
void hardening_init_entropy(struct hardening_task_ctx *ctx);
void hardening_random_delay(struct hardening_task_ctx *ctx, u32 max_delay_us);
void hardening_entropy_security_adjust(struct hardening_task_ctx *ctx,
				       u32 factor);
u32 hardening_randomize_threshold(struct hardening_task_ctx *ctx,
				  u32 base, u32 range);

/* Adaptive security */
void hardening_escalate_security(struct hardening_task_ctx *ctx);
void hardening_deescalate_security(struct hardening_task_ctx *ctx);
int hardening_check_capability(struct hardening_task_ctx *ctx, int cap);
int hardening_check_resource_limit(struct hardening_task_ctx *ctx,
				   int resource_type, u32 value);
const struct security_level_policy *
hardening_get_level_policy(enum hardening_security_level level);

/* Malware detection */
int hardening_init_malware_ctx(struct hardening_task_ctx *ctx);
void hardening_free_malware_ctx(struct malware_stats *stats);
int hardening_check_ransomware_write(struct file *file, const char __user *buf,
				     size_t len, struct hardening_task_ctx *ctx);
int hardening_check_ransomware_rename(struct dentry *old_dentry,
				      struct dentry *new_dentry,
				      struct hardening_task_ctx *ctx);
int hardening_check_cryptominer(struct hardening_task_ctx *ctx);
int hardening_check_execution_pattern(struct linux_binprm *bprm,
				      struct hardening_task_ctx *ctx);
int hardening_malware_file_open(struct file *file, struct hardening_task_ctx *ctx);

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