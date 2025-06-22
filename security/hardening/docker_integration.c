/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Docker/Container Security Integration for Hardening LSM
 *
 * Provides enhanced security for containerized environments
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/cgroup.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/net_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/user_namespace.h>
#include <linux/uts_namespace.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/capability.h>
#include <linux/in.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include "../security_audit.h"
#include "hardening.h"

/* Container runtime detection */
#define DOCKER_CGROUP_PREFIX	"docker"
#define CONTAINERD_CGROUP_PREFIX "containerd"
#define PODMAN_CGROUP_PREFIX	"machine.slice"
#define K8S_CGROUP_PREFIX	"kubepods"

/* Container security policies */
#define CONTAINER_MAX_CAPS	5	/* Maximum capabilities for containers */
#define CONTAINER_MAX_SYSCALLS	200	/* Restricted syscall set */
#define CONTAINER_MAX_MOUNTS	50	/* Mount limit per container */

/* Container escape detection patterns */
static const char *escape_patterns[] = {
	"/proc/self/exe",
	"/proc/self/fd",
	"/proc/sys/kernel/core_pattern",
	"/sys/fs/cgroup",
	"/var/run/docker.sock",
	"/.dockerenv",
	NULL
};

/* Dangerous capabilities for containers */
static const int dangerous_caps[] = {
	CAP_SYS_ADMIN,
	CAP_SYS_MODULE,
	CAP_SYS_RAWIO,
	CAP_SYS_PTRACE,
	CAP_SYS_BOOT,
	CAP_NET_ADMIN,
	CAP_DAC_READ_SEARCH,
	-1
};

/* Forward declarations */
static int check_inter_container_comm(struct socket *sock,
				      struct sockaddr *address);

/**
 * detect_container_runtime - Detect which container runtime is in use
 * @ctx: task security context
 *
 * Returns: container runtime type
 */
static enum container_runtime_type
detect_container_runtime(struct hardening_task_ctx *ctx)
{
	struct cgroup *cgrp;
	char *path;
	
	rcu_read_lock();
	cgrp = task_cgroup(current, cpu_cgrp_id);
	if (!cgrp) {
		rcu_read_unlock();
		return RUNTIME_NONE;
	}
	
	path = cgroup_path(cgrp, NULL, 0);
	rcu_read_unlock();
	
	if (!path)
		return RUNTIME_NONE;
		
	/* Check for various container runtimes */
	if (strstr(path, DOCKER_CGROUP_PREFIX))
		return RUNTIME_DOCKER;
	else if (strstr(path, CONTAINERD_CGROUP_PREFIX))
		return RUNTIME_CONTAINERD;
	else if (strstr(path, PODMAN_CGROUP_PREFIX))
		return RUNTIME_PODMAN;
	else if (strstr(path, K8S_CGROUP_PREFIX))
		return RUNTIME_K8S;
		
	kfree(path);
	return RUNTIME_NONE;
}

/**
 * is_container_process - Check if current process is in a container
 *
 * Returns: true if in container, false otherwise
 */
bool hardening_is_container_process(void)
{
	/* Check for container indicators */
	
	/* 1. Check PID namespace */
	if (task_active_pid_ns(current) != &init_pid_ns)
		return true;
		
	/* 2. Check for /.dockerenv file */
	struct path path;
	int ret = kern_path("/.dockerenv", LOOKUP_FOLLOW, &path);
	if (ret == 0) {
		path_put(&path);
		return true;
	}
	
	/* 3. Check cgroup membership */
	if (detect_container_runtime(NULL) != RUNTIME_NONE)
		return true;
		
	return false;
}

/**
 * check_container_escape_attempt - Detect container escape attempts
 * @file: file being accessed
 *
 * Returns: 0 if allowed, -EPERM if potential escape detected
 */
static int check_container_escape_attempt(struct file *file)
{
	struct dentry *dentry;
	char *path_buf, *path;
	int i;
	uid_t uid;
	
	if (!file || !file->f_path.dentry)
		return 0;
		
	dentry = file->f_path.dentry;
	
	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf)
		return 0;
		
	path = dentry_path_raw(dentry, path_buf, PATH_MAX);
	if (IS_ERR(path)) {
		kfree(path_buf);
		return 0;
	}
	
	/* Check against escape patterns */
	for (i = 0; escape_patterns[i]; i++) {
		if (strstr(path, escape_patterns[i])) {
			uid = from_kuid(&init_user_ns, current_uid());
			security_audit_log(AUDIT_EXPLOIT_ATTEMPT, uid,
					   "container_escape_attempt path=%s", path);
			kfree(path_buf);
			return -EPERM;
		}
	}
	
	/* Check for accessing host filesystem */
	if (strncmp(path, "/host", 5) == 0 ||
	    strncmp(path, "/var/lib/docker", 15) == 0) {
		uid = from_kuid(&init_user_ns, current_uid());
		security_audit_log("container_host_access", uid,
				   "path=%s", path);
	}
	
	kfree(path_buf);
	return 0;
}

/**
 * restrict_container_capabilities - Restrict capabilities for containers
 * @cap: capability being checked
 *
 * Returns: 0 if allowed, -EPERM if denied
 */
static int restrict_container_capabilities(int cap)
{
	int i;
	uid_t uid;
	
	/* Allow only safe capabilities in containers */
	for (i = 0; dangerous_caps[i] != -1; i++) {
		if (cap == dangerous_caps[i]) {
			uid = from_kuid(&init_user_ns, current_uid());
			security_audit_log("container_dangerous_cap", uid,
					   "capability=%d denied", cap);
			return -EPERM;
		}
	}
	
	return 0;
}

/**
 * check_container_mount - Check container mount operations
 * @dev_name: device name
 * @path: mount path
 * @type: filesystem type
 * @flags: mount flags
 *
 * Returns: 0 if allowed, error otherwise
 */
static int check_container_mount(const char *dev_name, const struct path *path,
				 const char *type, unsigned long flags)
{
	struct hardening_container_ctx *container;
	uid_t uid;
	
	container = current->security;
	if (!container)
		return 0;
		
	/* Deny dangerous mount types */
	if (type && (strcmp(type, "proc") == 0 ||
		     strcmp(type, "sysfs") == 0 ||
		     strcmp(type, "debugfs") == 0)) {
		uid = from_kuid(&init_user_ns, current_uid());
		security_audit_log("container_dangerous_mount", uid,
				   "type=%s denied", type);
		return -EPERM;
	}
	
	/* Check mount flags */
	if (!(flags & MS_RDONLY) && (flags & MS_BIND)) {
		/* Writable bind mount - potential escape vector */
		uid = from_kuid(&init_user_ns, current_uid());
		security_audit_log("container_writable_bind", uid,
				   "flags=0x%lx", flags);
	}
	
	/* Limit number of mounts per container */
	if (++container->mount_count > CONTAINER_MAX_MOUNTS) {
		uid = from_kuid(&init_user_ns, current_uid());
		security_audit_log("container_mount_limit", uid,
				   "count=%u", container->mount_count);
		return -ENOSPC;
	}
	
	return 0;
}

/**
 * container_network_isolation - Enforce network isolation for containers
 * @sk: socket
 * @address: socket address
 *
 * Returns: 0 if allowed, error otherwise
 */
static int container_network_isolation(struct socket *sock,
				       struct sockaddr *address)
{
	struct hardening_container_ctx *container;
	struct sockaddr_in *addr_in;
	uid_t uid;
	
	if (!hardening_is_container_process())
		return 0;
		
	container = current->security;
	if (!container || container->host_network)
		return 0;
		
	/* Check for attempts to access host network */
	if (address->sa_family == AF_INET) {
		addr_in = (struct sockaddr_in *)address;
		
		/* Deny access to host loopback from container */
		if (addr_in->sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
		    ntohs(addr_in->sin_port) < 1024) {
			uid = from_kuid(&init_user_ns, current_uid());
			security_audit_log("container_host_network", uid,
					   "port=%u denied", ntohs(addr_in->sin_port));
			return -EPERM;
		}
	}
	
	/* Check for container-to-container communication */
	if (container->isolation_level >= CONTAINER_ISOLATION_STRICT) {
		/* In strict mode, deny inter-container communication */
		return check_inter_container_comm(sock, address);
	}
	
	return 0;
}

/**
 * check_inter_container_comm - Check inter-container communication
 * @sock: socket
 * @address: destination address
 *
 * Returns: 0 if allowed, -EPERM if denied
 */
static int check_inter_container_comm(struct socket *sock,
				      struct sockaddr *address)
{
	/* In strict isolation mode, deny all inter-container communication */
	/* This is a simplified implementation - real implementation would
	 * check if source and destination are in different containers */
	
	uid_t uid = from_kuid(&init_user_ns, current_uid());
	security_audit_log("container_comm_blocked", uid,
			   "inter-container communication denied");
	
	return -EPERM;
}

/**
 * detect_privileged_container - Detect if container is running privileged
 *
 * Returns: true if privileged, false otherwise
 */
static bool detect_privileged_container(void)
{
	/* Check if all capabilities are present */
	if (capable(CAP_SYS_ADMIN) && 
	    capable(CAP_NET_ADMIN) &&
	    capable(CAP_SYS_MODULE))
		return true;
		
	/* Check if running as real root */
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID) &&
	    uid_eq(current_euid(), GLOBAL_ROOT_UID))
		return true;
		
	return false;
}

/**
 * enforce_container_seccomp - Enforce seccomp for containers
 * @container: container context
 *
 * Applies additional seccomp filters for container security
 */
static void enforce_container_seccomp(struct hardening_container_ctx *container)
{
	/* This would integrate with seccomp-bpf to restrict syscalls */
	static const int allowed_syscalls[] = {
		__NR_read, __NR_write, __NR_open, __NR_close,
		__NR_stat, __NR_fstat, __NR_lstat,
		__NR_poll, __NR_lseek, __NR_mmap,
		__NR_mprotect, __NR_munmap, __NR_brk,
		__NR_rt_sigaction, __NR_rt_sigprocmask,
		__NR_ioctl, __NR_pread64, __NR_pwrite64,
		__NR_readv, __NR_writev, __NR_access,
		__NR_pipe, __NR_select, __NR_sched_yield,
		__NR_mremap, __NR_msync, __NR_mincore,
		__NR_madvise, __NR_shmget, __NR_shmat,
		__NR_shmctl, __NR_dup, __NR_dup2,
		__NR_pause, __NR_nanosleep, __NR_getitimer,
		__NR_alarm, __NR_setitimer, __NR_getpid,
		__NR_sendfile, __NR_socket, __NR_connect,
		__NR_accept, __NR_sendto, __NR_recvfrom,
		__NR_sendmsg, __NR_recvmsg, __NR_shutdown,
		__NR_bind, __NR_listen, __NR_getsockname,
		__NR_getpeername, __NR_socketpair,
		__NR_setsockopt, __NR_getsockopt,
		__NR_fork, __NR_vfork, __NR_execve,
		__NR_exit, __NR_wait4, __NR_kill,
		__NR_uname, __NR_semget, __NR_semop,
		__NR_semctl, __NR_shmdt, __NR_msgget,
		__NR_msgsnd, __NR_msgrcv, __NR_msgctl,
		__NR_fcntl, __NR_flock, __NR_fsync,
		__NR_fdatasync, __NR_truncate,
		__NR_ftruncate, __NR_getdents,
		__NR_getcwd, __NR_chdir, __NR_fchdir,
		__NR_rename, __NR_mkdir, __NR_rmdir,
		__NR_creat, __NR_link, __NR_unlink,
		__NR_symlink, __NR_readlink, __NR_chmod,
		__NR_fchmod, __NR_chown, __NR_fchown,
		__NR_lchown, __NR_umask, __NR_gettimeofday,
		__NR_getrlimit, __NR_getrusage,
		__NR_sysinfo, __NR_times, __NR_ptrace,
		__NR_getuid, __NR_syslog, __NR_getgid,
		__NR_setuid, __NR_setgid, __NR_geteuid,
		__NR_getegid, __NR_setpgid, __NR_getppid,
		__NR_getpgrp, __NR_setsid, __NR_setreuid,
		__NR_setregid, __NR_getgroups,
		__NR_setgroups, __NR_setresuid,
		__NR_getresuid, __NR_setresgid,
		__NR_getresgid, __NR_getpgid, __NR_setfsuid,
		__NR_setfsgid, __NR_getsid, __NR_capget,
		__NR_capset, __NR_rt_sigpending,
		__NR_rt_sigtimedwait, __NR_rt_sigqueueinfo,
		__NR_rt_sigsuspend, __NR_utime,
		__NR_mknod, __NR_uselib, __NR_personality,
		__NR_ustat, __NR_statfs, __NR_fstatfs,
		__NR_getpriority, __NR_setpriority,
		__NR_sched_setparam, __NR_sched_getparam,
		__NR_sched_setscheduler,
		__NR_sched_getscheduler,
		__NR_sched_get_priority_max,
		__NR_sched_get_priority_min,
		__NR_sched_rr_get_interval, __NR_mlock,
		__NR_munlock, __NR_mlockall, __NR_munlockall,
		__NR_vhangup, __NR_modify_ldt, __NR_pivot_root,
		__NR_prctl, __NR_arch_prctl, __NR_adjtimex,
		__NR_setrlimit, __NR_chroot, __NR_acct,
		__NR_settimeofday, __NR_umount2, __NR_swapon,
		__NR_swapoff, __NR_sethostname,
		__NR_setdomainname, __NR_iopl, __NR_ioperm,
		__NR_init_module, __NR_delete_module,
		__NR_quotactl, __NR_readahead, __NR_setxattr,
		__NR_lsetxattr, __NR_fsetxattr, __NR_getxattr,
		__NR_lgetxattr, __NR_fgetxattr, __NR_listxattr,
		__NR_llistxattr, __NR_flistxattr,
		__NR_removexattr, __NR_lremovexattr,
		__NR_fremovexattr, __NR_tkill, __NR_time,
		__NR_futex, __NR_set_thread_area,
		__NR_get_thread_area, __NR_io_setup,
		__NR_io_destroy, __NR_io_getevents,
		__NR_io_submit, __NR_io_cancel,
		__NR_lookup_dcookie, __NR_epoll_create,
		__NR_remap_file_pages, __NR_getdents64,
		__NR_set_tid_address, __NR_restart_syscall,
		__NR_semtimedop, __NR_fadvise64,
		__NR_timer_create, __NR_timer_settime,
		__NR_timer_gettime, __NR_timer_getoverrun,
		__NR_timer_delete, __NR_clock_settime,
		__NR_clock_gettime, __NR_clock_getres,
		__NR_clock_nanosleep, __NR_exit_group,
		__NR_epoll_wait, __NR_epoll_ctl,
		__NR_tgkill, __NR_utimes,
		-1
	};
	
	container->syscall_whitelist = allowed_syscalls;
	container->syscall_count = ARRAY_SIZE(allowed_syscalls) - 1;
}

/**
 * init_container_context - Initialize container security context
 * @ctx: task security context
 *
 * Returns: 0 on success, error otherwise
 */
int hardening_init_container_context(struct hardening_task_ctx *ctx)
{
	struct hardening_container_ctx *container;
	enum container_runtime_type runtime;
	
	if (!hardening_is_container_process())
		return 0;
		
	container = kzalloc(sizeof(*container), GFP_KERNEL);
	if (!container)
		return -ENOMEM;
		
	/* Detect runtime */
	runtime = detect_container_runtime(ctx);
	container->runtime = runtime;
	
	/* Set container ID from cgroup */
	container->container_id = task_cgroup_id(current);
	
	/* Detect privileged mode */
	container->privileged = detect_privileged_container();
	
	/* Check namespace sharing with host */
	container->host_network = (current->nsproxy->net_ns == &init_net);
	container->host_pid = (task_active_pid_ns(current) == &init_pid_ns);
	container->host_ipc = (current->nsproxy->ipc_ns == &init_ipc_ns);
	
	/* Set default isolation level */
	if (container->privileged)
		container->isolation_level = CONTAINER_ISOLATION_NONE;
	else if (runtime == RUNTIME_K8S)
		container->isolation_level = CONTAINER_ISOLATION_STRICT;
	else
		container->isolation_level = CONTAINER_ISOLATION_NORMAL;
		
	/* Apply seccomp restrictions */
	if (!container->privileged)
		enforce_container_seccomp(container);
		
	/* Initialize resource limits */
	container->memory_limit = 512 * 1024 * 1024; /* 512MB default */
	container->cpu_quota = 50; /* 50% CPU default */
	
	ctx->container = container;
	
	/* Log container creation */
	security_audit_log("container_created", 
			   from_kuid(&init_user_ns, current_uid()),
			   "runtime=%d privileged=%d isolation=%d",
			   runtime, container->privileged,
			   container->isolation_level);
			   
	return 0;
}

/**
 * Container-specific LSM hooks
 */

int hardening_container_file_open(struct file *file)
{
	if (!hardening_is_container_process())
		return 0;
		
	return check_container_escape_attempt(file);
}

int hardening_container_capable(int cap)
{
	if (!hardening_is_container_process())
		return 0;
		
	return restrict_container_capabilities(cap);
}

int hardening_container_sb_mount(const char *dev_name, const struct path *path,
				 const char *type, unsigned long flags)
{
	if (!hardening_is_container_process())
		return 0;
		
	return check_container_mount(dev_name, path, type, flags);
}

int hardening_container_socket_connect(struct socket *sock,
				       struct sockaddr *address, int addrlen)
{
	if (!hardening_is_container_process())
		return 0;
		
	return container_network_isolation(sock, address);
}

/**
 * Docker socket protection
 */
int hardening_docker_socket_access(struct file *file)
{
	struct dentry *dentry;
	char *path_buf, *path;
	uid_t uid;
	
	if (!file || !file->f_path.dentry)
		return 0;
		
	dentry = file->f_path.dentry;
	
	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!path_buf)
		return 0;
		
	path = dentry_path_raw(dentry, path_buf, PATH_MAX);
	if (IS_ERR(path)) {
		kfree(path_buf);
		return 0;
	}
	
	/* Check if accessing Docker socket */
	if (strcmp(path, "/var/run/docker.sock") == 0) {
		/* Only allow root and docker group */
		if (!uid_eq(current_uid(), GLOBAL_ROOT_UID) &&
		    !in_group_p(GLOBAL_ROOT_GID)) {
			uid = from_kuid(&init_user_ns, current_uid());
			security_audit_log("docker_socket_denied", uid,
					   "unauthorized access attempt");
			kfree(path_buf);
			return -EPERM;
		}
		
		/* Log access for audit */
		uid = from_kuid(&init_user_ns, current_uid());
		security_audit_log("docker_socket_access", uid,
				   "granted");
	}
	
	kfree(path_buf);
	return 0;
}