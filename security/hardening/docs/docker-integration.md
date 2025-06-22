# Docker/Container Security Integration

The Hardening LSM provides comprehensive security for Docker and other container runtimes through deep kernel-level integration.

## Features

### 1. Container Runtime Detection
- Automatic detection of Docker, containerd, Podman, and Kubernetes
- Runtime-specific security policies
- Container ID tracking via cgroups

### 2. Capability Restrictions
Dangerous capabilities are denied by default in containers:
- `CAP_SYS_ADMIN` - Prevent container escape
- `CAP_SYS_MODULE` - Block kernel module loading
- `CAP_SYS_RAWIO` - Prevent raw I/O access
- `CAP_SYS_PTRACE` - Block process tracing
- `CAP_NET_ADMIN` - Restrict network configuration

### 3. Filesystem Protection
- Block access to sensitive paths:
  - `/proc/sys/*` - Kernel parameters
  - `/sys/fs/cgroup` - Cgroup filesystem
  - `/var/run/docker.sock` - Docker socket
  - `/var/lib/docker` - Docker storage
- Prevent dangerous mounts (proc, sysfs, debugfs)
- Detect container escape attempts

### 4. Network Isolation
- Restrict container-to-host communication
- Detect port scanning behavior
- Block access to host services
- Optional strict container-to-container isolation

### 5. Docker Socket Protection
- Restrict Docker socket access to authorized users
- Audit all Docker API operations
- Prevent privilege escalation via Docker

### 6. Resource Limits
- Memory limits (default: 512MB)
- CPU quotas (default: 50%)
- PID limits
- Mount count restrictions

## Configuration

### Enable Container Security
```bash
echo 1 > /sys/kernel/security/hardening/container_enabled
```

### Set Isolation Level
```bash
# 0 = None, 1 = Normal, 2 = Strict
echo 2 > /sys/kernel/security/hardening/container_isolation
```

### Load Policy
```bash
cat /etc/hardening/docker-policy.yaml > /sys/kernel/security/hardening/policy
```

## Usage Examples

### Running Secure Containers

1. **Basic container with LSM protection:**
```bash
docker run --rm alpine:latest sh -c "echo Hello from secure container"
```

2. **Container with specific capabilities:**
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx
```

3. **Privileged container (still restricted by LSM):**
```bash
docker run --rm --privileged alpine:latest sh -c "modprobe dummy"
# Will fail - kernel module loading blocked
```

### Monitoring

View container security events:
```bash
dmesg | grep -E "container_|docker_"
```

Check audit log:
```bash
ausearch -m AVC -ts recent | grep container
```

## Integration with Container Runtimes

### Docker
The LSM automatically detects Docker containers by:
- Checking cgroup paths for "docker" prefix
- Monitoring Docker socket access
- Tracking container namespace creation

### Kubernetes
Enhanced security for K8s pods:
- Enforce Pod Security Standards
- Block host network/PID/IPC by default
- Integrate with admission controllers

### Podman
Rootless container support:
- User namespace detection
- UID mapping restrictions
- Rootless-specific policies

## Security Policies

### Default Policy
Located at `/etc/hardening/docker-policy.yaml`

Key sections:
- `denied_capabilities`: Capabilities blocked in containers
- `denied_paths`: Filesystem paths containers cannot access
- `denied_mount_types`: Mount types containers cannot use
- `resource_limits`: Default resource constraints

### Custom Policies

Create runtime-specific policies:

```yaml
runtime_policies:
  production:
    denied_capabilities:
      - ALL
    allowed_capabilities:
      - NET_BIND_SERVICE
      - SETUID
      - SETGID
    isolation_level: strict
```

## Troubleshooting

### Container Fails to Start
Check for capability denials:
```bash
dmesg | grep "container_dangerous_cap"
```

### Application Errors in Container
Check for filesystem access denials:
```bash
dmesg | grep "container_escape_attempt"
```

### Network Issues
Check for network isolation blocks:
```bash
dmesg | grep "container_host_network"
```

## Best Practices

1. **Never disable the LSM for containers** - Use policies to allow specific operations
2. **Avoid privileged containers** - Use specific capabilities instead
3. **Enable audit logging** - Monitor container security events
4. **Use read-only root filesystems** - Add `:ro` to mounts
5. **Implement network policies** - Use container-specific firewall rules

## Performance Impact

The container security features add minimal overhead:
- ~2-5% CPU overhead for capability checks
- ~1-3% memory overhead for tracking
- <1ms latency for most operations

Optimizations:
- Per-CPU statistics collection
- RCU-based policy lookups
- Cached security decisions

## API Reference

### Sysfs Interface

```
/sys/kernel/security/hardening/
├── container_enabled      # Enable/disable container security
├── container_isolation    # Set isolation level (0-2)
├── container_stats/       # Per-container statistics
│   ├── created           # Containers created
│   ├── destroyed         # Containers destroyed
│   ├── escapes_blocked   # Escape attempts blocked
│   └── violations        # Policy violations
└── policy                # Load security policy
```

### Prctl Interface

```c
#define PR_HARDENING_GET_CONTAINER  0x48000001
#define PR_HARDENING_SET_ISOLATION   0x48000002

// Get container ID
uint64_t container_id;
prctl(PR_HARDENING_GET_CONTAINER, &container_id, 0, 0, 0);

// Set isolation level
prctl(PR_HARDENING_SET_ISOLATION, CONTAINER_ISOLATION_STRICT, 0, 0, 0);
```

## Contributing

To contribute to the Docker integration:

1. Review the code in `security/hardening/docker_integration.c`
2. Add tests to `security/testing/test_docker_security.py`
3. Update policies in `security/hardening/policies/`
4. Submit patches to the kernel security mailing list

## Future Enhancements

Planned features:
- OCI runtime spec integration
- eBPF-based syscall filtering
- Machine learning for anomaly detection
- Integration with container registries
- Automated policy generation