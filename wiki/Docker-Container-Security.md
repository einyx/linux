# Docker and Container Security with Hardening LSM

The Hardening LSM provides kernel-level security for Docker containers and other container runtimes, offering protection beyond what standard container security provides.

## Overview

### What it protects against

- **Container escapes**: Blocks attempts to break out of container isolation
- **Privilege escalation**: Prevents containers from gaining host privileges  
- **Docker socket attacks**: Protects the Docker daemon API
- **Resource abuse**: Enforces CPU, memory, and I/O limits
- **Network attacks**: Controls container-to-container and container-to-host communication

### Supported runtimes

- Docker / Docker Engine
- containerd
- Podman
- Kubernetes (via CRI)
- LXC/LXD (partial support)

## How it Works

### Automatic Detection

The LSM automatically detects containers by:

1. **Cgroup analysis**: Identifies container cgroup paths
2. **Namespace inspection**: Detects PID, network, mount namespaces
3. **Runtime markers**: Looks for `.dockerenv`, container labels
4. **Process lineage**: Tracks container init processes

### Security Layers

```
┌─────────────────────────────────┐
│     Container Application       │
├─────────────────────────────────┤
│     Container Runtime           │
├─────────────────────────────────┤
│     Hardening LSM               │ ← Kernel-level enforcement
├─────────────────────────────────┤
│     Linux Security Modules      │
├─────────────────────────────────┤
│     Linux Kernel                │
└─────────────────────────────────┘
```

## Key Features

### 1. Capability Filtering

Dangerous capabilities are blocked by default:

| Capability | Risk | LSM Action |
|------------|------|------------|
| CAP_SYS_ADMIN | Container escape | Blocked |
| CAP_SYS_MODULE | Kernel rootkit | Blocked |
| CAP_SYS_PTRACE | Process inspection | Restricted |
| CAP_NET_ADMIN | Network manipulation | Restricted |
| CAP_DAC_READ_SEARCH | File access bypass | Blocked |

### 2. Filesystem Protection

Protected paths (even if mounted):
- `/proc/sys/*` - Kernel parameters
- `/sys/fs/cgroup` - Control groups
- `/var/run/docker.sock` - Docker API
- `/dev/mem`, `/dev/kmem` - Memory devices

### 3. Mount Restrictions

Blocked mount types:
- `proc` - Process information
- `sysfs` - System devices
- `debugfs` - Kernel debugging
- `securityfs` - Security modules

Required mount options:
- `nosuid` - No setuid binaries
- `nodev` - No device files
- `noexec` - No execution (where applicable)

### 4. Network Isolation

Three isolation levels:

**None (0)**: No additional restrictions

**Normal (1)**: 
- Block container-to-host localhost access
- Audit unusual port usage
- Detect port scanning

**Strict (2)**:
- Block all inter-container communication
- Whitelist-only external access
- Enforce network policies

## Configuration

### System-wide Settings

```bash
# Enable/disable container security
echo 1 > /sys/kernel/security/hardening/container_enabled

# Set default isolation level
echo 2 > /sys/kernel/security/hardening/container_isolation

# Load policy file
cat /etc/hardening/docker-policy.yaml > /sys/kernel/security/hardening/policy
```

### Per-Container Settings

Using Docker labels:
```bash
docker run -d \
  --label hardening.isolation=strict \
  --label hardening.profile=web_server \
  nginx:latest
```

Using environment variables:
```bash
docker run -d \
  -e HARDENING_ISOLATION=strict \
  -e HARDENING_PROFILE=web_server \
  nginx:latest
```

## Security Policies

### Default Policy

Located at `/etc/hardening/docker-policy.yaml`:

```yaml
container_defaults:
  denied_capabilities:
    - CAP_SYS_ADMIN
    - CAP_SYS_MODULE
    - CAP_SYS_RAWIO
    
  resource_limits:
    memory_max: "2G"
    cpu_quota: "200%"
    
  network:
    deny_raw_sockets: true
    deny_host_network: true
```

### Custom Policies

Create runtime-specific policies:

```yaml
# /etc/hardening/policies/production.yaml
production_containers:
  isolation_level: strict
  
  denied_operations:
    - mount
    - pivot_root
    - kexec
    
  allowed_syscalls:
    # Whitelist specific syscalls
    - read
    - write
    - open
    - close
    # ... minimal set
    
  network:
    allowed_ports: [80, 443]
    deny_all_outbound: false
```

## Usage Examples

### Basic Container Security

```bash
# Run a secure container
docker run --rm \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --read-only \
  --security-opt no-new-privileges \
  nginx:latest
```

### Debugging Blocked Operations

```bash
# Check why container operation failed
hardening docker debug nginx_container

# Output:
# [BLOCKED] CAP_SYS_ADMIN: mount operation denied
# [BLOCKED] /proc/sys write attempt
# [ALLOWED] bind to port 80
```

### Monitoring Container Security

```bash
# Real-time monitoring
hardening-dashboard --container-view

# Container security report
hardening docker report --last-hour

# Export audit events
hardening docker audit --format json > audit.json
```

## Advanced Features

### Container Escape Detection

The LSM detects escape attempts through:

1. **Process monitoring**: Unexpected parent changes
2. **Namespace tracking**: Escape from namespaces  
3. **File access patterns**: Access to host paths
4. **Syscall analysis**: Dangerous syscall sequences

Example alert:
```
[CRITICAL] Container escape attempt detected
Container: nginx_prod (ID: abc123)
Method: namespace manipulation
Action: Blocked and terminated
```

### Runtime-Specific Features

#### Docker
- Docker socket protection
- Image scanning integration
- Swarm mode security
- BuildKit isolation

#### Kubernetes
- Pod Security Standards enforcement
- NetworkPolicy integration
- Admission webhook support
- CRI-O compatibility

#### Podman
- Rootless container support
- User namespace protection
- Systemd integration
- Pod security

### Performance Optimization

The LSM minimizes overhead through:

- **Cached decisions**: Recent allow/deny cached
- **Fast path checks**: Common operations optimized
- **Per-CPU statistics**: No lock contention
- **Lazy evaluation**: Expensive checks deferred

Typical overhead: <5% CPU, <10MB memory per container

## Troubleshooting

### Container Won't Start

```bash
# Check for capability denials
dmesg | grep container_dangerous_cap

# Try with reduced security temporarily
docker run --security-opt hardening=permissive ...

# Create exception
hardening docker exception add nginx_startup
```

### Network Issues

```bash
# Check network blocks
hardening docker network-debug <container>

# Allow specific connection
hardening docker allow-network <container> --port 3306 --dest mysql_server
```

### Performance Problems

```bash
# Check overhead
hardening docker perf-stats

# Disable expensive checks
echo 0 > /sys/kernel/security/hardening/container_behavioral_analysis
```

## Integration

### CI/CD Pipeline

```yaml
# .gitlab-ci.yml
test:
  script:
    - hardening docker scan ${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA}
    - docker run --rm --security-opt hardening=enforce ${CI_REGISTRY_IMAGE}:${CI_COMMIT_SHA} test
```

### Docker Compose

```yaml
version: '3.8'
services:
  web:
    image: nginx
    security_opt:
      - hardening=enforce
      - hardening.profile=web_server
```

### Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    hardening.security/enforce: "true"
    hardening.security/profile: "web-server"
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
```

## Best Practices

1. **Start with monitoring**: Use `isolation_level: 0` initially
2. **Build profiles gradually**: Use learning mode for complex apps
3. **Layer security**: Combine with seccomp, AppArmor/SELinux
4. **Regular updates**: Keep policies updated with app changes
5. **Monitor alerts**: Set up notification for security events

## FAQ

**Q: Does it work with rootless containers?**
A: Yes, with additional user namespace protections.

**Q: Can I use it with existing security tools?**
A: Yes, it complements AppArmor, SELinux, and seccomp.

**Q: What's the performance impact?**
A: Typically 2-5% CPU overhead, less than 10MB RAM per container.

**Q: Does it support Windows containers?**
A: No, Linux containers only.

**Q: Can I disable it for specific containers?**
A: Yes, use `--security-opt hardening=disabled`.

## Additional Resources

- [Docker Security Best Practices](/docs/docker-integration.md)
- [Policy Reference](/docs/policies/container-policies.md)
- [API Documentation](/docs/api/container-api.md)
- [Performance Tuning](/docs/performance/container-tuning.md)