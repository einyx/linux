# Linux Security Hardening Module

A comprehensive Linux Security Module (LSM) that provides innovative security features not found in existing LSMs, with ML-inspired anomaly detection and advanced threat mitigation.

## Core Features

### 1. Temporal Access Control
- Time-based security policies with hour/day restrictions
- Business hours enforcement
- Time window-based capability restrictions
- Weekend/holiday access controls

### 2. ML-Inspired Behavioral Anomaly Detection
- N-gram analysis for syscall pattern recognition
- Markov chain transition probability modeling
- Shannon entropy calculation for randomness detection
- Sequence complexity analysis
- Real-time anomaly scoring with adaptive thresholds

### 3. Resource Usage Fingerprinting
- Baseline establishment with learning mode
- CPU, memory, I/O, and file descriptor monitoring
- Statistical deviation detection
- Automatic anomaly response

### 4. Process Lineage Tracking
- Full ancestry chain analysis
- Suspicious process chain detection (e.g., web server→shell→wget)
- Container escape pattern recognition
- Fork bomb detection

### 5. Container-Aware Security with Docker Integration
- Automatic container runtime detection (Docker, containerd, Podman, K8s)
- Container-specific capability restrictions
- Docker socket access protection
- Container escape detection and prevention
- Filesystem and mount restrictions
- Network isolation enforcement
- Inter-container communication control
- Resource limit enforcement
- Integration with seccomp filters

### 6. Network Behavior Profiling
- Connection rate monitoring
- Port scan detection
- Destination tracking
- Failed connection analysis
- Suspicious port access alerts

### 7. Memory Access Pattern Analysis
- Heap spray detection
- ROP chain identification
- W^X violation tracking
- Stack pivot detection
- Allocation entropy analysis

### 8. Entropy-Based Randomization
- Unpredictable security decisions
- Anti-timing attack measures
- Dynamic threshold adjustment
- Per-process entropy pools

### 9. Cryptographic Integrity
- Process hashing with SHA-256
- Memory integrity verification
- File integrity checking

### 10. Security Profiles
- Pre-defined profiles (web_server, database, container, developer)
- Custom profile support
- Per-process security policies
- Resource limits and capability restrictions

### 11. Adaptive Security Levels
- Four levels: Normal, Elevated, High, Critical
- Automatic escalation based on threats
- Progressive restriction enforcement
- Time-based de-escalation

## Configuration

### Enable the module in kernel config:
```
CONFIG_SECURITY_HARDENING=y
CONFIG_SECURITY_HARDENING_SYSCALL_FILTER=y
CONFIG_SECURITY_HARDENING_NETWORK=y
```

### Boot parameters:
Add `hardening` to the LSM list:
```
lsm=landlock,lockdown,yama,loadpin,safesetid,hardening,selinux,apparmor
```

### Runtime configuration via sysctl:
```bash
# Enable/disable module
echo 1 > /proc/sys/kernel/hardening/enabled

# Set enforcement mode (0=permissive, 1=enforcing)
echo 1 > /proc/sys/kernel/hardening/enforce
```

### SecurityFS interface:
```bash
# View current status
cat /sys/kernel/security/hardening/status

# View statistics
cat /sys/kernel/security/hardening/stats

# Configure policies
echo "enable" > /sys/kernel/security/hardening/policy
echo "enforce" > /sys/kernel/security/hardening/policy
```

## Usage Examples

### Temporal Access Control
```c
// In application code, set time restrictions via prctl
struct hardening_time_rule rule = {
    .hour_start = 9,    // 9 AM
    .hour_end = 17,     // 5 PM
    .days_mask = 0x3E,  // Monday-Friday
    .allowed_caps = CAP_TO_MASK(CAP_NET_BIND_SERVICE)
};
// Would need custom prctl implementation
```

### Monitoring
- Check dmesg for security events:
```bash
dmesg | grep hardening:
```

- Monitor security level changes:
```bash
watch -n 1 'cat /sys/kernel/security/hardening/status'
```

## Security Levels

1. **Normal**: No additional restrictions
2. **Elevated**: Blocks module loading, kexec, limits file descriptors
3. **High**: Blocks most capabilities, user namespaces, network restrictions
4. **Critical**: Maximum restrictions, minimal capabilities allowed

## Implementation Details

The module hooks into:
- Process creation (`bprm_creds_for_exec`)
- Capability checks (`capable`)
- File operations (`file_open`)
- Ptrace operations (`ptrace_access_check`)
- System call auditing (for behavioral analysis)

## Testing

1. Enable in permissive mode first:
```bash
echo 0 > /proc/sys/kernel/hardening/enforce
```

2. Monitor logs for policy violations
3. Gradually enable enforcement once policies are tuned

## Docker/Container Integration

The Hardening LSM provides deep integration with Docker and container runtimes:

### Container Security Features
- **Automatic Detection**: Identifies containers via cgroups and namespaces
- **Runtime Support**: Docker, containerd, Podman, Kubernetes
- **Capability Restrictions**: Blocks dangerous capabilities (SYS_ADMIN, SYS_MODULE, etc.)
- **Escape Prevention**: Detects and blocks container escape attempts
- **Docker Socket Protection**: Restricts access to Docker API
- **Network Isolation**: Controls container-to-host and container-to-container communication

### Quick Start for Docker Security
```bash
# Enable container security
echo 1 > /sys/kernel/security/hardening/container_enabled

# Set strict isolation
echo 2 > /sys/kernel/security/hardening/container_isolation

# Load Docker policy
cat /etc/hardening/docker-policy.yaml > /sys/kernel/security/hardening/policy
```

### Example: Secure Container Launch
```bash
# Container with LSM protection (dangerous operations blocked)
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# Even privileged containers are restricted
docker run --rm --privileged alpine modprobe dummy  # Blocked by LSM
```

For detailed Docker integration documentation, see [docs/docker-integration.md](docs/docker-integration.md).

## Future Enhancements

- Machine learning models for better anomaly detection
- Integration with IMA/EVM for integrity verification
- Enhanced container runtime integration (CRI-O, rkt)
- eBPF-based syscall filtering for containers
- Per-application security profiles