# Testing the Hardening Security Module in a VM

## Quick Start

1. **Run the VM with the hardening kernel:**
   ```bash
   ./test-hardening-vm.sh
   ```

2. **Inside the VM, you'll see a welcome message showing:**
   - Whether the hardening module is loaded
   - Available security interfaces
   - Current module statistics

3. **Run the built-in tests:**
   ```bash
   # Test behavioral anomaly detection
   test-behavior
   
   # Test temporal access control
   test-temporal
   
   # Test resource monitoring
   test-resource
   
   # Test container security
   test-container
   ```

4. **Exit the VM:**
   Press `Ctrl-A` then `X`

## What the Hardening Module Does

The module provides several unique security features:

### 1. **Behavioral Anomaly Detection**
- Uses ML-inspired algorithms (n-grams, Markov chains)
- Detects unusual syscall patterns
- Identifies potential exploitation attempts

### 2. **Temporal Access Control**
- Time-based security policies
- Restrict operations to specific time windows
- Useful for maintenance windows or business hours

### 3. **Resource Usage Fingerprinting**
- Monitors CPU, memory, I/O patterns
- Detects deviation from baseline behavior
- Identifies resource-based attacks

### 4. **Container-Aware Security**
- Different policies for containerized workloads
- Container escape detection
- Namespace-aware security controls

### 5. **Adaptive Security Levels**
- Dynamic security posture based on threat level
- Escalates from NORMAL → ELEVATED → HIGH → CRITICAL
- Automatic response to detected threats

### 6. **Memory Exploit Detection**
- ROP chain detection
- Heap spray detection
- Stack pivot detection
- W^X enforcement monitoring

## Testing the Module

### Check Module Status
```bash
cat /sys/kernel/security/hardening/enabled
cat /sys/kernel/security/hardening/enforce
cat /sys/kernel/security/hardening/stats
```

### Enable/Disable Module
```bash
echo 1 > /sys/kernel/security/hardening/enabled  # Enable
echo 0 > /sys/kernel/security/hardening/enabled  # Disable
```

### Set Enforcement Mode
```bash
echo 1 > /sys/kernel/security/hardening/enforce  # Enforce (block violations)
echo 0 > /sys/kernel/security/hardening/enforce  # Monitor only
```

### View Statistics
```bash
cat /sys/kernel/security/hardening/stats
```

## Triggering Detections

### Behavioral Anomalies
```bash
# Rapid syscall pattern
for i in {1..1000}; do touch /tmp/test_$i && rm /tmp/test_$i; done

# Unusual executable creation
dd if=/dev/zero of=/tmp/suspicious bs=1K count=1
chmod +x /tmp/suspicious
/tmp/suspicious || true
```

### Resource Violations
```bash
# Memory spike
dd if=/dev/zero of=/tmp/huge bs=1M count=100

# Process bomb (careful!)
for i in {1..50}; do (sleep 3600) & done
killall sleep
```

### Memory Exploits (Simulated)
```bash
# These won't actually exploit but will trigger detection patterns
# Multiple mprotect calls
for i in {1..20}; do 
    dd if=/dev/zero of=/tmp/test$i bs=4K count=1 2>/dev/null
done
```

## VM Requirements

- QEMU (qemu-system-x86_64)
- 512MB RAM minimum
- KVM support recommended for better performance

## Troubleshooting

1. **Module not found**: Make sure CONFIG_SECURITY_HARDENING=y in .config
2. **VM won't start**: Check if QEMU is installed
3. **No KVM**: The VM will run slower without KVM acceleration
4. **Can't write to /sys files**: Some interfaces may be read-only

## Advanced Testing

For comprehensive testing, copy the test script into the VM:
```bash
# On host (before starting VM)
cp test-hardening-features.sh test-initramfs/

# In VM
/test-hardening-features.sh
```

This will run a full test suite checking all module features.