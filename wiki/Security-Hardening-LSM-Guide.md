# Security Hardening LSM Guide

This guide shows you how to use the Security Hardening LSM to protect your system.

## Quick Start

### 1. Check if it's working

```bash
hardening-status
```

If you see "Module: Enabled", you're good to go.

### 2. Secure an app quickly

```bash
# Secure nginx
hardening quick-secure nginx

# Secure firefox  
hardening quick-secure firefox
```

That's it. The app is now protected with a security profile.

### 3. See what's happening

```bash
# Open the dashboard
hardening-dashboard
```

Use TAB to switch between tabs. Press Q to quit.

## Common Tasks

### See why something was blocked

When an app doesn't work as expected:

```bash
# See the last blocked action
hardening explain --last-block

# See all blocks for firefox
hardening explain --pid $(pgrep firefox)
```

### Give temporary permissions

If an app needs to do something once:

```bash
# Allow extra permissions for 30 minutes
hardening allow-temp --pid 1234 --duration 30m
```

### Monitor an app

Watch what an app is doing:

```bash
# Monitor firefox for 5 minutes
hardening monitor firefox --duration 5m
```

### Create a custom profile

Use the learning wizard:

```bash
hardening-learn
```

Follow the steps:
1. Choose your app
2. Set learning time (default 5 minutes)
3. Use the app normally
4. Review and save the profile

## Desktop Notifications

Get alerts when something important happens:

```bash
# Start notifications
hardening-notify

# Test if it works
hardening-notify --test
```

## Profiles

### List profiles

```bash
hardening-profiles list
```

### See profile details

```bash
hardening-profiles show web_server
```

### Apply a profile

```bash
hardening-ctl profile nginx
```

## Emergency Actions

### Block a process immediately

```bash
hardening block 1234
```

### Unblock a process

```bash
hardening unblock 1234
```

### Reset everything

```bash
# Reset one app
hardening reset firefox

# Reset all security
hardening reset
```

## Automation

### Get JSON output

```bash
# Status in JSON
hardening-status --format json

# Profile list in JSON
hardening-profiles list --format json
```

### Use in scripts

```bash
#!/bin/bash
# Check if module is enabled
if hardening-status --format json | jq -r '.module.enabled'; then
    echo "Security is active"
fi
```

## Tips

1. **Start simple**: Use `quick-secure` for common apps
2. **Learn profiles**: Run `hardening-learn` when setting up new apps
3. **Check blocks**: Use `hardening explain` when things don't work
4. **Monitor first**: Use `hardening monitor` before creating profiles
5. **Keep notifications on**: Run `hardening-notify` in the background

## Troubleshooting

### App won't start

```bash
# Check if it's being blocked
hardening explain --last-block

# Give it temporary permissions
hardening allow-temp --pid $(pgrep appname)
```

### Too many alerts

```bash
# Edit notification settings
nano /etc/hardening-lsm/notify.conf
```

Change `min_severity` to "HIGH" or "CRITICAL".

### Profile too strict

```bash
# Re-learn the profile
hardening-learn

# Or edit it
nano /etc/hardening-lsm/profiles/yourapp.json
```

## Examples

### Secure a web server

```bash
# Quick secure
hardening quick-secure nginx

# Monitor for issues
hardening monitor nginx

# Check status
hardening-dashboard
```

### Secure a development environment

```bash
# Learn what your IDE does
hardening-learn
# Choose "Start a new process"
# Enter: code .
# Work normally for 5 minutes

# Apply the profile
hardening-ctl profile vscode
```

### Set up monitoring

```bash
# Terminal 1: Dashboard
hardening-dashboard

# Terminal 2: Notifications
hardening-notify

# Terminal 3: Your work
# Do your normal tasks
```

## Docker Security

### Enable Docker protection

```bash
# Enable container security
echo 1 > /sys/kernel/security/hardening/container_enabled

# Set isolation level (0=none, 1=normal, 2=strict)
echo 2 > /sys/kernel/security/hardening/container_isolation

# Load Docker security policy
cat /etc/hardening/docker-policy.yaml > /sys/kernel/security/hardening/policy
```

### Quick secure Docker containers

```bash
# Check if containers are detected
hardening-status --containers

# Monitor container security events
hardening monitor --container

# See container-specific blocks
hardening explain --container-blocks
```

### Docker-specific commands

```bash
# List protected containers
hardening docker list

# Check container security status
hardening docker status <container-id>

# Apply stricter policy to a container
hardening docker harden <container-name>

# Monitor Docker socket access
hardening docker socket-monitor
```

### Common Docker security tasks

#### Secure a new container

```bash
# Launch with security defaults
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# Check what was blocked
hardening explain --container <container-id>
```

#### Debug container issues

```bash
# Container won't start?
hardening docker debug <container-name>

# See why operations are blocked
dmesg | grep -E "container_|docker_"

# Give temporary permissions
hardening docker allow-temp <container-id> --cap SYS_ADMIN --duration 5m
```

#### Monitor container behavior

```bash
# Watch container in real-time
hardening-dashboard --container-view

# Export container security events
hardening docker export-events --format json > container-audit.json
```

### Docker security profiles

```bash
# Use pre-made profiles
hardening docker profile nginx --apply
hardening docker profile postgres --apply
hardening docker profile redis --apply

# Create custom profile
hardening-learn --container
```

### Container escape detection

The LSM automatically detects and blocks:
- Privileged container escapes
- Docker socket manipulation
- Dangerous mounts (proc, sysfs)
- Kernel module loading
- Raw device access

See alerts:
```bash
hardening docker escape-attempts
```

### Docker Compose security

```yaml
# docker-compose.yml with security annotations
services:
  web:
    image: nginx
    # Hardening LSM annotations
    labels:
      hardening.profile: "web_server"
      hardening.isolation: "strict"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

Apply:
```bash
hardening docker-compose secure docker-compose.yml
```

### Kubernetes integration

```yaml
# Pod with hardening annotations
apiVersion: v1
kind: Pod
metadata:
  annotations:
    hardening.security/profile: "web"
    hardening.security/isolation: "strict"
spec:
  containers:
  - name: app
    image: myapp:latest
```

## Next Steps

- Read `hardening --help` for all commands
- Check `/etc/hardening-lsm/profiles/` for profile examples  
- See `/etc/hardening/docker-policy.yaml` for Docker policies
- Read the full Docker integration guide at `/docs/docker-integration.md`
- Join the community for help and tips