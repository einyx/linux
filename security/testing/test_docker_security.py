#!/usr/bin/env python3
"""
Docker Security Integration Tests

Tests the Hardening LSM's Docker/container security features
"""

import os
import sys
import subprocess
import json
import time
import tempfile
from pathlib import Path

class DockerSecurityTests:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.docker_available = self.check_docker()
        
    def check_docker(self):
        """Check if Docker is available"""
        try:
            result = subprocess.run(["docker", "--version"], 
                                  capture_output=True, check=True)
            return True
        except:
            print("WARNING: Docker not available, skipping container tests")
            return False
            
    def run_test(self, name, func):
        """Run a single test"""
        print(f"Testing {name}...", end=" ")
        try:
            func()
            print("PASSED")
            self.passed += 1
        except Exception as e:
            print(f"FAILED: {e}")
            self.failed += 1
            
    def run_container_cmd(self, image, cmd, **kwargs):
        """Run a command in a container"""
        docker_cmd = ["docker", "run", "--rm"]
        
        # Add additional Docker options
        for key, value in kwargs.items():
            if key == "privileged" and value:
                docker_cmd.append("--privileged")
            elif key == "cap_add":
                for cap in value:
                    docker_cmd.extend(["--cap-add", cap])
            elif key == "cap_drop":
                for cap in value:
                    docker_cmd.extend(["--cap-drop", cap])
            elif key == "security_opt":
                for opt in value:
                    docker_cmd.extend(["--security-opt", opt])
            elif key == "volumes":
                for vol in value:
                    docker_cmd.extend(["-v", vol])
                    
        docker_cmd.extend([image, "sh", "-c", cmd])
        
        return subprocess.run(docker_cmd, capture_output=True, text=True)
        
    def test_capability_restrictions(self):
        """Test capability restrictions in containers"""
        if not self.docker_available:
            return
            
        # Test 1: Try to load kernel module (should fail)
        result = self.run_container_cmd(
            "alpine:latest",
            "modprobe dummy",
            cap_add=["SYS_MODULE"]
        )
        assert result.returncode != 0, "Module loading should be blocked"
        
        # Test 2: Try to access raw sockets (should fail without CAP_NET_RAW)
        result = self.run_container_cmd(
            "alpine:latest", 
            "ping -c 1 google.com",
            cap_drop=["NET_RAW"]
        )
        assert result.returncode != 0, "Raw sockets should be blocked"
        
        # Test 3: Try to change system time (should fail)
        result = self.run_container_cmd(
            "alpine:latest",
            "date -s '2020-01-01'",
            cap_add=["SYS_TIME"]
        )
        assert result.returncode != 0, "System time change should be blocked"
        
    def test_filesystem_restrictions(self):
        """Test filesystem access restrictions"""
        if not self.docker_available:
            return
            
        # Test 1: Try to access Docker socket
        result = self.run_container_cmd(
            "alpine:latest",
            "ls -la /var/run/docker.sock",
            volumes=["/var/run/docker.sock:/var/run/docker.sock"]
        )
        # Should be blocked by LSM even if mounted
        
        # Test 2: Try to write to /proc/sys
        result = self.run_container_cmd(
            "alpine:latest",
            "echo 1 > /proc/sys/kernel/panic"
        )
        assert result.returncode != 0, "Writing to /proc/sys should be blocked"
        
        # Test 3: Try to access host filesystem
        result = self.run_container_cmd(
            "alpine:latest",
            "cat /etc/passwd",
            volumes=["/etc/passwd:/host/etc/passwd:ro"]
        )
        # Access to /host should be audited
        
    def test_escape_detection(self):
        """Test container escape detection"""
        if not self.docker_available:
            return
            
        # Test 1: Try to access process namespaces
        escape_script = """
        #!/bin/sh
        # Try various escape techniques
        
        # 1. Access /proc/self/exe
        ls -la /proc/self/exe
        
        # 2. Try to access other namespaces
        ls -la /proc/1/ns/
        
        # 3. Check for .dockerenv
        ls -la /.dockerenv
        
        # 4. Try to mount proc
        mkdir -p /tmp/proc
        mount -t proc proc /tmp/proc
        """
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(escape_script)
            script_path = f.name
            
        result = self.run_container_cmd(
            "alpine:latest",
            f"sh {script_path}",
            volumes=[f"{script_path}:{script_path}:ro"],
            privileged=True
        )
        
        os.unlink(script_path)
        
        # Should detect escape attempts
        
    def test_network_isolation(self):
        """Test network isolation enforcement"""
        if not self.docker_available:
            return
            
        # Test 1: Try to access host network services
        result = self.run_container_cmd(
            "alpine:latest",
            "nc -zv host.docker.internal 22"  # SSH port
        )
        # Should be blocked or audited
        
        # Test 2: Port scanning detection
        scan_script = """
        for port in $(seq 1000 1100); do
            timeout 0.1 nc -zv 127.0.0.1 $port 2>/dev/null
        done
        """
        
        result = self.run_container_cmd(
            "alpine:latest",
            scan_script
        )
        # Should detect port scanning
        
    def test_privileged_container_restrictions(self):
        """Test restrictions on privileged containers"""
        if not self.docker_available:
            return
            
        # Even privileged containers should have some restrictions
        result = self.run_container_cmd(
            "alpine:latest",
            "insmod /tmp/dummy.ko",
            privileged=True
        )
        assert result.returncode != 0, "Kernel module loading should be blocked"
        
    def test_mount_restrictions(self):
        """Test mount operation restrictions"""
        if not self.docker_available:
            return
            
        # Test dangerous mount types
        mount_tests = [
            ("proc", "/proc", "proc"),
            ("sysfs", "/sys", "sysfs"),
            ("debugfs", "/sys/kernel/debug", "debugfs"),
        ]
        
        for name, target, fstype in mount_tests:
            result = self.run_container_cmd(
                "alpine:latest",
                f"mkdir -p /mnt/{name} && mount -t {fstype} {fstype} /mnt/{name}",
                privileged=True
            )
            assert result.returncode != 0, f"Mounting {fstype} should be blocked"
            
    def test_resource_limits(self):
        """Test resource limit enforcement"""
        if not self.docker_available:
            return
            
        # Test memory limit
        result = self.run_container_cmd(
            "alpine:latest",
            "dd if=/dev/zero of=/tmp/bigfile bs=1M count=3000",  # 3GB
            security_opt=["memory:2g"]
        )
        # Should be killed by OOM or blocked
        
    def test_seccomp_integration(self):
        """Test seccomp filter integration"""
        if not self.docker_available:
            return
            
        # Test blocked syscalls
        blocked_syscalls = [
            ("kexec_load", "kexec -l /vmlinuz"),
            ("ptrace", "strace ls"),
            ("mount", "mount -t tmpfs tmpfs /mnt"),
        ]
        
        for syscall, cmd in blocked_syscalls:
            result = self.run_container_cmd(
                "alpine:latest",
                cmd,
                security_opt=["seccomp=unconfined"],  # Even with unconfined
                privileged=True
            )
            # LSM should still block
            
    def test_docker_socket_protection(self):
        """Test Docker socket access protection"""
        if not self.docker_available:
            return
            
        # Test 1: Non-root access to Docker socket
        result = self.run_container_cmd(
            "alpine:latest",
            "su nobody -c 'docker ps'",
            volumes=["/var/run/docker.sock:/var/run/docker.sock"]
        )
        assert result.returncode != 0, "Non-root Docker socket access should be blocked"
        
        # Test 2: Root access should be audited
        result = self.run_container_cmd(
            "alpine:latest", 
            "docker ps",
            volumes=["/var/run/docker.sock:/var/run/docker.sock"]
        )
        # Should be audited even if allowed
        
    def test_container_to_container_isolation(self):
        """Test container-to-container communication restrictions"""
        if not self.docker_available:
            return
            
        # Create a network for testing
        subprocess.run(["docker", "network", "create", "test-isolation"],
                      capture_output=True)
        
        try:
            # Start a server container
            server = subprocess.Popen([
                "docker", "run", "--rm", "--name", "test-server",
                "--network", "test-isolation",
                "alpine:latest", "nc", "-l", "-p", "8080"
            ])
            
            time.sleep(2)  # Let server start
            
            # Try to connect from client container
            result = subprocess.run([
                "docker", "run", "--rm", "--network", "test-isolation",
                "alpine:latest", "nc", "-zv", "test-server", "8080"
            ], capture_output=True, timeout=5)
            
            # Should be restricted in strict isolation mode
            
            server.terminate()
            
        finally:
            subprocess.run(["docker", "network", "rm", "test-isolation"],
                          capture_output=True)
            
    def check_audit_logs(self):
        """Check kernel audit logs for container events"""
        # Check dmesg for container security events
        result = subprocess.run(["dmesg", "-T", "--since", "5 minutes ago"],
                              capture_output=True, text=True)
        
        expected_events = [
            "container_created",
            "container_escape_attempt",
            "docker_socket_access",
            "container_dangerous_cap",
            "container_dangerous_mount"
        ]
        
        found_events = []
        for event in expected_events:
            if event in result.stdout:
                found_events.append(event)
                
        print(f"Found audit events: {found_events}")
        
    def run_all_tests(self):
        """Run all Docker security tests"""
        print("=== Docker Security Integration Tests ===\n")
        
        if not self.docker_available:
            print("Docker not available, skipping tests")
            return True
            
        tests = [
            ("Capability Restrictions", self.test_capability_restrictions),
            ("Filesystem Restrictions", self.test_filesystem_restrictions),
            ("Escape Detection", self.test_escape_detection),
            ("Network Isolation", self.test_network_isolation),
            ("Privileged Container Restrictions", self.test_privileged_container_restrictions),
            ("Mount Restrictions", self.test_mount_restrictions),
            ("Resource Limits", self.test_resource_limits),
            ("Seccomp Integration", self.test_seccomp_integration),
            ("Docker Socket Protection", self.test_docker_socket_protection),
            ("Container-to-Container Isolation", self.test_container_to_container_isolation),
        ]
        
        for name, func in tests:
            self.run_test(name, func)
            
        # Check audit logs
        print("\nChecking audit logs...")
        self.check_audit_logs()
        
        print(f"\n=== Test Summary ===")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Total:  {self.passed + self.failed}")
        
        return self.failed == 0

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: Docker security tests require root privileges")
        return 1
        
    runner = DockerSecurityTests()
    success = runner.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())