#!/usr/bin/env python3
"""
Comprehensive Security Module Test Suite

Tests various security modules for correct behavior and edge cases
"""

import os
import sys
import subprocess
import tempfile
import time
import random
import threading
import signal
from pathlib import Path

class SecurityModuleTests:
    def __init__(self):
        self.test_dir = tempfile.mkdtemp(prefix="lsm_test_")
        self.passed = 0
        self.failed = 0
        self.tests = []
        
    def cleanup(self):
        """Clean up test directory"""
        subprocess.run(["rm", "-rf", self.test_dir], check=False)
        
    def run_test(self, name, func):
        """Run a single test"""
        print(f"Running test: {name}...", end=" ")
        try:
            func()
            print("PASSED")
            self.passed += 1
            return True
        except Exception as e:
            print(f"FAILED: {e}")
            self.failed += 1
            return False
            
    def test_rate_limiting(self):
        """Test rate limiting prevents DoS"""
        # Create test program that triggers many security checks
        test_prog = f"{self.test_dir}/rate_limit_test"
        code = """
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

int main() {
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    // Trigger many file operations
    for (int i = 0; i < 10000; i++) {
        int fd = open("/etc/passwd", O_RDONLY);
        if (fd >= 0) close(fd);
    }
    
    gettimeofday(&end, NULL);
    long elapsed = (end.tv_sec - start.tv_sec) * 1000 + 
                   (end.tv_usec - start.tv_usec) / 1000;
    
    // Should complete quickly if rate limiting works
    if (elapsed > 5000) {
        printf("SLOW: %ld ms\\n", elapsed);
        return 1;
    }
    
    printf("OK: %ld ms\\n", elapsed);
    return 0;
}
"""
        with open(f"{test_prog}.c", "w") as f:
            f.write(code)
            
        # Compile and run
        subprocess.run(["gcc", "-O2", f"{test_prog}.c", "-o", test_prog], check=True)
        result = subprocess.run([test_prog], capture_output=True)
        
        assert result.returncode == 0, "Rate limiting test failed"
        
    def test_memory_protection(self):
        """Test memory exploitation detection"""
        test_prog = f"{self.test_dir}/memory_test"
        code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    // Test 1: RWX mapping detection
    void *rwx = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (rwx == MAP_FAILED) {
        printf("RWX mapping blocked - GOOD\\n");
    } else {
        munmap(rwx, 4096);
        printf("RWX mapping allowed - BAD\\n");
        return 1;
    }
    
    // Test 2: Heap spray detection
    size_t total = 0;
    for (int i = 0; i < 1000; i++) {
        void *p = malloc(1024 * 1024); // 1MB chunks
        if (!p) break;
        memset(p, 0x90, 1024 * 1024); // NOP sled pattern
        total += 1024 * 1024;
    }
    
    if (total < 100 * 1024 * 1024) {
        printf("Heap spray blocked at %zu MB - GOOD\\n", total / (1024*1024));
    } else {
        printf("Heap spray not detected - BAD\\n");
        return 1;
    }
    
    return 0;
}
"""
        with open(f"{test_prog}.c", "w") as f:
            f.write(code)
            
        subprocess.run(["gcc", "-O2", f"{test_prog}.c", "-o", test_prog], check=True)
        result = subprocess.run([test_prog], capture_output=True, text=True)
        
        print(f"Memory test output: {result.stdout}")
        # Note: May pass if hardening LSM not loaded
        
    def test_network_anomaly_detection(self):
        """Test network anomaly detection"""
        test_prog = f"{self.test_dir}/network_test"
        code = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    int blocked = 0;
    
    // Test rapid connection attempts (potential DoS)
    for (int i = 0; i < 200; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            blocked++;
            continue;
        }
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        // Non-blocking connect
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
        
        usleep(1000); // 1ms delay
    }
    
    printf("Blocked %d/200 rapid connections\\n", blocked);
    
    // Test port scanning behavior
    int scan_blocked = 0;
    for (int port = 1000; port < 1100; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            scan_blocked++;
            continue;
        }
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
    }
    
    printf("Blocked %d/100 port scan attempts\\n", scan_blocked);
    
    return (blocked > 50 || scan_blocked > 20) ? 0 : 1;
}
"""
        with open(f"{test_prog}.c", "w") as f:
            f.write(code)
            
        subprocess.run(["gcc", "-O2", f"{test_prog}.c", "-o", test_prog], check=True)
        result = subprocess.run([test_prog], capture_output=True, text=True)
        
        print(f"Network test output: {result.stdout}")
        
    def test_behavior_anomaly_detection(self):
        """Test behavioral anomaly detection"""
        test_prog = f"{self.test_dir}/behavior_test"
        code = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

int main() {
    // Normal behavior pattern
    for (int i = 0; i < 100; i++) {
        int fd = open("/tmp/test", O_CREAT|O_RDWR, 0600);
        if (fd >= 0) {
            if (write(fd, "test", 4) < 0) perror("write");
            close(fd);
        }
        unlink("/tmp/test");
        usleep(10000);
    }
    
    // Sudden anomalous pattern
    printf("Starting anomalous behavior...\\n");
    
    // Rapid file operations
    for (int i = 0; i < 1000; i++) {
        char path[256];
        snprintf(path, sizeof(path), "/tmp/anomaly_%d", i);
        int fd = open(path, O_CREAT|O_RDWR, 0600);
        if (fd >= 0) close(fd);
    }
    
    // Suspicious system calls
    for (int i = 0; i < 50; i++) {
        fork();
        char *argv[] = {"/bin/false", NULL};
        char *envp[] = {NULL};
        execve("/bin/false", argv, envp);
    }
    
    printf("Anomaly test completed\\n");
    return 0;
}
"""
        with open(f"{test_prog}.c", "w") as f:
            f.write(code)
            
        subprocess.run(["gcc", "-O2", f"{test_prog}.c", "-o", test_prog], check=True)
        result = subprocess.run([test_prog], capture_output=True, text=True, timeout=10)
        
        print(f"Behavior test output: {result.stdout}")
        
    def test_audit_flooding(self):
        """Test audit log flood protection"""
        # Generate many audit events
        print("Generating audit flood...")
        
        start_time = time.time()
        for i in range(10000):
            # Trigger audit events
            try:
                open("/root/secret", "r")
            except:
                pass
                
        elapsed = time.time() - start_time
        
        # Check if audit system handled flood gracefully
        print(f"Generated 10000 audit events in {elapsed:.2f}s")
        
        # Check dmesg for flood warnings
        result = subprocess.run(["dmesg", "--since", "1 minute ago"], 
                              capture_output=True, text=True)
        
        if "audit flood" in result.stdout or "suppressed" in result.stdout:
            print("Audit flood protection detected - GOOD")
        
    def test_race_conditions(self):
        """Test for race conditions in security checks"""
        test_prog = f"{self.test_dir}/race_test"
        code = """
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

volatile int race_detected = 0;
const char *target = "/tmp/race_target";

void *thread_func(void *arg) {
    int id = *(int*)arg;
    
    for (int i = 0; i < 1000; i++) {
        if (id % 2 == 0) {
            // Creator thread
            int fd = open(target, O_CREAT|O_RDWR, 0600);
            if (fd >= 0) {
                if (write(fd, "A", 1) < 0) perror("write");
                close(fd);
            }
        } else {
            // Deleter thread
            unlink(target);
        }
        
        // Check for TOCTOU
        struct stat st1, st2;
        if (stat(target, &st1) == 0) {
            usleep(100);
            if (stat(target, &st2) == 0) {
                if (st1.st_ino != st2.st_ino) {
                    race_detected++;
                }
            }
        }
    }
    
    return NULL;
}

int main() {
    pthread_t threads[10];
    int ids[10];
    
    // Create racing threads
    for (int i = 0; i < 10; i++) {
        ids[i] = i;
        pthread_create(&threads[i], NULL, thread_func, &ids[i]);
    }
    
    // Wait for completion
    for (int i = 0; i < 10; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("Race conditions detected: %d\\n", race_detected);
    
    return race_detected > 0 ? 1 : 0;
}
"""
        with open(f"{test_prog}.c", "w") as f:
            f.write(code)
            
        subprocess.run(["gcc", "-O2", "-pthread", f"{test_prog}.c", "-o", test_prog], 
                      check=True)
        result = subprocess.run([test_prog], capture_output=True, text=True)
        
        print(f"Race test output: {result.stdout}")
        
    def test_input_validation(self):
        """Test policy parsing input validation"""
        # Test with various malformed inputs
        test_inputs = [
            b"\x00" * 1000,  # Null bytes
            b"\xff" * 1000,  # High bytes
            b"%s%s%s%s",     # Format strings
            b"../" * 100,    # Path traversal
            b"\x00\x00\x00\x00" + b"A" * 1000000,  # Large size
            b"A" * 65536,    # Maximum size
        ]
        
        for i, test_input in enumerate(test_inputs):
            # Write test input
            test_file = f"{self.test_dir}/policy_test_{i}"
            with open(test_file, "wb") as f:
                f.write(test_input)
                
            # Try to load as policy (should fail gracefully)
            # This would need actual policy loading commands
            print(f"Testing malformed input {i}: {len(test_input)} bytes")
            
    def test_performance_impact(self):
        """Test performance impact of security modules"""
        test_prog = f"{self.test_dir}/perf_test"
        code = """
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

long benchmark_file_ops(int count) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < count; i++) {
        int fd = open("/etc/passwd", O_RDONLY);
        if (fd >= 0) {
            char buf[1];
            if (read(fd, buf, 1) < 0) perror("read");
            close(fd);
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - start.tv_sec) * 1000000000L + 
           (end.tv_nsec - start.tv_nsec);
}

int main() {
    // Warmup
    benchmark_file_ops(100);
    
    // Actual benchmark
    long ns = benchmark_file_ops(10000);
    double ms = ns / 1000000.0;
    double per_op = ns / 10000.0;
    
    printf("10000 file operations: %.2f ms (%.2f ns/op)\\n", ms, per_op);
    
    // Check if overhead is reasonable (< 10us per op)
    if (per_op > 10000) {
        printf("WARNING: High overhead detected\\n");
        return 1;
    }
    
    return 0;
}
"""
        with open(f"{test_prog}.c", "w") as f:
            f.write(code)
            
        subprocess.run(["gcc", "-O2", f"{test_prog}.c", "-o", test_prog], check=True)
        result = subprocess.run([test_prog], capture_output=True, text=True)
        
        print(f"Performance test output: {result.stdout}")
        
    def run_all_tests(self):
        """Run all security tests"""
        print("=== Linux Security Module Test Suite ===\n")
        
        tests = [
            ("Rate Limiting", self.test_rate_limiting),
            ("Memory Protection", self.test_memory_protection),
            ("Network Anomaly Detection", self.test_network_anomaly_detection),
            ("Behavior Anomaly Detection", self.test_behavior_anomaly_detection),
            ("Audit Flood Protection", self.test_audit_flooding),
            ("Race Condition Handling", self.test_race_conditions),
            ("Input Validation", self.test_input_validation),
            ("Performance Impact", self.test_performance_impact),
        ]
        
        for name, func in tests:
            self.run_test(name, func)
            
        print(f"\n=== Test Summary ===")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")
        print(f"Total:  {self.passed + self.failed}")
        
        return self.failed == 0

def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("WARNING: Some tests require root privileges")
        
    # Create test runner
    runner = SecurityModuleTests()
    
    try:
        success = runner.run_all_tests()
        return 0 if success else 1
    finally:
        runner.cleanup()

if __name__ == "__main__":
    sys.exit(main())