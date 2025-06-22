# Kernel Testing Guide

This directory contains test scripts for the Kain kernel.

## Quick Start

```bash
# Quick sanity check (< 1 minute)
./quick-test.sh

# Run all automated tests
./run-all-tests.sh

# Full VM boot test
./test-in-vm.sh

# Test with debugging
./test-in-vm.sh --debug --run-tests
```

## Available Tests

### quick-test.sh
Fast sanity checks without building:
- Configuration test
- Dependency check
- Syntax validation
- Checkpatch on recent commits

**Runtime**: ~30 seconds

### test-in-vm.sh
Complete kernel build and boot test:
- Builds kernel with test config
- Creates minimal initramfs
- Boots in QEMU
- Runs basic functionality tests

**Options**:
- `--skip-build`: Use existing kernel build
- `--skip-boot`: Only build, don't boot
- `--run-tests`: Run tests inside VM
- `--debug`: Enable debug output

**Runtime**: 5-10 minutes

### run-all-tests.sh
Comprehensive test suite:
- Environment validation
- Static analysis
- Build tests
- Security checks
- GitHub Actions validation

**Options**:
- `--with-vm`: Include VM boot test

**Runtime**: 2-15 minutes

### test-github-actions.sh
Test GitHub Actions workflows locally:
```bash
# Test specific workflow
./test-github-actions.sh package

# Test all workflows
./test-github-actions.sh all
```

**Requirements**: Docker, act

## CI/CD Testing

Before pushing changes:

1. **Minimal testing**:
   ```bash
   ./quick-test.sh
   ```

2. **Standard testing**:
   ```bash
   ./run-all-tests.sh
   ./test-in-vm.sh --skip-build
   ```

3. **Full testing**:
   ```bash
   ./run-all-tests.sh --with-vm
   ./test-github-actions.sh all
   ```

## Writing New Tests

Add tests to `run-all-tests.sh`:

```bash
run_test "Test name" "command to run"
```

For VM tests, modify the init script in `test-in-vm.sh`.

## Troubleshooting

**Build fails**: Check dependencies with `./quick-test.sh`

**VM won't boot**: 
- Ensure KVM is available: `ls -l /dev/kvm`
- Check QEMU installation: `qemu-system-x86_64 --version`
- Try without KVM: Remove `-enable-kvm` from test script

**Tests timeout**: Increase `TEST_TIMEOUT` in `test-in-vm.sh`

**GitHub Actions fail**: 
- Check workflow syntax
- Verify all dependencies are installed
- Some features require actual GitHub environment

## Performance Testing

For performance regression testing:

```bash
# Build with performance counters
./scripts/config --enable CONFIG_PERF_EVENTS
make olddefconfig

# Run perf tests
perf stat make -j$(nproc)
```

## Security Testing

Additional security-specific tests:

```bash
# Check hardening options
./scripts/kconfig-hardened-check -c .config

# Run syzkaller locally (advanced)
# See .github/workflows/fuzzing.yml for setup
```