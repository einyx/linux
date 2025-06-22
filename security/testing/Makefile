# SPDX-License-Identifier: GPL-2.0
# Makefile for security module testing

CC = gcc
CFLAGS = -O2 -Wall -Wextra -fsanitize=address -fsanitize=undefined
LDFLAGS = -pthread

# Fuzzing configuration
FUZZ_CC = clang
FUZZ_FLAGS = -g -O1 -fsanitize=fuzzer,address

# Test programs
TEST_PROGS = test_rate_limit test_memory test_network test_behavior test_race

# Fuzzing targets
FUZZ_TARGETS = fuzz_policy_parsing fuzz_apparmor fuzz_selinux fuzz_hardening

all: tests fuzzers

tests: $(TEST_PROGS)

fuzzers: $(FUZZ_TARGETS)

# Build test programs
test_rate_limit: test_rate_limit.c
	$(CC) $(CFLAGS) -o $@ $<

test_memory: test_memory.c
	$(CC) $(CFLAGS) -o $@ $<

test_network: test_network.c
	$(CC) $(CFLAGS) -o $@ $<

test_behavior: test_behavior.c
	$(CC) $(CFLAGS) -o $@ $<

test_race: test_race.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

# Build fuzzers
fuzz_policy_parsing: fuzz_policy_parsing.c
	$(FUZZ_CC) $(FUZZ_FLAGS) -o $@ $<

fuzz_apparmor: fuzz_apparmor.c
	$(FUZZ_CC) $(FUZZ_FLAGS) -I../../apparmor/include -o $@ $<

fuzz_selinux: fuzz_selinux.c
	$(FUZZ_CC) $(FUZZ_FLAGS) -I../../selinux/include -o $@ $<

fuzz_hardening: fuzz_hardening.c
	$(FUZZ_CC) $(FUZZ_FLAGS) -I../../hardening -o $@ $<

# Run tests
run-tests: tests
	@echo "Running security module tests..."
	@python3 test_security_modules.py

# Run fuzzers
run-fuzz: fuzzers
	@echo "Running fuzzers..."
	@mkdir -p corpus
	@for target in $(FUZZ_TARGETS); do \
		echo "Fuzzing $$target..."; \
		timeout 60s ./$$target -max_total_time=60 corpus/$$target; \
	done

# Coverage testing
coverage:
	@echo "Running coverage tests..."
	$(CC) $(CFLAGS) --coverage -o test_coverage test_*.c
	./test_coverage
	gcov test_coverage
	lcov --capture --directory . --output-file coverage.info
	genhtml coverage.info --output-directory coverage_html

# Static analysis
static-analysis:
	@echo "Running static analysis..."
	cppcheck --enable=all --suppress=missingIncludeSystem .
	scan-build make tests

# Memory leak testing
valgrind: tests
	@echo "Running memory leak tests..."
	@for prog in $(TEST_PROGS); do \
		echo "Testing $$prog..."; \
		valgrind --leak-check=full --show-leak-kinds=all ./$$prog; \
	done

# Kernel module testing framework
kunit-tests:
	@echo "Building KUnit tests..."
	$(MAKE) -C ../.. M=security/testing CONFIG_KUNIT=y

# Integration tests
integration-tests:
	@echo "Running integration tests..."
	@./run_integration_tests.sh

# Stress testing
stress-test: tests
	@echo "Running stress tests..."
	@for i in {1..10}; do \
		echo "Iteration $$i..."; \
		./test_rate_limit & \
		./test_memory & \
		./test_network & \
		wait; \
	done

# Regression tests
regression-tests:
	@echo "Running regression tests..."
	@python3 regression_tests.py

# Performance benchmarks
benchmarks: tests
	@echo "Running performance benchmarks..."
	@./test_performance
	@python3 plot_benchmarks.py

clean:
	rm -f $(TEST_PROGS) $(FUZZ_TARGETS)
	rm -f *.o *.gcda *.gcno *.gcov
	rm -rf corpus coverage_html
	rm -f coverage.info

.PHONY: all tests fuzzers run-tests run-fuzz coverage static-analysis \
        valgrind kunit-tests integration-tests stress-test \
        regression-tests benchmarks clean