# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_SECURITY_HARDENING) += hardening.o

# Core files
hardening-y := hardening_lsm.o hardening_fs.o

# Feature implementations
hardening-$(CONFIG_SECURITY_HARDENING_TEMPORAL) += temporal.o
hardening-$(CONFIG_SECURITY_HARDENING_BEHAVIOR) += behavior.o
hardening-$(CONFIG_SECURITY_HARDENING_RESOURCES) += resources.o
hardening-$(CONFIG_SECURITY_HARDENING_ADAPTIVE) += adaptive.o
hardening-$(CONFIG_SECURITY_HARDENING_LINEAGE) += lineage.o
hardening-$(CONFIG_SECURITY_HARDENING_CONTAINER) += container.o
hardening-$(CONFIG_SECURITY_HARDENING_NETWORK) += network.o
hardening-$(CONFIG_SECURITY_HARDENING_MEMORY) += memory.o
hardening-$(CONFIG_SECURITY_HARDENING_ENTROPY) += entropy.o
hardening-$(CONFIG_SECURITY_HARDENING_SYSCALL_FILTER) += syscall_filter.o

# Additional features
hardening-$(CONFIG_SECURITY_HARDENING_PROFILES) += profiles.o
hardening-$(CONFIG_SECURITY_HARDENING_CRYPTO) += crypto.o
hardening-$(CONFIG_SECURITY_HARDENING_STATS) += stats.o