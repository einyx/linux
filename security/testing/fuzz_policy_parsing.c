// SPDX-License-Identifier: GPL-2.0
/*
 * Fuzzing Harness for Security Policy Parsing
 *
 * Tests policy parsing code in various LSMs for vulnerabilities
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/kernel.h>

/* Mock kernel functions for userspace fuzzing */
#ifndef __KERNEL__
#define kmalloc(size, flags) malloc(size)
#define kfree(ptr) free(ptr)
#define kzalloc(size, flags) calloc(1, size)
#define GFP_KERNEL 0
#define pr_err(...) fprintf(stderr, __VA_ARGS__)
#endif

/* Forward declarations for LSM policy parsing functions */
extern int apparmor_unpack_policy(const uint8_t *data, size_t size);
extern int selinux_parse_policy(const uint8_t *data, size_t size);
extern int hardening_parse_config(const uint8_t *data, size_t size);

/* Fuzzing entry point for libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 4)
		return 0;
		
	/* Test different policy parsers based on first byte */
	switch (data[0] & 0x3) {
	case 0:
		/* Fuzz AppArmor policy unpacking */
		apparmor_fuzz_unpack(data + 1, size - 1);
		break;
	case 1:
		/* Fuzz SELinux policy parsing */
		selinux_fuzz_policy(data + 1, size - 1);
		break;
	case 2:
		/* Fuzz Hardening LSM config */
		hardening_fuzz_config(data + 1, size - 1);
		break;
	case 3:
		/* Fuzz generic policy operations */
		generic_policy_fuzz(data + 1, size - 1);
		break;
	}
	
	return 0;
}

/* AppArmor fuzzing harness */
static void apparmor_fuzz_unpack(const uint8_t *data, size_t size) {
	struct aa_ext {
		void *start;
		void *end;
		void *pos;
		u32 version;
	} e;
	
	/* Initialize ext structure */
	e.start = (void *)data;
	e.end = (void *)(data + size);
	e.pos = e.start;
	e.version = 3; /* Current version */
	
	/* Test various unpack operations */
	
	/* Test string unpacking with various sizes */
	if (size >= 4) {
		uint16_t str_len = *(uint16_t *)data;
		if (str_len < size - 2) {
			/* Simulate string validation */
			for (int i = 0; i < str_len; i++) {
				if (data[2 + i] == '\0' && i < str_len - 1) {
					/* Found null in middle of string */
					return;
				}
			}
		}
	}
	
	/* Test blob unpacking */
	if (size >= 8) {
		uint32_t blob_size = *(uint32_t *)(data + 4);
		if (blob_size > 512 * 1024 * 1024) {
			/* Blob too large */
			return;
		}
	}
	
	/* Test array unpacking */
	if (size >= 6) {
		uint16_t array_size = *(uint16_t *)(data + 2);
		if (array_size > 65535) {
			/* Array too large */
			return;
		}
	}
}

/* SELinux fuzzing harness */
static void selinux_fuzz_policy(const uint8_t *data, size_t size) {
	/* Test policy database parsing */
	if (size < 12)
		return;
		
	/* Magic and version checks */
	uint32_t magic = *(uint32_t *)data;
	uint32_t version = *(uint32_t *)(data + 4);
	uint32_t len = *(uint32_t *)(data + 8);
	
	if (magic != 0xf97cff8c) /* POLICYDB_MAGIC */
		return;
		
	if (version < 15 || version > 33)
		return;
		
	if (len == 0 || len == (uint32_t)-1 || len > size - 12)
		return;
		
	/* Test string parsing */
	const char *str = (const char *)(data + 12);
	size_t max_len = size - 12;
	size_t str_len = strnlen(str, max_len);
	
	if (str_len == max_len) {
		/* Unterminated string */
		return;
	}
	
	/* Test expression parsing with depth limit */
	int depth = 0;
	size_t pos = 12 + str_len + 1;
	
	while (pos < size && depth < 10) {
		uint8_t expr_type = data[pos++];
		
		switch (expr_type) {
		case 1: /* CEXPR_NOT */
			depth++;
			break;
		case 2: /* CEXPR_AND */
		case 3: /* CEXPR_OR */
			depth++;
			if (depth >= 10)
				return;
			break;
		default:
			break;
		}
	}
}

/* Hardening LSM fuzzing harness */
static void hardening_fuzz_config(const uint8_t *data, size_t size) {
	/* Test configuration parsing */
	char *config = malloc(size + 1);
	if (!config)
		return;
		
	memcpy(config, data, size);
	config[size] = '\0';
	
	/* Parse commands */
	char *p = config;
	char *cmd, *arg;
	
	while (p && *p) {
		/* Skip whitespace */
		while (*p && (*p == ' ' || *p == '\t' || *p == '\n'))
			p++;
			
		if (!*p)
			break;
			
		/* Extract command */
		cmd = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
			
		if (*p) {
			*p++ = '\0';
			
			/* Extract argument */
			while (*p && (*p == ' ' || *p == '\t'))
				p++;
				
			arg = p;
			while (*p && *p != '\n')
				p++;
				
			if (*p)
				*p++ = '\0';
		} else {
			arg = NULL;
		}
		
		/* Validate commands */
		if (strlen(cmd) > 32) {
			/* Command too long */
			break;
		}
		
		if (arg && strlen(arg) > 256) {
			/* Argument too long */
			break;
		}
	}
	
	free(config);
}

/* Generic policy operations fuzzing */
static void generic_policy_fuzz(const uint8_t *data, size_t size) {
	/* Test integer overflow scenarios */
	if (size >= 8) {
		uint32_t count = *(uint32_t *)data;
		uint32_t elem_size = *(uint32_t *)(data + 4);
		
		/* Check for multiplication overflow */
		if (count != 0 && elem_size > SIZE_MAX / count) {
			/* Would overflow */
			return;
		}
		
		size_t total = count * elem_size;
		if (total > size - 8) {
			/* Not enough data */
			return;
		}
	}
	
	/* Test path traversal */
	if (size > 0) {
		const char *path = (const char *)data;
		size_t path_len = strnlen(path, size);
		
		if (path_len < size) {
			/* Check for directory traversal */
			if (strstr(path, "../") || strstr(path, "..\\")) {
				/* Path traversal attempt */
				return;
			}
		}
	}
	
	/* Test format string issues */
	if (size >= 2) {
		/* Look for format specifiers */
		for (size_t i = 0; i < size - 1; i++) {
			if (data[i] == '%' && data[i + 1] == 's') {
				/* Potential format string */
				return;
			}
		}
	}
}

/* Initialization for AFL++ */
#ifdef __AFL_COMPILER
__AFL_FUZZ_INIT();

int main() {
	__AFL_INIT();
	
	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
	while (__AFL_LOOP(10000)) {
		int len = __AFL_FUZZ_TESTCASE_LEN;
		LLVMFuzzerTestOneInput(buf, len);
	}
	
	return 0;
}
#endif

/* Standalone test mode */
#ifdef STANDALONE_TEST
int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
		return 1;
	}
	
	FILE *f = fopen(argv[1], "rb");
	if (!f) {
		perror("fopen");
		return 1;
	}
	
	fseek(f, 0, SEEK_END);
	size_t size = ftell(f);
	fseek(f, 0, SEEK_SET);
	
	uint8_t *data = malloc(size);
	if (!data) {
		fclose(f);
		return 1;
	}
	
	if (fread(data, 1, size, f) != size) {
		free(data);
		fclose(f);
		return 1;
	}
	
	fclose(f);
	
	LLVMFuzzerTestOneInput(data, size);
	
	free(data);
	return 0;
}
#endif