/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Network Behavior Profiling for Security Hardening Module
 *
 * Monitors and analyzes network access patterns
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/percpu.h>
#include <net/sock.h>
#include "hardening.h"

/* Per-CPU network statistics for performance */
struct hardening_net_stats {
	u64 connections;
	u64 bytes_sent;
	u64 bytes_received;
	u64 packets;
};

static DEFINE_PER_CPU(struct hardening_net_stats, hardening_pcpu_net_stats);

/* Network anomaly thresholds */
#define MAX_CONNECTIONS_PER_MINUTE	100
#define MAX_UNIQUE_DESTINATIONS		50
#define PORT_SCAN_THRESHOLD		20
#define PORT_SCAN_WARNING_SCORE		5
#define ANOMALY_SCORE_THRESHOLD		50
#define CONNECTION_LOG_INTERVAL		0xFF	/* Log every 256 connections */
#define MAX_PORT_NUMBER			65535
#define MAX_FAILED_CONNECTIONS		10

/* Common server ports that shouldn't be accessed by clients */
static const u16 server_ports[] = {
	22,	/* SSH */
	23,	/* Telnet */
	25,	/* SMTP */
	110,	/* POP3 */
	143,	/* IMAP */
	445,	/* SMB */
	3389,	/* RDP */
	5432,	/* PostgreSQL */
	3306,	/* MySQL */
	6379,	/* Redis */
	27017,	/* MongoDB */
};

/* Initialize network behavior profile */
int hardening_init_network_profile(struct hardening_task_ctx *ctx)
{
	struct hardening_network_profile *network;
	
	network = kzalloc(sizeof(*network), GFP_KERNEL);
	if (!network)
		return -ENOMEM;
		
	/* Initialize port bitmap */
	bitmap_zero(network->used_ports, 65536);
	
	network->last_activity = ktime_get_ns();
	ctx->network = network;
	
	return 0;
}

/* Update network activity profile */
int hardening_update_network_activity(struct hardening_task_ctx *ctx,
				     int sock_type, int result)
{
	struct hardening_network_profile *network;
	u64 now;
	
	if (!ctx || !ctx->network)
		return 0;
		
	network = ctx->network;
	now = ktime_get_ns();
	
	/* Update connection statistics using per-CPU counters */
	if (sock_type == SOCK_STREAM || sock_type == SOCK_DGRAM) {
		struct hardening_net_stats *stats;
		
		/* Use per-CPU counter for performance */
		stats = this_cpu_ptr(&hardening_pcpu_net_stats);
		stats->connections++;
		
		/* Periodically sync to main counter */
		if ((stats->connections & CONNECTION_LOG_INTERVAL) == 0) {
			network->total_connections += 256;
		}
		
		if (result < 0)
			network->failed_connections++;
	}
	
	/* Check connection rate */
	if (now - network->last_activity < NSEC_PER_SEC) {
		/* Multiple connections within 1 second */
		network->packet_rate++;
	} else {
		network->packet_rate = 1;
	}
	
	network->last_activity = now;
	
	/* Detect anomalies */
	return hardening_check_network_anomaly(ctx);
}

/* Track port usage */
static void track_port_usage(struct hardening_network_profile *network,
			     u16 port, bool is_connect)
{
	if (port == 0 || port > MAX_PORT_NUMBER)
		return;
		
	/* Mark port as used */
	if (!test_and_set_bit(port, network->used_ports)) {
		/* First time using this port */
		if (is_connect) {
			/* Check for port scanning behavior */
			u32 unique_ports = bitmap_weight(network->used_ports, 65536);
			if (unique_ports > PORT_SCAN_THRESHOLD) {
				network->port_scan_score++;
			}
		}
	}
	
	/* Check for suspicious server port access */
	if (is_connect) {
		int i;
		for (i = 0; i < ARRAY_SIZE(server_ports); i++) {
			if (port == server_ports[i]) {
				network->network_anomaly_score += 5;
				break;
			}
		}
	}
}

/* Check for network anomalies */
int hardening_check_network_anomaly(struct hardening_task_ctx *ctx)
{
	struct hardening_network_profile *network;
	u32 anomaly_score = 0;
	
	if (!ctx || !ctx->network)
		return 0;
		
	network = ctx->network;
	
	/* Check connection rate */
	if (network->packet_rate > MAX_CONNECTIONS_PER_MINUTE) {
		anomaly_score += 20;
		pr_notice("hardening: high connection rate detected (%u/min)\n",
			  network->packet_rate);
	}
	
	/* Check failed connections */
	if (network->failed_connections > MAX_FAILED_CONNECTIONS) {
		anomaly_score += 15;
		pr_notice("hardening: excessive failed connections (%u)\n",
			  network->failed_connections);
	}
	
	/* Check port scanning */
	if (network->port_scan_score > PORT_SCAN_WARNING_SCORE) {
		anomaly_score += 30;
		pr_notice("hardening: port scanning behavior detected\n");
	}
	
	/* Check unique destinations */
	if (network->unique_destinations > MAX_UNIQUE_DESTINATIONS) {
		anomaly_score += 10;
	}
	
	/* Update total anomaly score */
	network->network_anomaly_score = anomaly_score;
	
	/* Escalate security if needed */
	if (anomaly_score > ANOMALY_SCORE_THRESHOLD && hardening_enforce) {
		hardening_escalate_security(ctx);
		atomic64_inc(&hardening_global_stats.network_anomalies);
		return -EACCES;
	}
	
	return 0;
}

/* Socket operation hooks */
int hardening_socket_create(int family, int type, int protocol)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;
	
	cred = current_cred();
	ctx = cred->security;
	if (!ctx || !ctx->network)
		return 0;
		
	/* Track socket creation */
	return hardening_update_network_activity(ctx, type, 0);
}

int hardening_socket_connect(struct socket *sock,
			     struct sockaddr *address, int addrlen)
{
	struct hardening_task_ctx *ctx;
	const struct cred *cred;
	u16 port = 0;
	
	cred = current_cred();
	ctx = cred->security;
	if (!ctx || !ctx->network)
		return 0;
		
	/* Extract port from address */
	if (address->sa_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in *)address;
		port = ntohs(addr->sin_port);
	} else if (address->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
		port = ntohs(addr6->sin6_port);
	}
	
	/* Track port usage */
	if (port > 0 && ctx->network) {
		track_port_usage(ctx->network, port, true);
		ctx->network->unique_destinations++;
	}
	
	return hardening_update_network_activity(ctx, sock->type, 0);
}

/* Free network profile */
void hardening_free_network_profile(struct hardening_network_profile *network)
{
	kfree(network);
}