/* Copyright (c) 2007-2017 Sergey Matveychuk Yandex, LLC.  All rights
 * reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. 2.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. 4. Neither the name
 * of the company nor the names of its contributors may be used to endorse or
 * promote products derived from this software without specific prior written
 * permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. */

#ifndef _DHCP_H
#define _DHCP_H
#include <time.h>
#include <sys/types.h>
#include <sys/mac.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <libutil.h>
#include <syslog.h>

#define	IF_MAX		100	/* Max interfaces supported */
#define	SERVERS_MAX	64	/* Max servers supported */

/* Error codes */
#define	EX_OK		0
#define EX_MEM		16
#define EX_RES		32
#define EX_USAGE	64
#define EX_NOHOST	68
#define EX_UNAVAILABLE	69

#define INTF_NAME_LEN	16
#define ETH_ADDR_LEN	6

#define DHCP_UDP_OVERHEAD	(20 +	/* IP header */	\
				 8)	/* UDP header */
#define DHCP_SNAME_LEN		64
#define DHCP_FILE_LEN		128
#define DHCP_FIXED_NON_UDP	236
#define DHCP_FIXED_LEN		(DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
/* Everything but options. */
#define DHCP_MTU_MAX		1500
#define DHCP_MIN_SIZE		300
#define DHCP_OPTION_LEN		(DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_COOKIE_LEN		4

/* BOOTP (rfc951) message types */
#define BOOTREQUEST	1
#define BOOTREPLY	2

#pragma pack(push, 1)
struct packet_headers {
	struct ether_header eh;
	struct ip ip;
	struct udphdr udp;
};

struct dhcp_packet {
	uint8_t op;		/* 0: Message opcode/type */
	uint8_t htype;		/* 1: Hardware addr type (net/if_types.h) */
	uint8_t hlen;		/* 2: Hardware addr length */
	uint8_t hops;		/* 3: Number of relay agent hops from client */
	uint32_t xid;		/* 4: Transaction ID */
	uint16_t secs;		/* 8: Seconds since client started looking */
	uint16_t flags;		/* 10: Flag bits */
	struct in_addr ciaddr;	/* 12: Client IP address (if already in use) */
	struct in_addr yiaddr;	/* 16: Client IP address */
	struct in_addr siaddr;	/* 20: IP address of next server to talk to */
	struct in_addr giaddr;	/* 24: DHCP relay agent IP address */
	unsigned char chaddr[16];	/* 28: Client hardware address */
	char sname[DHCP_SNAME_LEN];	/* 44: Server name */
	char file[DHCP_FILE_LEN];	/* 108: Boot filename */
	unsigned char options[DHCP_OPTION_LEN];
	/* 236: Optional parameters (actual length dependent on MTU). */
};
#pragma pack(pop)

typedef in_addr_t ip_addr_t;

struct interface {
	int idx;
	int fd;
	char name[INTF_NAME_LEN];
	ip_addr_t ip;
	uint8_t mac[6];
	int bpf;
	pcap_t *cap;
	int srv_num;
	int *srvrs;
};

struct dhcp_server {
	char *name;
	struct sockaddr_in sockaddr;
};

struct queue {
	struct dhcp_packet dhcp;
	int if_idx;
	ip_addr_t ip_dst;

	STAILQ_ENTRY(queue) entries;
};

struct ip_binding_map {
	char *iname;
	ip_addr_t ip;
	STAILQ_ENTRY(ip_binding_map) next;
};

/* Global options */
extern unsigned debug, max_packet_size;

struct interface *get_interface_by_idx(int idx);
struct interface *get_interface_by_name(char *iname);

/* ip_checksum.c */
short ip_checksum(const char *packet, int count);
short udp_checksum(const char *packet);

/* utils.c */
char *print_xid(uint32_t ip, char *buf);
void logd(int log_level, char *fmt,...);
int get_bool_value(const char *str);

/* net_utils.c */
int get_mac(const char *if_name, char *if_mac);
int get_ip(const char *iname, ip_addr_t *ip, const ip_addr_t *preferable);

/* dhcp_utils.c */
#define INSERT_OPTION_NORMAL 0		// No replace, no stack
#define INSERT_OPTION_OVERRIDE 1	// If duplicate found - override
#define INSERT_OPTION_STACK 2		// No search for duplicate, just insert

uint8_t *find_option(struct dhcp_packet *dhcp, uint8_t option_id);
uint8_t *find_suboption(struct dhcp_packet *dhcp, uint8_t option_id, uint8_t suboption_id);
int insert_option(struct dhcp_packet *dhcp, uint8_t option_id, uint8_t len, uint8_t *option, int flags);
int remove_option(struct dhcp_packet *dhcp, uint8_t option_id);
int get_dhcp_len(struct dhcp_packet *dhcp);

/* Plugins support */
#define MAX_PLUGINS 20
#define PLUGIN_PATH "/usr/local/lib/"

struct plugin_options {
	char *option_line;
	SLIST_ENTRY(plugin_options) next;
};
typedef SLIST_HEAD(opt_head, plugin_options) plugin_options_head_t;

struct plugin_data {
	char *name;
	int (*init) (plugin_options_head_t *poptions);
	void (*destroy) ();
	/* packet buffer could be reallocated in functions bellow */
	int (*client_request) (const struct interface *intf,
				struct dhcp_packet *dhcp, struct packet_headers *headers);
	int (*send_to_server) (const struct sockaddr_in *server,
				const struct interface *input_intf, struct dhcp_packet *dhcp);
	int (*server_answer) (const struct sockaddr_in *server,
				struct dhcp_packet *dhcp);
	int (*send_to_client) (const struct sockaddr_in *server,
				const struct interface *intf,
				struct dhcp_packet *dhcp, struct packet_headers *headers);
};

#endif
