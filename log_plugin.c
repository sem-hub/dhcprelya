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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "dhcprelya.h"
#include "dhcp_options.h"

#define BITS8	0
#define BITS32	1

#define SPERW	(7 * 24 * 3600)
#define SPERD	(24 * 3600)
#define SPERH	(3600)
#define SPERM	(60)

static unsigned detailed = 0, print_only_incoming = 0;

int
log_plugin_init(plugin_options_head_t *options_head)
{
	struct plugin_options *opts, *opts_tmp;
	char *p;

	SLIST_FOREACH_SAFE(opts, options_head, next, opts_tmp) {
		if ((p = strchr(opts->option_line, '=')) == NULL) {
			logd(LOG_ERR, "log_plugin: Syntax error at line: %s", opts->option_line);
			return 0;
		}
		*p = '\0';
		p++;
		if (strcasecmp(opts->option_line, "detailed") == 0) {
			if ((detailed = get_bool_value(p)) == -1) {
				logd(LOG_ERR, "log_plugin: Syntax error at line: %s", opts->option_line);
				return 0;
			}
			if (detailed)
				logd(LOG_DEBUG, "log_plugin: Detailed: on");
		} else if (strcasecmp(opts->option_line, "print_only_incoming") == 0) {
			if ((print_only_incoming = get_bool_value(p)) == -1) {
				logd(LOG_ERR, "log_plugin: Syntax error at line: %s", opts->option_line);
				return 0;
			}
			if (print_only_incoming)
				logd(LOG_DEBUG, "log_plugin: Print only incoming: on");
		} else {
			logd(LOG_ERR, "log_plugin: Unknown option at line: %s", opts->option_line);
			return 0;
		}
		free(opts->option_line);
		SLIST_REMOVE(options_head, opts, plugin_options, next);
		free(opts);
	}
	return 1;
}

void
log_plugin_get_time(char *buf)
{
	struct timeval tv;
	struct timezone tz;
	struct tm tm;

	gettimeofday(&tv, &tz);
	localtime_r((const time_t *)&tv.tv_sec, &tm);
	sprintf(buf, "%02d:%02d:%02d.%06lu",
		tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
}

/* print the data as a hex-list, with the translation into ascii behind it */
void
printHexString(uint8_t *data, int len)
{
	int i, j, k;
	char c;

	for (i = 0; i <= len / 8; i++) {
		for (j = 0; j < 8; j++) {
			if (i * 8 + j >= len)
				break;
			printf("%02x", data[i * 8 + j]);
		}
		for (k = j; k < 8; k++)
			printf("  ");
		printf(" ");
		for (j = 0; j < 8; j++) {
			c = data[i * 8 + j];
			if (i * 8 + j >= len)
				break;
			printf("%c", isprint(c) ? c : '.');
		}
		if (i * 8 + j < len)
			printf("\n\t\t\t\t\t    ");
	}
}

/* print the data as a hex-list, without the translation into ascii behind it */
void
printHex(uint8_t *data, int len)
{
	int i, j;

	for (i = 0; i <= len / 8; i++) {
		for (j = 0; j < 8; j++) {
			if (i * 8 + j >= len)
				break;
			printf("%02x", data[i * 8 + j]);
		}
		if (i * 8 + j < len)
			printf("\n\t\t\t\t\t    ");
	}
}

/* print the data as a hex-list seperated by colons */
void
printHexColon(uint8_t *data, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i != 0)
			printf(":");
		printf("%02x", data[i]);
	}
}

void
print_word(uint8_t *data)
{
	printf("%d", (data[0] << 8) + data[1]);
}

/* print the data as a 8 and 32 bits time-value */
void
print_time(uint8_t *data, int bits)
{
	int t;

	if (bits == BITS8)
		t = data[0];
	else
		t = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];

	printf("%d (", t);
	if (t > SPERW) {
		printf("%dw", t / (SPERW));
		t %= SPERW;
	}
	if (t > SPERD) {
		printf("%dd", t / (SPERD));
		t %= SPERD;
	}
	if (t > SPERH) {
		printf("%dh", t / (SPERH));
		t %= SPERH;
	}
	if (t > SPERM) {
		printf("%dm", t / (SPERM));
		t %= SPERM;
	}
	if (t > 0)
		printf("%ds", t);
	printf(")");
}

void
printReqParmList(uint8_t *data, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		printf("%3d (%s)\n", data[i], dhcp_options[data[i]]);
		printf("\t\t\t\t\t    ");
	}
}

void
print_dhcp_packet(struct dhcp_packet *dhcp, int data_len)
{
	char buf[1024];
	uint8_t *data;
	int i, j;

	puts("---------------------------------------------------------------------------");
	printf("op: %d (%s)\n", dhcp->op,
		dhcp->op == 1 ? "BOOTREQUEST" :
				(dhcp->op == 2 ? "BOOTREPLY" : "illegal"));
	printf("htype: %d (%s)\n", dhcp->htype, dhcp->htype == 1 ? "Ethernet" :
									"");
	printf("hlen: %d\n", dhcp->hlen);
	printf("hops: %d\n", dhcp->hops);
	printf("xid: %s\n", print_xid(dhcp->xid, buf));
	printf("secs: %d\n", dhcp->secs);
	printf("flags: 0x%X\n", dhcp->flags);
	printf("ciaddr: %s\n", inet_ntop(AF_INET, &dhcp->ciaddr.s_addr,
					buf, sizeof(buf)));
	printf("yiaddr: %s\n", inet_ntop(AF_INET, &dhcp->yiaddr.s_addr,
					buf, sizeof(buf)));
	printf("siaddr: %s\n", inet_ntop(AF_INET, &dhcp->siaddr.s_addr,
					buf, sizeof(buf)));
	printf("giaddr: %s\n", inet_ntop(AF_INET, &dhcp->giaddr.s_addr,
					buf, sizeof(buf)));
	printf("chaddr: %s\n", ether_ntoa_r((struct ether_addr*)dhcp->chaddr,
						buf));
	printf("sname: %s.\n", dhcp->sname);
	printf("file: %s.\n", dhcp->file);

	data = (uint8_t *)dhcp;
	/* print options */
	j = DHCP_FIXED_NON_UDP;
	/* XXX print cookie */
	j += DHCP_COOKIE_LEN;
	while (j < data_len && data[j] != 255) {
		printf("OPTION: %3d (%3d) %-26s", data[j], data[j + 1],
			dhcp_options[data[j]]);
		switch (data[j]) {
		default:
			printHexString(data + j + 2, data[j + 1]);
			break;
		case 0:	/* padding */
			break;
		case 1:	/* Subnetmask */
		case 3:	/* Routers */
		case 16:	/* Swap server */
		case 28:	/* Broadcast address */
		case 32:	/* Router solicitation */
		case 50:	/* Requested IP address */
		case 54:	/* Server identifier */
			printf("%s", inet_ntop(AF_INET, data + j + 2,
						buf, sizeof(buf)));
			break;

		case 12:	/* Hostname */
		case 14:	/* Merit dump file */
		case 15:	/* Domain name */
		case 17:	/* Root Path */
		case 18:	/* Extensions path */
		case 40:	/* NIS domain */
		case 56:	/* Message */
		case 62:	/* Netware/IP domain name */
		case 64:	/* NIS+ domain */
		case 66:	/* TFTP server name */
		case 67:	/* bootfile name */
		case 60:	/* Vendor class identifier */
		case 86:	/* NDS Tree name */
		case 87:	/* NDS context */
		case 252:	/* MSFT - WinSock Proxy Auto Detect */
			strlcpy(buf, (char *)&data[j + 2], data[j + 1]+1);
			buf[data[j + 1]] = 0;
			printf("%s", buf);
			break;

		case 4:	/* Time servers */
		case 5:	/* Name servers */
		case 6:	/* DNS server */
		case 7:	/* Log server */
		case 8:	/* Cookie server */
		case 9:	/* LPR server */
		case 10:	/* Impress server */
		case 11:	/* Resource location server */
		case 41:	/* NIS servers */
		case 42:	/* NTP servers */
		case 44:	/* NetBIOS name server */
		case 45:	/* NetBIOS datagram distribution server */
		case 48:	/* X Window System font server */
		case 49:	/* X Window System display server */
		case 65:	/* NIS+ servers */
		case 68:	/* Mobile IP home agent */
		case 69:	/* SMTP server */
		case 70:	/* POP3 server */
		case 71:	/* NNTP server */
		case 72:	/* WWW server */
		case 73:	/* Finger server */
		case 74:	/* IRC server */
		case 75:	/* StreetTalk server */
		case 76:	/* StreetTalk directory assistance server */
		case 85:	/* NDS server */
		case 150:	/* CiscoCallManagerTFTP */
			for (i = 0; i < data[j + 1] / 4; i++) {
				if (i != 0)
					printf(",");
				printf("%s", inet_ntop(AF_INET,
					data + j + 2 + i * 4,
					buf, sizeof(buf)));
			}
			break;

		case 21:	/* Policy filter */
			for (i = 0; i < data[j + 1] / 8; i++) {
				if (i != 0)
					printf(",");
				printf("%s/%s",
					inet_ntop(AF_INET,
						data + j + 2 + i * 8,
						buf, sizeof(buf)),
					inet_ntop(AF_INET,
						(data + j + 2 + i * 8) + 4,
						buf+16, sizeof(buf)-16)
				);
			}
			break;

		case 33:	/* Static route */
			for (i = 0; i < data[j + 1] / 8; i++) {
				if (i != 0)
					printf(",");
				printf("%s %s",
					inet_ntop(AF_INET,
						data + j + 2 + i * 8,
						buf, sizeof(buf)),
					inet_ntop(AF_INET,
						(data + j + 2 + i * 8) + 4,
						buf+16, sizeof(buf)-16)
				);
			}
			break;

		case 25:	/* Path MTU plateau table */
			for (i = 0; i < data[j + 1] / 2; i++) {
				if (i != 0)
					printf(",");
				print_word(data + j + 2 + i * 2);
			}
			break;

		case 13:	/* bootfile size */
		case 22:	/* Maximum datagram reassembly size */
		case 26:	/* Interface MTU */
		case 57:	/* Maximum DHCP message size */
			print_word(data + j + 2);
			break;

		case 19:	/* IP forwarding enabled/disable */
		case 20:	/* Non-local source routing */
		case 27:	/* All subnets local */
		case 29:	/* Perform mask discovery */
		case 30:	/* Mask supplier */
		case 31:	/* Perform router discovery */
		case 34:	/* Trailer encapsulation */
		case 39:	/* TCP keepalive garbage */
			printf("%d (%s)", data[j + 2], enabledisable[data[j + 2]]);
			break;

		case 23:	/* Default IP TTL */
			print_time(data + j + 2, BITS8);
			break;

		case 37:	/* TCP default TTL */
			printf("%d", data[j + 2]);
			break;

		case 43:	/* Vendor specific info */
		case 47:	/* NetBIOS scope (no idea how it looks like) */
			printHexString(data + j + 2, data[j + 1]);
			break;

		case 46:	/* NetBIOS over TCP/IP node type */
			printf("%d (%s)",
				data[j + 2], netbios_node_type[data[j + 2]]);
			break;

		case 2:	/* Time offset */
		case 24:	/* Path MTU aging timeout */
		case 35:	/* ARP cache timeout */
		case 38:	/* TCP keepalive interval */
		case 51:	/* IP address leasetime */
		case 58:	/* T1 */
		case 59:	/* T2 */
			print_time(data + j + 2, BITS32);
			break;

		case 36:	/* Ethernet encapsulation */
			printf("%d (%s)",
				data[j + 2],
				data[j + 2] > sizeof(ethernet_encapsulation) ?
				"*wrong value*" :
				ethernet_encapsulation[data[j + 2]]);
			break;

		case 52:	/* Option overload */
			printf("%d (%s)",
				data[j + 2],
				data[j + 2] > sizeof(option_overload) ?
				"*wrong value*" :
				option_overload[data[j + 2]]);
			break;

		case 53:	/* DHCP message type */
			printf("%d (%s)",
				data[j + 2],
				data[j + 2] > sizeof(dhcp_message_types) ?
				"*wrong value*" :
				dhcp_message_types[data[j + 2]]);
			break;

		case 55:	/* Parameter Request List */
			printReqParmList(data + j + 2, data[j + 1]);
			break;

		case 63:	/* Netware/IP domain information */
			printHex(data + j + 2, data[j + 1]);
			break;

		case 61:	/* Client identifier */
			printHexColon(data + j + 2, data[j + 1]);
			break;

		case 81:	/* Client FQDN */
			printf("%d", data[j + 2]);
			printf("-");
			printf("%d", data[j + 3]);
			printf("-");
			printf("%d", data[j + 4]);
			printf(" ");
			strlcpy(buf, (char *)&data[j + 5], data[j + 1] - 2);
			buf[data[j + 1] - 3] = 0;
			printf("%s", buf);
			break;

		case 82:	/* Relay Agent Information */
			for (i = j + 2; i < j + data[j + 1];) {
				printf("\n%-5s subopt: %3d (%3d) %-19s ", " ",
					data[i], data[i + 1],
					data[i] > sizeof(relayagent_suboptions) ?
					"*wrong value*" :
					relayagent_suboptions[data[i]]);
				if (i + data[i + 1] > j + data[j + 1]) {
					printf("*MALFORMED -- TOO LARGE*\n");
					break;
				}
				printHexString(data + i + 2, data[i + 1]);
				i += data[i + 1] + 2;
			}
			break;
		}
		printf("\n");
		if (data[j] == 0)	/* padding */
			j++;
		else
			j += data[j + 1] + 2;
	}
	puts("---------------------------------------------------------------------------\n");
}

int
log_plugin_client_request(const struct interface *intf,
			uint8_t **packet, size_t *psize)
{
	char buf[18 * 2 + 11], timebuf[16], logbuf[256];
	struct dhcp_packet *dhcp;

	if (debug) {
		dhcp = (struct dhcp_packet *)(*packet + ETHER_HDR_LEN + DHCP_UDP_OVERHEAD);
		log_plugin_get_time(timebuf);
		sprintf(logbuf, "%s request on %s XID: %s %s -> %s (%zu bytes)", timebuf,
			intf->name,
			print_xid(dhcp->xid, buf),
			ether_ntoa_r((struct ether_addr*)((struct ether_header *)*packet)->ether_shost, buf+11),
			ether_ntoa_r((struct ether_addr*)((struct ether_header *)*packet)->ether_dhost, buf+29),
			*psize - (ETHER_HDR_LEN + DHCP_UDP_OVERHEAD)
		);
		puts(logbuf);
		if (detailed)
			print_dhcp_packet(dhcp, *psize - (ETHER_HDR_LEN + DHCP_UDP_OVERHEAD));
	}
	return 1;
}

int
log_plugin_send_to_server(const struct sockaddr_in *server,
			uint8_t **packet, size_t *psize)
{
	char buf[16 + 11], timebuf[16], logbuf[256];
	struct dhcp_packet *dhcp;

	if (debug && !print_only_incoming) {
		dhcp = (struct dhcp_packet *)*packet;
		log_plugin_get_time(timebuf);
		sprintf(logbuf, "%s send XID: %s to server %s (%zu bytes)", timebuf,
			print_xid(dhcp->xid, buf),
			inet_ntop(AF_INET, &server->sin_addr.s_addr,
					buf+11, sizeof(buf)-11),
			*psize
		);
		puts(logbuf);
		if (detailed)
			print_dhcp_packet(dhcp, *psize);
	}
	return 1;
}

int
log_plugin_server_answer(const struct sockaddr_in *server, uint8_t **packet,
			 size_t *psize)
{
	char buf[16 + 11], timebuf[16], logbuf[256];
	struct dhcp_packet *dhcp;

	if (debug) {
		dhcp = (struct dhcp_packet *)*packet;
		log_plugin_get_time(timebuf);
		sprintf(logbuf, "%s reply from server (%s) XID: %s (%zu bytes)", timebuf,
			inet_ntop(AF_INET, &server->sin_addr.s_addr,
				buf, sizeof(buf)),
			print_xid(dhcp->xid, buf + 16),
			*psize
		);
		puts(logbuf);
		if (detailed)
			print_dhcp_packet(dhcp, *psize);
	}
	return 1;
}

int
log_plugin_send_to_client(const struct sockaddr_in *server,
			const struct interface *intf, uint8_t **packet,
			size_t *psize)
{
	char buf[11 + 16 + 18], timebuf[16], logbuf[256];
	struct ip *ip;
	struct udphdr *udp;
	struct dhcp_packet *dhcp;

	if (debug && !print_only_incoming) {
		ip = (struct ip *)(*packet + ETHER_HDR_LEN);
		udp = (struct udphdr *)(*packet + ETHER_HDR_LEN + sizeof(struct ip));
		dhcp = (struct dhcp_packet *)(*packet + ETHER_HDR_LEN + DHCP_UDP_OVERHEAD);

		log_plugin_get_time(timebuf);
		sprintf(logbuf, "%s (from %s) send XID: %s for %s via %s (%zu bytes)", timebuf,
			inet_ntop(AF_INET, &server->sin_addr.s_addr,
					buf, sizeof(buf)),
			print_xid(dhcp->xid, buf + 16),
			ether_ntoa_r((struct ether_addr*)dhcp->chaddr, buf+27),
			intf->name, *psize - (ETHER_HDR_LEN + DHCP_UDP_OVERHEAD)
		);
		puts(logbuf);
		if (detailed)
			print_dhcp_packet(dhcp,
				*psize - (ETHER_HDR_LEN + DHCP_UDP_OVERHEAD));
	}
	return 1;
}

struct plugin_data log_plugin = {
	"log",
	log_plugin_init,
	NULL,			/* no destroy() function */
	log_plugin_client_request,
	log_plugin_send_to_server,
	log_plugin_server_answer,
	log_plugin_send_to_client
};
