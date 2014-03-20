/* Copyright (c) 2007-2012 Sergey Matveychuk Yandex, LLC.  All rights
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
#include <strings.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <pcap.h>
#include <time.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/queue.h>

#include "dhcprelya.h"

#define VERSION "4.8"

/* options */
/* globals (can check in modules) */
unsigned debug = 0, max_packet_size = 1400;;
/* local */
static unsigned max_hops = 4;
static char plugin_base[80];

uint8_t plugins_number = 0;
struct plugin_data *plugins[MAX_PLUGINS];

struct pidfh *pfh = NULL;
int bootps_port, bootpc_port;
struct interface *ifs[IF_MAX];
struct dhcp_server *servers[SERVERS_MAX];
int if_num = 0;			/* interfaces number */
int srv_num = 0;		/* servers number */
unsigned int queue_size = 0, rps_limit = 0;
pthread_mutex_t queue_lock;
plugin_options_head_t *options_heads[MAX_PLUGINS];

#define DeltaUSec(finish,start) \
 (long)( ((long)(finish.tv_sec - start.tv_sec)<<10) + (long)(finish.tv_nsec>>20) - (long)(start.tv_nsec>>20) )

void
usage(char *prgname)
{
	fprintf(stderr, "DHCP relay. Yandex edition. 2007-2012.\n");
	fprintf(stderr, "Version %s.\n", VERSION);
	fprintf(stderr, "Usage:\n%s [-d] [-p<pidfile>] -f <config_file>\n", prgname);
	fprintf(stderr, "or ISC compatible mode:\n%s [-d] [-p<pidfile>] -A <packet_size> -c <max_hops> -i <ifname>... <dhcp_server>...\n", prgname);
	exit(EX_OK);
}

void
process_error(int ret_code, char *fmt,...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, fmt);

	if (pfh)
		pidfile_remove(pfh);

	vsprintf(buf, fmt, ap);
	logd(LOG_ERR, buf);
	errx(ret_code, buf);

	/* does not reach */
	va_end(ap);
}

int
find_interface(ip_addr_t addr)
{
	int i;

	for (i = 0; i < if_num; i++) {
		if (addr == ifs[i]->ip)
			break;
	}

	return i;
}

int
open_interface(char *iname)
{
	int i, j, x = 1;
	struct ifreq ifr;
	struct bpf_program fp;
	struct sockaddr_in baddr;
	char errbuf[PCAP_ERRBUF_SIZE], file[32], buf[256];

	if (if_num >= IF_MAX - 1)
		process_error(EX_RES, "too many interfaces");

	logd(LOG_DEBUG, "Trying to open interface: %s", iname);

	/* If we already have the interface, bind to the current server then */
	for (i = 0; i < if_num; i++) {
		if (strcmp(ifs[i]->name, iname) == 0) {
			/* If the interface is already binded to this server
			 * (appears twice). Ignore it. */
			if (ifs[i]->srv_num != srv_num) {
				ifs[i]->srv_num++;
				ifs[i]->srvrs = realloc(ifs[i]->srvrs, ifs[i]->srv_num * sizeof(int));
				ifs[i]->srvrs[ifs[i]->srv_num - 1] = srv_num - 1;
			}
			return 1;
		}
	}

	ifs[if_num] = malloc(sizeof(struct interface));
	if (ifs[if_num] == NULL)
		process_error(EX_MEM, "malloc");

	ifs[if_num]->idx = if_num;
	strlcpy(ifs[if_num]->name, iname, INTF_NAME_LEN);

	if (!get_mac(iname, (char *)ifs[if_num]->mac) ||
	    !get_ip(iname, &ifs[if_num]->ip, &ifs[if_num]->mask)) {
		free(ifs[if_num]);
		return 0;
	}
	ifs[i]->srv_num = 1;
	ifs[i]->srvrs = malloc(ifs[i]->srv_num * sizeof(int));
	if (ifs[i]->srvrs == NULL)
		process_error(EX_MEM, "malloc");
	ifs[i]->srvrs[0] = srv_num - 1;

	/* Looking for a free BPF device and open it */
	for (j = 0; j < 255; j++) {
		snprintf(file, sizeof(file), "/dev/bpf%d", j);
		ifs[if_num]->bpf = open(file, O_WRONLY);
		if (ifs[if_num]->bpf != -1 || errno != EBUSY)
			break;
	}
	/* Bind BPF to an interface */
	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, iname, sizeof(ifr.ifr_name));
	if (ioctl(ifs[if_num]->bpf, BIOCSETIF, (char *)&ifr) < 0)
		process_error(EX_RES, "Can't BIOCSETIF");

	if ((ifs[if_num]->cap = pcap_open_live(iname, max_packet_size, 0, 100, errbuf)) == NULL)
		process_error(EX_RES, "pcap_open_live(%s): %s", iname, errbuf);
	if (pcap_compile(ifs[if_num]->cap, &fp, "udp and dst port bootps", 0, 0) < 0)
		process_error(EX_RES, "pcap_compile");
	if (pcap_setfilter(ifs[if_num]->cap, &fp) < 0)
		process_error(EX_RES, "pcap_setfilter");

	if ((ifs[if_num]->fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		process_error(EX_RES, "socket for listener at %s: %s", iname, strerror(errno));

	if (setsockopt(ifs[if_num]->fd, SOL_SOCKET, SO_BROADCAST, (char *)&x, sizeof(x)) < 0)
		process_error(EX_RES, "setsockopt: SO_BROADCAST");
	if (setsockopt(ifs[if_num]->fd, SOL_SOCKET, SO_REUSEADDR, (char *)&x, sizeof(x)) < 0)
		process_error(EX_RES, "setsockopt: SO_REUSEADDR");

	bzero(&baddr, sizeof(baddr));
	baddr.sin_family = AF_INET;
	baddr.sin_port = bootps_port;
	memcpy(&baddr.sin_addr.s_addr, &ifs[if_num]->ip, sizeof(ip_addr_t));
	if (bind(ifs[if_num]->fd, (struct sockaddr *)&baddr, sizeof(baddr)) < 0)
		process_error(EX_RES, "bind: %s", strerror(errno));

	logd(LOG_WARNING, "Listen at %s: %s/%s, %s", iname, print_ip(ifs[if_num]->ip, buf),
	     print_ip(ifs[if_num]->mask, buf + 16), print_mac(ifs[if_num]->mac, buf + 32));

	if_num++;
	return 1;
}

int
open_server(char *server_spec)
{
	struct hostent *hostent;
	char buf[16], *p;
	int port = bootps_port;
	char *name = strdup(server_spec);

	if (name == NULL)
		process_error(EX_MEM, "malloc");

	if (srv_num >= SERVERS_MAX - 1)
		process_error(EX_RES, "too many servers");

	logd(LOG_DEBUG, "Open server: %s", name);

	if ((p = strchr(name, ':')) != NULL) {
		*p = '\0';
		port = htons(atoi(p + 1));
		if (port == 0)
			process_error(EX_USAGE, "bad port number");
	}
	if ((hostent = gethostbyname(name)) == NULL) {
		free(name);
		return 0;
	}
	servers[srv_num] = malloc(sizeof(struct dhcp_server));
	if (servers[srv_num] == NULL)
		process_error(EX_MEM, "malloc");

	servers[srv_num]->name = malloc(strlen(name));
	if (servers[srv_num]->name == NULL)
		process_error(EX_MEM, "malloc");
	strlcpy(servers[srv_num]->name, name, sizeof(servers[srv_num]->name));

	bzero(&servers[srv_num]->sockaddr, sizeof(struct sockaddr_in));
	servers[srv_num]->sockaddr.sin_family = AF_INET;
	servers[srv_num]->sockaddr.sin_port = port;
	memcpy(&(servers[srv_num]->sockaddr.sin_addr.s_addr), hostent->h_addr, hostent->h_length);

	srv_num++;

	logd(LOG_WARNING, "DHCP server #%d: %s (%s)", srv_num, name,
	     print_ip(servers[srv_num - 1]->sockaddr.sin_addr.s_addr, buf));

	free(name);
	return 1;
}

int
sanity_check(const char *packet, unsigned len)
{
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;

	eh = (struct ether_header *)packet;
	ip = (struct ip *)(packet + ETHER_HDR_LEN);
	udp = (struct udphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip));

	if (len < ETHER_HDR_LEN + DHCP_FIXED_LEN) {
		logd(LOG_ERR, "length too little -- packet discarded");
		return 0;
	}
	if (ntohs(eh->ether_type) != ETHERTYPE_IP) {
		logd(LOG_ERR, "wrong ether type -- packet discarded");
		return 0;
	}
	if (udp->uh_ulen < DHCP_FIXED_NON_UDP + DHCP_COOKIE_LEN + 1) {
		logd(LOG_ERR, "not enough DHCP data -- packet ignore");
		return 0;
	}
	return 1;
}

/* Listen an interface for a DHCP packet (from client) and store it in a
 * queue */
void *
listener(void *param)
{
	int i, n, ignore = 0, packet_count = 0;
	size_t len;
	struct interface *intf = param;
	struct pcap_pkthdr *header;
	const u_char *packet;
	uint8_t *p, *p1;
	struct queue *q;
	struct timespec tv, last_count_reset_tv = {0, 0};

	while (1) {
		if ((n = pcap_next_ex(intf->cap, &header, &packet)) > 0) {
			/* Drop a packet we got too quickly if we have a RPS
			 * limit */
			if (rps_limit && packet_count++ > rps_limit) {
				clock_gettime(CLOCK_MONOTONIC_FAST, &tv);
				if (DeltaUSec(tv, last_count_reset_tv) < 1000000) {
					logd(LOG_WARNING, "The packet droped due to RPS limit");
					continue;
				} else {
					memcpy(&last_count_reset_tv, &tv, sizeof(struct timeval));
					packet_count = 0;
				}
			}
			/* Discard BOOTREPLY from client */
			if (((struct dhcp_packet *)(packet + ETHER_HDR_LEN + DHCP_UDP_OVERHEAD))->op == BOOTREPLY)
				continue;

			if (!sanity_check((char *)packet, header->caplen))
				continue;

			len = header->caplen;
			p = malloc(len);
			if (p == NULL) {
				logd(LOG_ERR, "malloc error");
				continue;
			}
			memcpy(p, packet, len);

			/* If a plugin returns 0, ignore the packet */
			for (i = 0; i < plugins_number; i++) {
				if (plugins[i]->client_request)
					if (plugins[i]->client_request(intf, &p, &len) == 0) {
						logd(LOG_WARNING, "The packet rejected by %s plugin", plugins[i]->name);
						ignore = 1;
						break;
					}
			}
			if (ignore) {
				free(p);
				continue;
			}
			/* We need no headers anymore, store the packet
			 * without them */
			p1 = malloc(len - (ETHER_HDR_LEN + DHCP_UDP_OVERHEAD));
			if (p1 == NULL) {
				logd(LOG_ERR, "malloc error");
				free(p);
				continue;
			}
			len -= ETHER_HDR_LEN + DHCP_UDP_OVERHEAD;
			memcpy(p1, p + ETHER_HDR_LEN + DHCP_UDP_OVERHEAD, len);
			/* We'll free *p after saving ip_dist */

			q = malloc(sizeof(struct queue));
			if (p1 == NULL) {
				logd(LOG_ERR, "malloc error");
				free(p);
				free(p1);
				continue;
			}
			q->packet = p1;
			q->len = len;
			q->if_idx = intf->idx;
			q->ip_dst = ((struct ip *)(p + ETHER_HDR_LEN))->ip_dst.s_addr;
			/* We don't need *p anymore */
			free(p);

			pthread_mutex_lock(&queue_lock);
			STAILQ_INSERT_TAIL(&q_head, q, entries);
			queue_size++;
			pthread_mutex_unlock(&queue_lock);
		} else {
			/* Sleep if an error. It prevent us from 100% CPU
			 * load if there is an interface problem. */
			usleep(1000);
		}
	}
}

/* Only one packet from server is processed at once
 * 
 */
void
process_server_answer()
{
	struct sockaddr_in from_addr;
	struct dhcp_packet *dhcp = NULL;
	struct ether_header *eh;
	struct ip *ip;
	struct udphdr *udp;
	struct timeval timeout;
	uint8_t *buf = NULL, *packet = NULL;
	char pbuf[11 + 16 + 19];
	socklen_t from_len = sizeof(from_addr);
	int i, j, fdmax = 0, ignore, if_idx;
	size_t len, psize = 0;
	fd_set fds;

	FD_ZERO(&fds);
	for (i = 0; i < if_num; i++) {
		FD_SET(ifs[i]->fd, &fds);
		if (fdmax < ifs[i]->fd)
			fdmax = ifs[i]->fd;
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = 10;
	if (select(fdmax + 1, &fds, NULL, NULL, &timeout)) {
		for (i = 0; i < if_num; i++)
			if (FD_ISSET(ifs[i]->fd, &fds)) {
				bzero(&from_addr, sizeof(from_addr));
				/* from_addr.sin_family=AF_INET;
				 * from_addr.sin_port = bootps_port; */
				from_len = sizeof(from_addr);

				buf = malloc(max_packet_size);
				if (buf == NULL) {
					logd(LOG_ERR, "malloc error");
					return;
				}
				psize = recvfrom(ifs[i]->fd, buf, max_packet_size, 0,
				  (struct sockaddr *)&from_addr, &from_len);
				/* XXX a sanity check? */
				/* If a plugin returns 0, stop processing and
				 * do not send the packet */
				ignore = 0;
				for (j = 0; j < plugins_number; j++) {
					if (plugins[j]->server_answer)
						if (plugins[j]->server_answer(&from_addr, &buf, &psize) == 0) {
							logd(LOG_WARNING, "The packet rejected by %s plugin",
							  plugins[j]->name);
							ignore = 1;
							break;
						}
				}

				if (ignore) {
					free(buf);
					return;
				}
				/* Only one packet! */
				break;
			}
	} else {
		/* No packets from servers */
		return;
	}

	dhcp = (struct dhcp_packet *)buf;
	/* Generate a new packet to send to a client */
	packet = malloc(ETHER_HDR_LEN + DHCP_UDP_OVERHEAD + psize);
	if (packet == NULL) {
		logd(LOG_ERR, "malloc error");
		free(buf);
		return;
	}
	bzero(packet, ETHER_HDR_LEN + DHCP_UDP_OVERHEAD + psize);
	eh = (struct ether_header *)packet;
	ip = (struct ip *)(packet + ETHER_HDR_LEN);
	udp = (struct udphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip));

	if_idx = find_interface(*((ip_addr_t *)&dhcp->giaddr));
	if (if_idx == if_num) {
		logd(LOG_ERR, "Destination interface not found for: %s",
		     print_ip(*((ip_addr_t *)&dhcp->giaddr), pbuf));
		free(buf);
		return;
	}
	memcpy(eh->ether_shost, ifs[if_idx]->mac, ETHER_ADDR_LEN);
	eh->ether_type = htons(ETHERTYPE_IP);

	ip->ip_v = IPVERSION;
	ip->ip_hl = 5;		/* IP header length is 5 word (no options) */
	ip->ip_tos = IPTOS_LOWDELAY;
	ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + psize);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 16;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_sum = 0;
	memcpy(&ip->ip_src, &ifs[if_idx]->ip, sizeof(ip_addr_t));
	/* Broadcast flag */
	if (dhcp->op == BOOTREPLY && dhcp->flags & 0x80) {
		ip->ip_dst.s_addr = INADDR_BROADCAST;
		memset(eh->ether_dhost, 0xff, ETHER_ADDR_LEN);
	} else {
		memcpy(&ip->ip_dst, &dhcp->yiaddr, sizeof(ip_addr_t));
		memcpy(eh->ether_dhost, dhcp->chaddr, ETHER_ADDR_LEN);
	}

	udp->uh_sport = bootps_port;
	udp->uh_dport = bootpc_port;
	udp->uh_ulen = htons(sizeof(struct udphdr) + psize);
	udp->uh_sum = 0;	/* UDP checksum is optional. we don't care
				 * it. */

	memcpy(packet + ETHER_HDR_LEN + DHCP_UDP_OVERHEAD, buf, psize);
	ip->ip_sum = htons(ip_checksum((const char *)ip, sizeof(struct ip)));

	len = ETHER_HDR_LEN + DHCP_UDP_OVERHEAD + psize;
	ignore = 0;
	for (j = 0; j < plugins_number; j++) {
		if (plugins[j]->send_to_client)
			if (plugins[j]->send_to_client(&from_addr, ifs[if_idx],
						       &packet, &len) == 0) {
				logd(LOG_WARNING, "The packet rejected by %s plugin", plugins[j]->name);
				ignore = 1;
				break;
			}
	}

	if (!ignore)
		write(ifs[if_idx]->bpf, packet, len);

	free(packet);
	free(buf);
}

/* Get one packet from queue and process it (send to server(s)) */
void
process_queue()
{
	int i, j, ignore, sent = 0;
	struct queue *q;
	struct dhcp_packet *dhcp;

	pthread_mutex_lock(&queue_lock);
	q = STAILQ_FIRST(&q_head);
	STAILQ_REMOVE_HEAD(&q_head, entries);
	queue_size--;
	pthread_mutex_unlock(&queue_lock);

	dhcp = (struct dhcp_packet *)q->packet;

	/* Check the packet pass too many hops */
	if (dhcp->hops >= max_hops) {
		free(q->packet);
		free(q);
		return;
	}
	dhcp->hops++;
	if (dhcp->giaddr.s_addr == 0)
		memcpy(&dhcp->giaddr, &ifs[q->if_idx]->ip, sizeof(ip_addr_t));
	for (i = 0; i < ifs[q->if_idx]->srv_num; i++) {
		ignore = 0;
		for (j = 0; j < plugins_number; j++) {
			if (plugins[j]->send_to_server)
				if (plugins[j]->send_to_server(&(servers[ifs[q->if_idx]->srvrs[i]]->sockaddr),
						&q->packet, &q->len) == 0) {
					logd(LOG_WARNING, "The packet rejected by %s plugin",
					     plugins[j]->name);
					ignore = 1;
					break;
				}
		}

		if (!ignore) {
			sendto(ifs[q->if_idx]->fd, q->packet,
			       q->len, 0,
			       (struct sockaddr *)&servers[ifs[q->if_idx]->srvrs[i]]->sockaddr,
			       sizeof(struct sockaddr_in));
			sent++;
		}
	}

	free(q->packet);
	free(q);
}

/* Parse a servers part of config */
void
parse_servers_line(char *buf)
{
	char *p, *n;
	int inum;

	p = buf;
	strsep(&p, " \t");
	if (!open_server(buf)) {
		logd(LOG_WARNING, "Can't open server %s. Ignored.", buf);
		return;
	}
	inum = 0;
	while ((n = strsep(&p, " \t")) != NULL) {
		if (*n != '\0') {
			if (open_interface(n))
				inum++;
			else {
				logd(LOG_WARNING, "Interface %s does not exist. Ignored.", n);
			}
		}
	}
	/* We found no interfaces for listening on this computer */
	if (inum == 0) {
		srv_num--;
		free(servers[srv_num]);
	}
}

/* Read and parse a configuration file */
void
read_config(const char *filename)
{
	char buf[5000], plugin_name[50], plugin_path[100];
	char plugin_data_name[100];
	FILE *f, *fs;
	char *p;
	int line = 0;
	void *handle;
	enum sections {
		Servers, Options, Plugin
	} section = Servers;
	struct plugins_data *plugins_data;
	struct plugin_options *popt, *last_popt = NULL;

	if ((f = fopen(filename, "r")) == NULL)
		errx(1, "Can't open: %s", filename);
	while (fgets(buf, sizeof(buf), f) != NULL) {
		line++;
		/* Ignore empty lines and comments */
		if (buf[0] == '\n' || buf[0] == '#')
			continue;

		/* strip \n */
		if ((p = strchr(buf, '\n')) != NULL)
			*p = '\0';

		/* A new section starts */
		if (buf[0] == '[') {
			p = strchr(buf, ']');
			if (p == NULL || *(p + 1) != '\0')
				errx(1, "Config file syntax error. Line: %d", line);
			*p = '\0';
			if (strcasecmp(buf + 1, "servers") == 0) {
				section = Servers;
				continue;
			}
			if (strcasecmp(buf + 1, "options") == 0) {
				section = Options;
				continue;
			}
			if ((p = strcasestr(buf, "-plugin")) != NULL) {
				if (plugins_number > MAX_PLUGINS - 1)
					errx(1, "Too many plugins. Line: %d", line);

				section = Plugin;
				*p = '\0';
				strlcpy(plugin_name, buf + 1, sizeof(plugin_name));

				strlcpy(plugin_data_name, plugin_name, sizeof(plugin_data_name));
				strlcat(plugin_data_name, "_plugin", sizeof(plugin_data_name));

				strlcpy(plugin_path, plugin_base, sizeof(plugin_path));
				strlcat(plugin_path, "dhcprelya_", sizeof(plugin_path));
				strlcat(plugin_path, plugin_name, sizeof(plugin_path));
				strlcat(plugin_path, "_plugin.so", sizeof(plugin_path));
				handle = dlopen(plugin_path, RTLD_LAZY);
				if (handle == NULL) {
					printf("dlerror(): %s\n", dlerror());
					errx(1, "Can't open plugin: %s", plugin_path);
				}
				plugins_data = dlsym(handle, plugin_data_name);
				if (plugins_data == NULL)
					errx(1, "Can't load symbol %s", plugin_data_name);
				plugins[plugins_number] = malloc(sizeof(struct plugin_data));
				if (plugins[plugins_number] == NULL)
					process_error(EX_MEM, "malloc");

				memcpy(plugins[plugins_number], plugins_data, sizeof(struct plugin_data));

				/* head for options list for this plugin */
				options_heads[plugins_number] = malloc(sizeof(plugin_options_head_t));
				if (options_heads[plugins_number] == NULL)
					process_error(EX_MEM, "malloc");
				SLIST_INIT(options_heads[plugins_number]);

				plugins_number++;

				logd(LOG_DEBUG, "Plugin #%d (%s) loaded", plugins_number, plugin_name);
				continue;
			}
			errx(1, "Section name error. Line: %d", line);
		}
		if (section == Servers) {
			if ((p = strchr(buf, '=')) == NULL)
				parse_servers_line(buf);
			else {
				*p = '\0';
				p++;
				if (strcasecmp(buf, "file") != 0)
					errx(1, "Unknown option in Server section. Line: %d", line);
				if ((fs = fopen(p, "r")) == NULL)
					errx(1, "Can't open servers config file: %s", p);
				while (fgets(buf, sizeof(buf), fs) != NULL) {
					/* Ignore empty lines and comments */
					if (buf[0] == '\n' || buf[0] == '#')
						continue;

					/* strip \n */
					if ((p = strchr(buf, '\n')) != NULL)
						*p = '\0';

					parse_servers_line(buf);
				}
				fclose(fs);
			}
		}
		if (section == Options) {
			p = strchr(buf, '=');
			if (p == NULL)
				errx(1, "Option error. Line: %d", line);
			*p = '\0';
			p++;

			if (strcasecmp(buf, "max_packet_size") == 0) {
				max_packet_size = strtol(p, NULL, 10);
				if (max_packet_size < 300 || max_packet_size > DHCP_MTU_MAX)
					errx(1, "Wrong packet size. Line: %d", line);
				logd(LOG_DEBUG, "Option max_packet_size set to: %d", max_packet_size);
				continue;
			}
			if (strcasecmp(buf, "max_hops") == 0) {
				max_hops = strtol(p, NULL, 10);
				if (max_hops < 1 || max_hops > 16)
					errx(1, "Wrong hops number. Line: %d", line);
				logd(LOG_DEBUG, "Option max_hops set to: %d", max_hops);
				continue;
			}
			if (strcasecmp(buf, "rps_limit") == 0) {
				errno = 0;
				rps_limit = strtol(p, NULL, 10);
				if (errno != 0)
					errx(1, "rps_limit number error");
				logd(LOG_DEBUG, "Option rps_limit set to: %d", rps_limit);
				continue;
			}
			if (strcasecmp(buf, "plugin_path") == 0) {
				strlcpy(plugin_base, p, sizeof(plugin_base));
				if (plugin_base[strlen(plugin_base) - 1] != '/')
					strlcat(plugin_base, "/", sizeof(plugin_base));
				logd(LOG_DEBUG, "Option plugin_base set to: %s", plugin_base);
				continue;
			}
			errx(1, "Unknown option. Line: %d", line);
		}
		if (section == Plugin) {
			popt = malloc(sizeof(struct plugin_options));
			if (popt == NULL)
				process_error(EX_MEM, "malloc");
			popt->option_line = malloc(strlen(buf) + 1);
			if (popt->option_line == NULL)
				process_error(EX_MEM, "malloc");
			strcpy(popt->option_line, buf);
			if (SLIST_EMPTY(options_heads[plugins_number - 1])) {
				SLIST_INSERT_HEAD(options_heads[plugins_number - 1], popt, next);
				last_popt = popt;
			} else {
				SLIST_INSERT_AFTER(last_popt, popt, next);
				last_popt = popt;
			}
		}
	}
	fclose(f);
	if (if_num == 0)
		errx(1, "No interfaces found to listen. Exiting.");
}

int
main(int argc, char *argv[])
{
	int c, i, j, configured = 0;
	pid_t opid;
	char prgname[80], filename[256], *p;
	struct servent *servent;
	pthread_t tid;

	/* Default plugin_base */
	strlcpy(plugin_base, PLUGIN_PATH, sizeof(plugin_base));

	if ((servent = getservbyname("bootps", 0)) == NULL)
		errx(EX_UNAVAILABLE, "getservbyname(bootps)");
	bootps_port = servent->s_port;
	if ((servent = getservbyname("bootpc", 0)) == NULL)
		errx(EX_UNAVAILABLE, "getservbyname(bootpc)");
	bootpc_port = servent->s_port;

	openlog("dhcprelya", LOG_NDELAY | LOG_PID, LOG_DAEMON);

	strlcpy(prgname, argv[0], sizeof(prgname));
	filename[0] = '\0';
	while ((c = getopt(argc, argv, "A:c:df:hi:p:")) != -1) {
		switch (c) {
		case 'A':
			if (configured == 2)
				errx(1, "Either config file or command line options allowed. Not both.");
			max_packet_size = strtol(optarg, NULL, 10);
			if (max_packet_size < 300 || max_packet_size > DHCP_MTU_MAX)
				errx(1, "Wrong packet size");
			break;
		case 'c':
			if (configured == 2)
				errx(1, "Either config file or command line options allowed. Not both.");
			max_hops = strtol(optarg, NULL, 10);
			if (max_hops < 1 || max_hops > 16)
				errx(1, "Wrong hops number");
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			if (configured == 1)
				errx(1, "Either config file or command line options allowed. Not both.");
			if (configured == 2)
				errx(1, "only one config file allowed");
			configured = 2;
			read_config(optarg);
			break;
		case 'i':
			if (configured == 2)
				errx(1, "Either config file or command line options allowed. Not both.");
			configured = 1;
			if (!open_interface(optarg))
				logd(LOG_DEBUG, "Interface %s does not exist. Ignored.", optarg);
			break;
		case 'p':
			strlcpy(filename, optarg, sizeof(filename));
			break;
		case 'h':
		default:
			usage(prgname);
		}
	}

	argc -= optind;
	argv += optind;

	if (optind == 0)
		argc--;

	if ((configured == 1 && argc < 1) || (configured == 2 && argc >= 1))
		usage(prgname);

	/* Initialize polugins */
	for (i = 0; i < plugins_number; i++) {
		if (plugins[i]->init)
			if ((plugins[i]->init) (options_heads[i]) == 0)
				errx(1, "Can't initialize a plugin %s\n", plugins[i]->name);
	}

	for (i = 0; i < argc; i++) {
		open_server(argv[i]);
		for (j = 0; j < if_num; j++) {
			if (i > ifs[j]->srv_num - 1) {
				ifs[j]->srv_num++;
				ifs[j]->srvrs = realloc(ifs[j]->srvrs, ifs[j]->srv_num * sizeof(int));
			}
			ifs[j]->srvrs[ifs[i]->srv_num - 1] = i;
		}
	}

	if (if_num == 0)
		errx(1, "No interfaces found to listen. Exiting.");

	logd(LOG_WARNING, "Total interfaces: %d", if_num);

	/* Make a PID filename */
	if (filename[0] == '\0') {
		strlcpy(filename, "/var/run/", sizeof(filename));
		p = strrchr(prgname, '/');
		if (p == NULL)
			p = prgname;
		else
			p++;
		strlcat(filename, p, sizeof(filename));
		strlcat(filename, ".pid", sizeof(filename));
	}
	/* Create a PID file and daemonize if no debug flag */
	if (!debug && (pfh = pidfile_open(filename, 0644, &opid)) == NULL) {
		if (errno == EEXIST)
			errx(1, "Already run with PID %lu. Exiting.", (unsigned long)opid);
		errx(1, "Can't create PID file");
	}
	signal(SIGHUP, SIG_IGN);

	if (!debug) {
		if (daemon(0, 0) == -1)
			process_error(1, "Can't daemonize. Exiting.");
		else
			logd(LOG_DEBUG, "Runned as %d", getpid());
	}
	if (pfh)
		pidfile_write(pfh);

	STAILQ_INIT(&q_head);

	pthread_mutex_init(&queue_lock, NULL);

	/* Create listeners for every interface */
	for (i = 0; i < if_num; i++) {
		pthread_create(&tid, NULL, listener, ifs[i]);
		pthread_detach(tid);
	}

	/* Main loop */
	while (1) {
		if (queue_size > 0)
			process_queue();

		/* Process one packet from server(s) */
		process_server_answer();
	}

	/* Destroy polugins */
	for (i = 0; i < plugins_number; i++) {
		if (plugins[i]->destroy)
			(plugins[i]->destroy) ();
	}
	pthread_mutex_destroy(&queue_lock);
}
