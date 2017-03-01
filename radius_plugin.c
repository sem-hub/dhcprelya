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
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <radlib.h>
#include "dhcprelya.h"

static struct rad_handle *rh;
static char **only_for;
static unsigned only_for_num = 0;
static struct in_addr bind_addr;
static pthread_mutex_t mtx;

void *
send_acct(void *packet)
{
	struct dhcp_packet *dhcp = (struct dhcp_packet *)packet;
	char buf[100];

	/* Ignore all packets w/o an assigned IP address */
	if (dhcp->yiaddr.s_addr == 0) {
		free(packet);
		return NULL;
	}
	pthread_mutex_lock(&mtx);
	if (rad_create_request(rh, RAD_ACCOUNTING_REQUEST) == -1) {
		logd(LOG_ERR, "radius_plugin: rad_create_request()");
		goto end;
	}
	if (rad_put_int(rh, RAD_ACCT_STATUS_TYPE, RAD_START) == -1) {
		logd(LOG_ERR, "radius_plugin: rad_put_int(RAD_ACCT_STATUS_TYPE) error");
		goto end;
	}
	if (rad_put_string(rh, RAD_USER_NAME,
		ether_ntoa_r((struct ether_addr*)dhcp->chaddr, buf)) == -1) {
		logd(LOG_ERR, "radius_plugin: rad_put_string()");
		goto end;
	}
	if (rad_put_string(rh, RAD_CALLING_STATION_ID,
		ether_ntoa_r((struct ether_addr*)dhcp->chaddr, buf)) == -1) {
		logd(LOG_ERR, "radius_plugin: rad_put_string()");
		goto end;
	}
	if (rad_put_addr(rh, RAD_FRAMED_IP_ADDRESS, dhcp->yiaddr) == -1) {
		logd(LOG_ERR, "radius_plugin: rad_put_addr()");
		goto end;
	}
	if (rad_put_int(rh, RAD_NAS_PORT, dhcp->yiaddr.s_addr) == -1) {
		logd(LOG_ERR, "radius_plugin: rad_put_int(port)");
		goto end;
	}
	if (rad_put_addr(rh, RAD_NAS_IP_ADDRESS, bind_addr) == -1) {
		logd(LOG_ERR, "radius_plugin: rad_put_addr()");
		goto end;
	}
	if (rad_send_request(rh) == -1)
		logd(LOG_ERR, "rad_send_request(): %s", rad_strerror(rh));
	else
		logd(LOG_DEBUG, "OK");
end:
	pthread_mutex_unlock(&mtx);
	free(packet);
	return NULL;
}

int
radius_plugin_init(plugin_options_head_t *options_head)
{
	struct plugin_options *opts, *opts_tmp;
	char *p, *p1;
	int i, n = 0, timeout = 5, tries = 3, dead_time = 60;
	int servers_num = 0, secrets_num = 0;
	char **servers = NULL, **secrets = NULL;

	if ((rh = rad_acct_open()) == NULL) {
		logd(LOG_ERR, "radius_plugin: can't intialize libradius");
		return 0;
	}
	SLIST_FOREACH_SAFE(opts, options_head, next, opts_tmp) {
		if ((p = strchr(opts->option_line, '=')) == NULL) {
			logd(LOG_ERR, "radius_plugin: syntax error at line: %s", opts->option_line);
			return 0;
		}
		*p = '\0';
		p++;
		if (strcasecmp(opts->option_line, "servers") == 0) {
			servers_num = 0;
			for (i = 0; i < strlen(p); i++)
				if (p[i] == ' ' || p[i] == '\t')
					n++;
			servers = malloc(sizeof(char *) * (n + 1));
			if (servers == NULL) {
				logd(LOG_ERR, "radius_plugin: malloc error");
				return 0;
			}
			while ((p1 = strsep(&p, " \t")) != NULL) {
				servers[servers_num] = malloc(strlen(p1) + 1);
				if (servers[servers_num] == NULL) {
					logd(LOG_ERR, "radius_plugin: malloc error");
					return 0;
				}
				logd(LOG_DEBUG, "Server: %s", p1);
				strcpy(servers[servers_num], p1);
				servers_num++;
			}
		} else if (strcasecmp(opts->option_line, "secret") == 0) {
			secrets_num = 0;
			for (i = 0; i < strlen(p); i++)
				if (p[i] == ' ' || p[i] == '\t')
					n++;
			secrets = malloc(sizeof(char *) * (n + 1));
			if (secrets == NULL) {
				logd(LOG_ERR, "radius_plugin: malloc error");
				return 0;
			}
			while ((p1 = strsep(&p, " \t")) != NULL) {
				secrets[secrets_num] = malloc(strlen(p1) + 1);
				if (secrets[secrets_num] == NULL) {
					logd(LOG_ERR, "radius_plugin: malloc error");
					return 0;
				}
				logd(LOG_DEBUG, "secret: %s", p1);
				strcpy(secrets[secrets_num], p1);
				secrets_num++;
			}
		} else if (strcasecmp(opts->option_line, "timeout") == 0) {
			timeout = strtol(p, NULL, 10);
			if (timeout < 1) {
				logd(LOG_ERR, "radius_plugin: timeout error");
				return 0;
			}
			logd(LOG_DEBUG, "timeout set to: %u", timeout);
		} else if (strcasecmp(opts->option_line, "tries") == 0) {
			tries = strtol(p, NULL, 10);
			if (tries < 1) {
				logd(LOG_ERR, "radius_plugin: tries error");
				return 0;
			}
			logd(LOG_DEBUG, "tries set to: %u", tries);
		} else if (strcasecmp(opts->option_line, "dead_time") == 0) {
			dead_time = strtol(p, NULL, 10);
			if (dead_time == 0 && errno != 0) {
				logd(LOG_ERR, "radius_plugin: dead_time error");
				return 0;
			}
			logd(LOG_DEBUG, "dead_time set to: %d", dead_time);
		} else if (strcasecmp(opts->option_line, "bind_to") == 0) {
			/* Bind to an IP or an interface */
			if (inet_pton(AF_INET, p, &bind_addr.s_addr) != 1)
				if (!get_ip(p, &bind_addr.s_addr, NULL)) {
					logd(LOG_ERR, "radius_plugin: interface %s not found", p);
					return 0;
				}
		} else if (strcasecmp(opts->option_line, "only_for") == 0) {
			only_for_num = 0;
			for (i = 0; i < strlen(p); i++)
				if (p[i] == ' ' || p[i] == '\t')
					n++;
			only_for = malloc(sizeof(char *) * (n + 1));
			if (only_for == NULL) {
				logd(LOG_ERR, "radius_plugin: malloc error");
				return 0;
			}
			while ((p1 = strsep(&p, " \t")) != NULL) {
				only_for[only_for_num] = malloc(strlen(p1) + 1);
				if (only_for[only_for_num] == NULL) {
					logd(LOG_ERR, "radius_plugin: malloc error");
					return 0;
				}
				strcpy(only_for[only_for_num], p1);
				only_for_num++;
			}
		} else {
			logd(LOG_ERR, "radius_plugin: unknown option at line: %s", opts->option_line);
			return 0;
		}
		free(opts->option_line);
		SLIST_REMOVE(options_head, opts, plugin_options, next);
		free(opts);
	}

	if (servers_num == 0) {
		logd(LOG_ERR, "radius_plugin: at least one server must be defined");
		return 0;
	}
	if (secrets_num == 0) {
		logd(LOG_ERR, "radius_plugin: at least one secret must be defined");
		return 0;
	}
	if (secrets_num > 1 && secrets_num != servers_num) {
		logd(LOG_ERR, "radius_plugin: number of secrets must be one or the same as servers number");
		return 0;
	}
	for (i = 0; i < servers_num; i++)
		if (rad_add_server_ex(rh, servers[i], 0, secrets_num == 1 ? secrets[0] : secrets[i],
				timeout, tries, dead_time, &bind_addr) == -1) {
			logd(LOG_ERR, "radius_plugin: rad_add_server_ex(%s) error", servers[i]);
			return 0;
		}
	for (i = 0; i < only_for_num; i++)
		logd(LOG_DEBUG, "only_for: %s", only_for[i]);

	pthread_mutex_init(&mtx, NULL);
	return 1;
}

void
radius_plugin_destroy()
{
	pthread_mutex_destroy(&mtx);
	rad_close(rh);
}

int
radius_plugin_send_to_client(const struct sockaddr_in *server,
				const struct interface *intf,
				struct dhcp_packet *dhcp, struct packet_headers *headers)
{
	pthread_t tid;
	int i;
	uint8_t *b;
	size_t dhcp_len;

	b = find_option(dhcp, 53);
	/* If it's not DHCPACK. Just pass the packet. */
	if (!b || b[2] != 5)
		return 1;

	/* Look for interfaces we should do radius request */
	for (i = 0; i < only_for_num; i++)
		if (strcmp(only_for[i], intf->name) == 0)
			break;

	if (only_for_num == 0 || i < only_for_num) {
		dhcp_len = get_dhcp_len(dhcp);
		b = malloc(dhcp_len);
		if (b == NULL) {
			logd(LOG_ERR, "radius_plugin: malloc error");
			return 0;
		}
		memcpy(b, dhcp, dhcp_len);
		pthread_create(&tid, NULL, send_acct, b);
		pthread_detach(tid);
	}
	return 1;
}

struct plugin_data radius_plugin = {
	"radius",
	radius_plugin_init,
	radius_plugin_destroy,
	NULL,
	NULL,
	NULL,
	radius_plugin_send_to_client
};
