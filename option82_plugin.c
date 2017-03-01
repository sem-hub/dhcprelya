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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "dhcprelya.h"

static char rid[255];
static int rid_len, drop_untrusted = 1, never_strip_answer = 0, always_strip_answer = 0;

STAILQ_HEAD(thead, trusted_circuits) trusted_head;
struct trusted_circuits {
	uint8_t *id;
	int len;

	 STAILQ_ENTRY(trusted_circuits) next;
};

static int link_selection_map[IF_MAX];
static int only_for[IF_MAX];

int
option82_plugin_init(plugin_options_head_t *options_head)
{
	struct plugin_options *opts, *opts_tmp;
	int i, n, rid_set = 0;
	char *p, *p1;
	struct trusted_circuits *tc_entry;
	struct interface *intf;

	STAILQ_INIT(&trusted_head);
	bzero(&link_selection_map, sizeof(link_selection_map));
	for (i = 0; i < IF_MAX; i++)
		only_for[i] = 1;

	SLIST_FOREACH_SAFE(opts, options_head, next, opts_tmp) {
		if ((p = strchr(opts->option_line, '=')) == NULL) {
			logd(LOG_ERR, "option82_plugin: Syntax error at line: %s", opts->option_line);
			return 0;
		}
		*p = '\0';
		p++;
		if (strcasecmp(opts->option_line, "drop_untrusted") == 0) {
			if ((drop_untrusted = get_bool_value(p)) == -1) {
				logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
				return 0;
			}
		} else if (strcasecmp(opts->option_line, "remote_id") == 0) {
			rid_set = 1;
			rid_len = 0;
			/* is a string */
			if (*p == '"') {
				p++;
				for (i = 0; *p != '"' && *p != '\0'; p++, i++)
					rid[i] = *p;
				if (*p != '"') {
					logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
					return 0;
				}
			} else if (strcasecmp(p, "0x") == 0) {
				p += 2;
				logd(LOG_ERR, "option82_plugin: hexadecimal is not supported yet at line: %s", opts->option_line);
				return 0;
			} else {
				logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
				return 0;
			}
		} else if (strcasecmp(opts->option_line, "never_strip_answer") == 0) {
			if ((never_strip_answer = get_bool_value(p)) == -1) {
				logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
				return 0;
			}
		} else if (strcasecmp(opts->option_line, "always_strip_answer") == 0) {
			if ((always_strip_answer = get_bool_value(p)) == -1) {
				logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
				return 0;
			}
			if (never_strip_answer && always_strip_answer) {
				logd(LOG_ERR, "option82_plugin: options never_strip_answer and always_strip_answer are mutually exclusive");
				return 0;
			}
		} else if (strcasecmp(opts->option_line, "trusted_circuits") == 0) {
			n = 1;
			while ((p1 = strsep(&p, " \t")) != NULL) {
				if (*p1 == '"') {
					p1++;
					tc_entry = malloc(sizeof(struct trusted_circuits));
					if (tc_entry == NULL) {
						logd(LOG_ERR, "option82_plugin: malloc error");
						return 0;
					}
					tc_entry->id = malloc(strlen(p1));
					if (tc_entry->id == NULL) {
						logd(LOG_ERR, "option82_plugin: malloc error");
						return 0;
					}
					for (i = 0; *p1 != '\0'; i++, p1++)
						tc_entry->id[i] = *p1;
					i--;
					if (tc_entry->id[i] != '"') {
						logd(LOG_ERR, "option82_plugin: value syntax error at line %d", opts->option_line);
						return 0;
					}
					tc_entry->id[i] = '\0';
					logd(LOG_DEBUG, "trusted circuit #%d: %s", n, tc_entry->id);
					tc_entry->len = strlen((char *)tc_entry->id);
					STAILQ_INSERT_TAIL(&trusted_head, tc_entry, next);
					n++;
				} else {
					if (strncasecmp(p1, "0x", 2) == 0)
						logd(LOG_ERR, "option82_plugin: hexadecial is not supported yet at line: %d", opts->option_line);
					else
						logd(LOG_ERR, "option82_plugin: value syntax error at line %d", opts->option_line);
					return 0;
				}
			}
		} else if (strcasecmp(opts->option_line, "enable_link_selection_for") == 0) {
			while ((p1 = strsep(&p, " ,")) != NULL) {
				if ((intf = get_interface_by_name(p1)) == NULL) {
					logd(LOG_WARNING, "option82_plugin: (link_selection) interface %s is not open. Ignoring.", p1);
					continue;
				}
				link_selection_map[intf->idx] = 1;
				logd(LOG_DEBUG, "option82_plugin: link_selection suboption enabled on %s", p1);
			}
		} else if (strcasecmp(opts->option_line, "only_for") == 0) {
			bzero(&only_for, sizeof(only_for));
			logd(LOG_DEBUG, "option82_plugin: plugin enabled only for these interfaces: %s", p);
			n = 0;
			while ((p1 = strsep(&p, " ,")) != NULL) {
				if ((intf = get_interface_by_name(p1)) == NULL) {
					logd(LOG_WARNING, "option82_plugin: (only_for) interface %s is not open. Ignoring.", p1);
					continue;
				}
				only_for[intf->idx] = 1;
				n++;
			}
			if (n == 0)
				logd(LOG_WARNING, "option82_plugin: (only_for) no valid interfaces found. Plugin is disabled.");
		} else {
			logd(LOG_ERR, "option82_plugin: Unknown option at line: %s", opts->option_line);
			return 0;
		}
		free(opts->option_line);
		SLIST_REMOVE(options_head, opts, plugin_options, next);
		free(opts);
	}

	if (!rid_set) {
		if (gethostname(rid, sizeof(rid)) == -1) {
			logd(LOG_ERR, "option82_plugin: Can't get a hostname");
			return 0;
		}
		rid_len = strlen(rid);
	}
	logd(LOG_DEBUG, "option82_plugin: Agent Remote ID: %s", rid);
	return 1;
}

int
option82_plugin_client_request(const struct interface *intf,
			       struct dhcp_packet *dhcp, struct packet_headers *headers)
{
	uint8_t buf[255], *p, *opt;
	int intf_name_len, match;
	struct trusted_circuits *tc_entry;

	if (!only_for[intf->idx])		// Disabled in config. Ignore interface and pass the packet as is.
		return 1;

	opt = find_option(dhcp, 82);
	/* XXX discard if GIADDR spoofing (our address) */
	if (*((ip_addr_t *)&dhcp->giaddr) == 0 && opt != NULL) {
		logd(LOG_ERR, "option82_plugin: got a packet from an agent but GIADDR == 0. Dropped.");
		return 0;
	}
	/* if we already have option82, check for trusted circuits. we'll not
	 * add own option82 if it's already there. */
	if (opt) {
		match = 0;
		STAILQ_FOREACH(tc_entry, &trusted_head, next) {
			if (tc_entry->len == rid_len && memcmp(tc_entry->id, rid, rid_len) == 0)
				match = 1;
		}
		if (!match) {
			logd(LOG_DEBUG, "option82_plugin: got a packet with option82 but from unknown circuit. Dropped.");
			return 0;
		}
	} else {
		intf_name_len = strlen(intf->name);

		/* insert option 82 */
		p = buf;
		*p++ = 1;
		*p++ = intf_name_len;
		memcpy(p, intf->name, intf_name_len);
		p += intf_name_len;
		*p++ = 2;
		*p++ = rid_len;
		memcpy(p, rid, rid_len);
		p += rid_len;
		if (link_selection_map[intf->idx]) {
			*p++ = 5;
			*p++ = sizeof(ip_addr_t);
			memcpy(p, &intf->ip, sizeof(ip_addr_t));
			p += sizeof(ip_addr_t);
		}
		insert_option(dhcp, 82, p - buf, buf, INSERT_OPTION_NORMAL);
	}

	return 1;
}

int
option82_plugin_send_to_client(const struct sockaddr_in *server,
					const struct interface *intf,
					struct dhcp_packet *dhcp, struct packet_headers *headers)
{
	uint8_t *p;
	int rlen, match, need_strip = 0;
	struct trusted_circuits *tc_entry;

	if (!only_for[intf->idx])		// Disabled in config. Ignore interface and pass the packet as is.
		return 1;

	/* We don't find option82, pass the packet as is */
	if (find_option(dhcp, 82) == NULL)
		return 1;
	/* Find Remote ID sub-option */
	p = find_suboption(dhcp, 82, 2);
	if (p == NULL) {
		logd(LOG_ERR, "option82_plugin: bad sub-option. The packet dropped.");
		return 0;
	}
	rlen = p[1];
	p += 2;
	/* Check if Remote ID is our one */
	match = 0;
	if (rlen == rid_len && memcmp(rid, p, rid_len) == 0)
		match = 1;

	/* it's not our. check for trusted */
	if (!match) {
		match = 0;
		STAILQ_FOREACH(tc_entry, &trusted_head, next) {
			if (tc_entry->len == rlen && memcmp(tc_entry->id, p, rlen) == 0)
				match = 1;
		}
		if (!match) {
			*(p + rlen) = '\0';
			logd(LOG_DEBUG, "option82_plugin: an answer from untrusted circuit: %s. Ignored", p);
			return 0;
		}
		need_strip = 0;
	} else if (!never_strip_answer)
		need_strip = 1;

	/* strip option82 */
	if (need_strip || always_strip_answer)
		remove_option(dhcp, 82);
	return 1;
}

struct plugin_data option82_plugin = {
	"option82",
	option82_plugin_init,
	NULL,
	option82_plugin_client_request,
	NULL,
	NULL,
	option82_plugin_send_to_client
};
