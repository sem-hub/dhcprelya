/*
 * Copyright (c) 2007-2012 Sergey Matveychuk
 *      Yandex, LLC.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the company nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "dhcprelya.h"

static char rid[255];
static int rid_len, drop_untrusted=1,
	   never_strip_answer=0, always_strip_answer=0;

STAILQ_HEAD(thead, trusted_circuits) trusted_head;
struct trusted_circuits {
    uint8_t	*id;
    int		len;

    STAILQ_ENTRY(trusted_circuits) next;
};

/*
 * returns: 
 *   NULL if optin82 was not found.
 *     *optins point to End-Of-Options mark (255)
 *   or pointer to option82
 */
uint8_t *
find_option82(uint8_t *options)
{
    uint8_t *p = NULL;

    do {
	switch(*options) {
	    case 0:
		options++;
		break;
	    default:
		options += options[1] + 2;
	}
    } while(*options != 255 && *options != 82);

    if(*options == 82)
	p = options;

    return p;
}

int
option82_plugin_init(plugin_options_head_t *options_head)
{
    struct plugin_options *opts, *opts_tmp;
    int i, n, rid_set=0;
    char *p, *p1;
    struct trusted_circuits *tc_entry;

    STAILQ_INIT(&trusted_head);

    SLIST_FOREACH_SAFE(opts, options_head, next, opts_tmp) {
	if((p = strchr(opts->option_line, '=')) == NULL) {
	    logd(LOG_ERR, "option82_plugin: Syntax error at line: %s", opts->option_line);
	    return 0;
	}
	*p = '\0'; p++;
	if(strcasecmp(opts->option_line, "drop_untrusted") == 0) {
	    if((drop_untrusted=get_bool_value(p)) == -1) {
		logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
		return 0;
	    }
	} else if(strcasecmp(opts->option_line, "remote_id") == 0) {
	    rid_set = 1;
	    rid_len = 0;
	    /* is a string */
	    if(*p == '"') {
		p++;
		for(i=0; *p != '"' && *p != '\0'; p++,i++)
		    rid[i] = *p;
		if(*p != '"') {
		    logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
		    return 0;
		}
	    } else if(strcasecmp(p, "0x") == 0) {
		p += 2;
		logd(LOG_ERR, "option82_plugin: hexadecimal is not supported yet at line: %s", opts->option_line);
		return 0;
	    } else {
		logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
		return 0;
	    }
	} else if(strcasecmp(opts->option_line, "never_strip_answer") == 0) {
	    if((never_strip_answer=get_bool_value(p)) == -1) {
		logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
		return 0;
	    }
	} else if(strcasecmp(opts->option_line, "always_strip_answer") == 0) {
	    if((always_strip_answer=get_bool_value(p)) == -1) {
		logd(LOG_ERR, "option82_plugin: Syntex error in option value at line: %s", opts->option_line);
		return 0;
	    }
	    if(never_strip_answer && always_strip_answer) {
		logd(LOG_ERR, "option82_plugin: options never_strip_answer and always_strip_answer are mutually exclusive");
		return 0;
	    }
	} else if(strcasecmp(opts->option_line, "trusted_circuits") == 0) {
	    n=1;
	    while((p1 = strsep(&p, " \t")) != NULL) {
		if(*p1 == '"') {
		    p1++;
		    tc_entry = malloc(sizeof(struct trusted_circuits));
		    if(tc_entry == NULL) {
			logd(LOG_ERR, "option82_plugin: malloc error");
			return 0;
		    }
		    tc_entry->id = malloc(strlen(p1));
		    if(tc_entry->id == NULL) {
			logd(LOG_ERR, "option82_plugin: malloc error");
			return 0;
		    }
		    for(i=0; *p1 != '\0'; i++,p1++)
			tc_entry->id[i] = *p1;
		    i--;
		    if(tc_entry->id[i] != '"') {
			logd(LOG_ERR, "option82_plugin: value syntax error at line %d", opts->option_line);
			return 0;
		    }
		    tc_entry->id[i] = '\0';
		    logd(LOG_DEBUG, "trusted circuit #%d: %s", n, tc_entry->id);
		    tc_entry->len = strlen((char*)tc_entry->id);
		    STAILQ_INSERT_TAIL(&trusted_head, tc_entry, next);
		    n++;
		} else {
		    if(strncasecmp(p1, "0x", 2) == 0)
			logd(LOG_ERR, "option82_plugin: hexadecial is not supported yet at line: %d", opts->option_line);
		    else
			logd(LOG_ERR, "option82_plugin: value syntax error at line %d", opts->option_line);
		    return 0;
		}
	    }
	} else {
	    logd(LOG_ERR, "option82_plugin: Unknown option at line: %s", opts->option_line);
	    return 0;
	}
	free(opts->option_line);
	SLIST_REMOVE(options_head, opts, plugin_options, next);
	free(opts);
    }

    if(!rid_set) {
	if(gethostname(rid, sizeof(rid)) == -1) {
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
	uint8_t **packet, size_t *psize)
{
    struct dhcp_packet *dhcp;
    uint8_t *buf, *p, *opt;
    int intf_name_len, match;
    struct trusted_circuits *tc_entry;

    dhcp = (struct dhcp_packet *)(*packet+ETHER_HDR_LEN+DHCP_UDP_OVERHEAD);
    p = dhcp->options;
    p += DHCP_COOKIE_LEN;

    opt = find_option82(p);
    /* XXX discard if GIADDR spoofing (our address) */
    if(*((ip_addr_t*)&dhcp->giaddr) == 0 && opt != NULL) {
	logd(LOG_ERR, "option82_plugin: got a packet from an agent but GIADDR == 0. Dropped.");
	return 0;
    }

    /* 
     * if we already have option82, check for trusted circuits.
     * we'll not add own option82 if it's already there.
     */
    if(opt) {
	match=0;
	STAILQ_FOREACH(tc_entry, &trusted_head, next) {
	    if(tc_entry->len == rid_len && memcmp(tc_entry->id, rid, rid_len) == 0)
		match = 1;
	}
	if(!match) {
	    logd(LOG_DEBUG, "option82_plugin: got a packet with option82 but from unknown circuit. Dropped.");
	    return 0;
	}
    } else {
	/* Go to end of options mark */
	while(*p != 255 && p-*packet <= *psize) {
	    p++;
	}

	/* Not found. Bad packet. */
	if(p-*packet >= *psize) {
	    logd(LOG_ERR, "option82_plugin: Bad options format");
	    return 0;
	}

	intf_name_len = strlen(intf->name);

	/* RFC3046 requires this check */
	if(*psize+4+intf_name_len+rid_len > max_packet_size) {
	    logd(LOG_ERR, "option82_plugin: a packet will oversided after adding options82. Passed without changes.");
	    return 1;
	}
	buf = malloc(*psize + intf_name_len + rid_len + 6);
	if(buf == NULL) {
	    logd(LOG_ERR, "option82_plugin: malloc error");
	    return 0;
	}
	memset(buf, 0, *psize + intf_name_len + rid_len + 6);
	memcpy(buf, *packet, *psize);

	p = buf + (p-*packet);

	*(p++) = 82;
	*(p++) = 4 + intf_name_len + rid_len;
	*(p++) = 1;
	*(p++) = intf_name_len;
	memcpy(p, intf->name, intf_name_len);
	p += intf_name_len;

	*(p++) = 2;
	*(p++) = rid_len;
	memcpy(p, rid, rid_len);
	p += rid_len;
	/* End of options */
	*p = 255;

	p = *packet;
	*packet = buf;
	free(p);
	*psize = *psize + intf_name_len + rid_len + 6;
    }

    return 1;
}

int option82_plugin_send_to_client(const struct sockaddr_in *server,
	const struct interface *intf, uint8_t **packet,
	size_t *psize)
{
    struct dhcp_packet *dhcp;
    struct ip *ip;
    struct udphdr *udp;
    uint8_t *p, *opt;
    int rlen, opt_size = 0, match, need_strip=0;
    struct trusted_circuits *tc_entry;

    dhcp = (struct dhcp_packet *)(*packet+ETHER_HDR_LEN+DHCP_UDP_OVERHEAD);
    ip = (struct ip *)(*packet+ETHER_HDR_LEN);
    udp = (struct udphdr *)(*packet+ETHER_HDR_LEN+sizeof(struct ip));

    opt = find_option82(dhcp->options + DHCP_COOKIE_LEN);
    /* We don't find option82, drop the packet */
    if(opt == NULL)
	return 0;
    /* Find Remote ID sub-option */
    p = opt + 2;
    if(*p != 1 && *p !=2) {
	logd(LOG_ERR, "option82_plugin: bad sub-option. The packet dropped.");
	return 0;
    }
    if(*p == 1)
	p += *(p+1)+2;
    p++;
    rlen = *p++;
    /* Check if Remote ID is our one */
    match=0;
    if(rlen == rid_len && memcmp(rid, p, rid_len) == 0)
	    match = 1;

    /* it's not our. check for trusted */
    if(!match) {
	match=0;
	STAILQ_FOREACH(tc_entry, &trusted_head, next) {
	    if(tc_entry->len == rlen && memcmp(tc_entry->id, p, rlen) == 0)
		match = 1;
	}
	if(!match) {
	    *(p+rlen) = '\0';
	    logd(LOG_DEBUG, "option82_plugin: an answer from untrusted circuit: %s. Ignored", p);
	    return 0;
	}
	need_strip = 0;
    } else
	if(!never_strip_answer)
	    need_strip = 1;

    /* strip option82 */
    if(need_strip || always_strip_answer) {
	opt_size = opt[1] + 2;
	memmove(opt, opt + opt_size, *psize - (opt+opt_size - *packet));
	*psize -= opt_size;
	udp->uh_ulen = htons(ntohs(udp->uh_ulen) - opt_size);
	ip->ip_len = htons(ntohs(ip->ip_len) - opt_size);
	ip->ip_sum = 0;
	ip->ip_sum = htons(ip_checksum((const char*)ip, sizeof(struct ip)));
    }

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
