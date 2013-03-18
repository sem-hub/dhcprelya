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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include "dhcprelya.h"

extern unsigned debug;

char *
print_mac(uint8_t *s, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
	    s[0],s[1],s[2],s[3],s[4],s[5]);
    return buf;
}

char *
print_ip(ip_addr_t ip, char *buf)
{
    union {
	ip_addr_t	n;
	uint8_t		b[4];
    } u;

    u.n = ip;
    sprintf(buf, "%u.%u.%u.%u", u.b[0], u.b[1], u.b[2], u.b[3]);
    return buf;
}

char *
print_xid(uint32_t ip, char *buf)
{
    union {
	uint32_t	n;
	uint8_t		b[4];
    } u;

    u.n = ip;
    sprintf(buf, "0x%02x%02x%02x%02x", u.b[0], u.b[1], u.b[2], u.b[3]);
    return buf;
}

/*
 * Print a log message
 */
void
logd(int log_level, char *fmt, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, fmt);

    vsprintf(buf, fmt, ap);
    if(debug) {
	printf(buf);
	putchar('\n');
    } else
	if(log_level != LOG_DEBUG)
	    syslog(LOG_ERR, buf);

    va_end(ap);
}

/*
 * Rerurn 1(true) for strings "yes", "on", "1"
 * or 0(false) for strings "no", "off", "0"
 * and -1 for an error.
 * All strings is case insensitive.
 */
int
get_bool_value(const char *str)
{
    if(strcasecmp(str, "yes") == 0 || strcasecmp(str, "on") == 0 ||
	    strcmp(str, "1"))
	return 1;
    else if(strcasecmp(str, "no") == 0 || strcasecmp(str, "off") == 0 ||
	    strcmp(str, "0"))
	return 0;
    else
	return -1;
}
