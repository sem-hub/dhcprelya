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

#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <sys/mac.h>
#include <ifaddrs.h>
#include "dhcprelya.h"

int
get_mac(char *if_name, char *if_mac)
{
    struct ifaddrs *ifaphead, *ifap;
    int found=0;
    struct sockaddr_dl *sdl=NULL;

    if(getifaddrs(&ifaphead) != 0)
	errx(EX_RES, "getifaddrs: %s", strerror(errno));

    for(ifap = ifaphead; ifap && !found; ifap = ifap->ifa_next)
	if(strcmp(ifap->ifa_name, if_name) == 0) {
	    found = 1;
	    sdl = (struct sockaddr_dl *)ifap->ifa_addr;
	    if(sdl)
		memcpy(if_mac, LLADDR(sdl), sdl->sdl_alen);
	}

    freeifaddrs(ifaphead);
    if(!found) {
	logd(LOG_DEBUG, "can't find mac for interface %s", if_name);
	return 0;
    }

    return 1;
}

int 
get_ip(char *iname, ip_addr_t *ip, ip_addr_t *mask)
{
    int s;
    struct ifreq ifr;
    struct sockaddr_in *saddr;

    if((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	errx(EX_RES, "get_ip: socket: %s", strerror(errno));

    strlcpy(ifr.ifr_name, iname, sizeof(ifr.ifr_name));
    if(ioctl(s, SIOCGIFADDR, &ifr) < 0) {
	close(s);
	logd(LOG_DEBUG, "Can't get IP for %s", iname);
	return 0;
    }

    saddr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(ip, &saddr->sin_addr.s_addr, sizeof(ip_addr_t));

    if(ioctl(s, SIOCGIFNETMASK, &ifr) < 0) {
	close(s);
	logd(LOG_DEBUG, "Can't get netmask for %s", iname);
	return 0;
    }

    memcpy(mask, &saddr->sin_addr.s_addr, sizeof(ip_addr_t));

    close(s);
    return 1;
}
