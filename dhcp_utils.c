#include <string.h>
#include <stdlib.h>

#include "dhcprelya.h"

/* returns offset of option start or -1 if malformed packet detected or -2 if nothing found */
int
find_opt_offset(uint8_t *start, uint8_t option_id, int max_len, int is_subopt)
{
	uint8_t *p;
	int passed = 0;

	p = start;
	while (passed < max_len && *p != 255 && *p != option_id) {
		if (*p == 0)
			p++;
		else
			p += p[1] + 2;
		passed = p - start;
	}

	if (passed > max_len ||
		(passed == max_len && *p != 255) ||
		(!is_subopt && passed + 2 + p[1] >= max_len))
		return -1;		// Malformed packet

	if (*p == option_id)
		return passed;

	return -2;			// Nothing found
}

/* returns: NULL if option was not found or malformed packet detected.
   *optins point to End-Of-Options mark (255) or pointer to option_id option */
uint8_t *
find_option(struct dhcp_packet *dhcp, uint8_t option_id)
{
	int passed, max_len;

	if (dhcp == NULL)
		return NULL;
	max_len = max_packet_size - ETHER_HDR_LEN - DHCP_FIXED_LEN - DHCP_COOKIE_LEN;
	passed = find_opt_offset(dhcp->options + DHCP_COOKIE_LEN,
					option_id, max_len, 0);

	if (passed < 0)
		return NULL;

	return dhcp->options + DHCP_COOKIE_LEN + passed;
}

uint8_t *
find_suboption(struct dhcp_packet *dhcp, uint8_t option_id, uint8_t suboption_id)
{
	uint8_t *p, opt_len;
	int passed;

	if (dhcp == NULL)
		return NULL;
	if ((p = find_option(dhcp, option_id)) == NULL)
		return NULL;
	opt_len = p[1];
	p += 2;
	passed = find_opt_offset(p, suboption_id, opt_len, 1);

	if (passed < 0)
		return NULL;

	return p + passed;
}

int
insert_option(struct dhcp_packet *dhcp, uint8_t option_id, uint8_t len, uint8_t *option, int flags)
{
	uint8_t *p;
	uint8_t buf[DHCP_OPTION_LEN];
	struct dhcp_packet dhcp_buf;
	uint8_t opt82_len;
	int new_len, old_len, max_opts_len, max_len;

	if (dhcp == NULL)
		return 0;
	max_len = max_packet_size - ETHER_HDR_LEN - DHCP_UDP_OVERHEAD;
	max_opts_len = max_len - DHCP_FIXED_NON_UDP - DHCP_COOKIE_LEN;
	old_len = get_dhcp_len(dhcp);
	if (!old_len)
		return 0;
	memcpy(&dhcp_buf, dhcp, sizeof(struct dhcp_packet));
	if (flags != INSERT_OPTION_STACK && find_option(&dhcp_buf, option_id) != NULL) {
		if (flags == INSERT_OPTION_OVERRIDE)
			remove_option(&dhcp_buf, option_id);
		else {
			logd(LOG_ERR, "insert option: Packet is already have option %d. Passed without changes.", option_id);
			return 0;
		}
	}
	new_len = old_len + 2 + len;
	if (new_len > max_opts_len) {
		logd(LOG_ERR, "Can't add option %d without packet oversizing. Passed without changes.", option_id);
		return 0;
	}
	if (flags != INSERT_OPTION_STACK && (p = find_option(&dhcp_buf, 82)) != NULL) {
		// Option82 must be in the end (RFC 3046)
		opt82_len = p[1];
		memcpy(buf, p + 2, opt82_len);
		*p++ = option_id;
		*p++ = len;
		memcpy(p, option, len);
		// Restore option 82 and option 255
		p += len;
		*p++ = 82;
		*p++ = opt82_len;
		memcpy(p, buf, opt82_len);
		p += opt82_len;
		*p = 255;
	} else {
		p = (uint8_t *)&dhcp_buf + old_len - 1;	// Points to option 255
		*p++ = option_id;
		*p++ = len;
		memcpy(p, option, len);
		p += len;
		*p = 255;
	}
	memcpy(dhcp, &dhcp_buf, sizeof(struct dhcp_packet));
	return 1;
}

int
remove_option(struct dhcp_packet *dhcp, uint8_t option_id)
{
	uint8_t *p, *end;
	uint8_t buf[DHCP_OPTION_LEN];
	int len;

	if ((p = find_option(dhcp, option_id)) == NULL ||
		(end = find_option(dhcp, 255)) == NULL)
		return 0;

	len = end - p + 1;
	len -= p[1] + 2;
	memcpy(buf, p + p[1] + 2, len);
	bzero(p, end - p + 1);
	memcpy(p, buf, len);
	return 1;
}

/* returns actual length of dhcp packet (including dhcp header) or 0 if packet is malformed */
int
get_dhcp_len(struct dhcp_packet *dhcp)
{
	uint8_t *p;

	if ((p = find_option(dhcp, 255)) == NULL)
		return 0;

	return p - ((uint8_t *)dhcp) + 1;
}
