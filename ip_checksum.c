/* NETWORKCS MAKES NO WARRANTIES OR REPRESENTATIONS, EXPRESS OR IMPLIED,
 * INCLUDING, BUT NOT LIMITED TO, IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE, AS TO ANY ELEMENT OF THE SOFTWARE OR ANY
 * SUPPORT PROVIDED IN CONNECTION WITH THIS SOFTWARE. In no event shall
 * NetworkCS be responsible for any damages, including but not limited to
 * consequential damages, arising from or relating to any use of the Software
 * or related support.
 * 
 * Copyright 1994-1998 Network Computing Services, Inc.
 * 
 * Copies of this Software may be made, however, the above copyright notice must
 * be reproduced on all copies. */

#include <arpa/inet.h>
#include "dhcprelya.h"

/* User Space Library Functions ----------------------------
 * 
 * IP checksum computation
 * 
 */

/* Compute an IP checksum
 * 
 * This code was taken from RFC 1071.
 * 
 * "The following "C" code algorithm computes the checksum with an inner loop
 * that sums 16 bits at a time in a 32-bit accumulator."
 * 
 * Arguments: addr	pointer to the buffer whose checksum is to be computed count
 * number of bytes to include in the checksum
 * 
 * Returns: the computed checksum
 * 
 */
short
inet_checksum(const char *addr, int count, long pseudosum)
{
	/* Compute Internet Checksum for "count" bytes beginning at location
	 * "addr". */
	long sum = pseudosum;

	while (count > 1) {
		/* This is the inner loop */
		sum += ntohs(*(const unsigned short *)(const void *)addr);
		addr += sizeof(unsigned short);
		count -= sizeof(unsigned short);
	}

	/* Add left-over byte, if any */
	if (count > 0)
		sum += *(const unsigned char *)addr << 8;

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ((short)~sum);
}

/* Cempute UDP checksum.
 * It contains a pseudo-header:
 *	src_ip, dst_ip, protocol number and UDP payload length
 * and payload.
 */
short
udp_checksum(const char *addr)
{
	size_t i;
	long pseudosum = 0;
	struct packet_headers *hdr = (struct packet_headers*) addr;
	union {
		uint32_t l32[3];
		uint16_t l16[6];
	} pseudo_udp;

	pseudo_udp.l32[0] = hdr->ip.ip_src.s_addr;
	pseudo_udp.l32[1] = hdr->ip.ip_dst.s_addr;
	pseudo_udp.l32[2] = (IPPROTO_UDP << 8) | hdr->udp.uh_ulen << 16;
	for(i = 0; i < 6; i++)
		pseudosum += htons(pseudo_udp.l16[i]);

	return inet_checksum((const char *) &hdr->udp, htons(hdr->udp.uh_ulen), pseudosum);
}

/* IP checksum computes only IP header fields.
 */
short
ip_checksum(const char *addr, int count)
{
	return inet_checksum(addr, count, 0);
}
