/*****************************************************************//**
 * \file   w2e_client.h
 * \brief  W2E client application (Windows)
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_CLIENT_H
#define __W2E_CLIENT_H


#include <signal.h>

#include "w2e_common.h"
#include "w2e_crypto.h"
#include "windivert.h"


#ifndef W2E_CLIENT_PORT
/**
 * Client's UDP source port.
 */
#define W2E_CLIENT_PORT 55888
#endif // !W2E_CLIENT_PORT

typedef struct {
	UINT					len_total;
	UINT					len_data;

	WINDIVERT_ADDRESS		addr;

	w2e_pkt_t*				pkt;

	PWINDIVERT_IPHDR		hdr_ip;
	PWINDIVERT_IPV6HDR		hdr_ipv6;

	PWINDIVERT_ICMPHDR		hdr_icmp;
	PWINDIVERT_ICMPV6HDR	hdr_icmpv6;

	PWINDIVERT_TCPHDR		hdr_tcp;
	PWINDIVERT_UDPHDR		hdr_udp;

	PVOID					data;
} w2e_client_ctx_t;



#endif // __W2E_CLIENT_H
