/*****************************************************************//**
 * \file   w2e_server.c
 * \brief  W2E server application (Linux)
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#include "w2e_server.h"


/**
 * Global counters.
 */
w2e_ctrs_t w2e_ctrs = { 0 };

/**
 * TX socket.
 */
int sock_tx = -1;

/**
 * NFQUEUE.
 */
static struct nfq_handle* h = NULL;
static struct nfq_q_handle* qh = NULL;

/**
 * Send buffer.
 */
static unsigned char pkt1[W2E_MAX_PACKET_SIZE] = { 0 };

static volatile uint8_t server_stop = 0;

/**
 * Context.
 */
static struct {
	uint32_t addr; // Client address in host byte order
	uint32_t last_dns_addr; // Last client DNS address in host byte order
} w2e_client_ctxt = { 0 };


static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data)
{
	//u_int32_t id = print_pkt(nfa);
	u_int32_t id;
	struct nfqnl_msg_packet_hdr* ph;
	unsigned char* pkt;
	struct iphdr* hdr_ip, *hdr_pre_ip = pkt1;
	struct udphdr* hdr_udp, *hdr_pre_udp = &(pkt1[20]);
	u_int32_t len_recv;
	u_int32_t len_send;
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { 0 } };

	w2e_ctrs.total_rx++;

	//w2e_dbg_printf("entering callback\n");

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);

	len_recv = nfq_get_payload(nfa, &pkt);
	if (len_recv < 0)
	{
		w2e_print_error("nfq_get_payload() error\n");
		w2e_ctrs.err_rx++;
		w2e_ctrs.total_tx++;
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}


	/**
	 * Packet processing.
	 */
	hdr_ip = pkt;
	if (hdr_ip->version != 4)
	{
		w2e_ctrs.total_tx++;
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	hdr_udp = &(pkt[hdr_ip->ihl * 4]);

	w2e_dbg_printf("payload_len=%d, proto=0x%02X, (0x%04X)\n", len_recv, hdr_ip->protocol, ntohs(hdr_udp->dest));

	if (hdr_ip->protocol == 0x11 // UDP
		&& ntohs(hdr_udp->dest) == W2E_UDP_SERVER_PORT_MARKER
	) /* Decapsulation needed */
	{
		w2e_ctrs.decap++;
		w2e_dbg_printf("Decap\n");

		/**
		 * Get client's IP.
		 */
		w2e_client_ctxt.addr = ntohl(hdr_ip->saddr);

		/**
		 * Decrypt payload.
		 */
		len_send = w2e_crypto_dec_pkt_ipv4(&(pkt[W2E_PREAMBLE_SIZE]), pkt1, len_recv - W2E_PREAMBLE_SIZE);

		/**
		 * Mangle source address.
		 */
		hdr_pre_ip->saddr = htonl(0x0a800002);

		/**
		 * Process DNS (if it is).
		 */
		if (hdr_pre_ip->protocol == 0x11 // UDP
			&& hdr_pre_udp->dest == htons(53) // DNS
		)
		{
			/** Remember client's DNS server address */
			w2e_client_ctxt.last_dns_addr = ntohl(hdr_ip->daddr);
			/** Substitute ours DNS server */
			hdr_pre_ip->saddr = htonl(W2E_DNS);
		}

		/** For send to socket */
		sin.sin_addr.s_addr = ntohl(hdr_pre_ip->daddr);


		/**
		 * Transport Layer CRC of decapsulated packet.
		 */
		if (hdr_pre_ip->protocol == 0x11) // UDP
		{
			nfq_udp_compute_checksum_ipv4(hdr_pre_udp, hdr_pre_ip);
		}
		else if (hdr_pre_ip->protocol == 0x06) // TCP
		{
			nfq_tcp_compute_checksum_ipv4(hdr_pre_udp, hdr_pre_ip);
		}

		/**
		 * Recalculate CRC (IPv4).
		 */
		nfq_ip_set_checksum(hdr_pre_ip);
	}
	else /* Encapsulation needed */
	{
		w2e_ctrs.encap++;
		w2e_dbg_printf("Encap\n");

		/**
		 * Process DNS (if it is).
		 */
		if (hdr_ip->protocol == 0x11 // UDP
			&& hdr_udp->dest == htons(53) // DNS
			)
		{
			/** Substitute client's DNS server back */
			hdr_pre_ip->saddr = htonl(w2e_client_ctxt.last_dns_addr);

			/**
			 * Recalculate CRCs (IPv4 and UDP).
			 */
			nfq_udp_compute_checksum_ipv4(hdr_udp, hdr_ip);
			nfq_ip_set_checksum(hdr_ip);
		}

		/**
		 * Encrypt payload.
		 */
		len_send = w2e_crypto_enc(
			pkt,
			&(pkt1[W2E_PREAMBLE_SIZE]),
			len_recv,
			W2E_MAX_PACKET_SIZE - W2E_PREAMBLE_SIZE);


		/**
		 * Add incapsulation header.
		 */

		 /** IPv4 header */
		memcpy(pkt1, w2e_template_iph, sizeof(w2e_template_iph));
		/** UDP header */
		memset(&(pkt1[sizeof(w2e_template_iph)]), 0, sizeof(w2e_template_udph));
		//memcpy(&(pkt1[sizeof(w2e_template_iph)]), w2e_template_udph, sizeof(w2e_template_udph));


		/** New UDP header */
		hdr_pre_udp->dest = htons(0x8880);
		hdr_pre_udp->source = htons(0x1488);
		hdr_pre_udp->len = htons(len_send + sizeof(w2e_template_udph));


		len_send += W2E_PREAMBLE_SIZE;


		/** New IPv4 header */
		hdr_pre_ip->tot_len = htons((u_short)(len_send));
		hdr_pre_ip->saddr = htonl(/*0x0A00A084*/ 0x0a800002); // My src address
		hdr_pre_ip->daddr = htonl(w2e_client_ctxt.addr); // Remote w2e client address
		//hdr_pre_ip->daddr = htonl(0xb2da7529); // Remote w2e server address // @TODO Substitute real address
		//hdr_pre_ip->SrcAddr = ppIpHdr->SrcAddr; // Same src address
		//hdr_pre_ip->DstAddr = htonl(0xc0000001); // Remote w2e server address // @TODO Substitute real address


		/** For send to socket */
		sin.sin_addr.s_addr = htonl(w2e_client_ctxt.addr);


		/**
		 * Recalculate CRCs (IPv4 and UDP).
		 */
		//hdr_pre_icmp->checksum = htons(calculate_checksum_icmp((unsigned char*)&hdr_pre_icmp, sizeof(hdr_pre_icmp)));
		//hdr_pre_udp->checksum = htons(calculate_checksum_icmp((unsigned char*)&hdr_pre_icmp, sizeof(hdr_pre_icmp)));
		nfq_udp_compute_checksum_ipv4(hdr_pre_udp, hdr_pre_ip);
		nfq_ip_set_checksum(hdr_pre_ip);
	}

	/**
	 * Send modified packet.
	 */
	 w2e_ctrs.total_tx++;
	 w2e_dbg_printf("len= %d\n", len_send);
	 w2e_dbg_dump(len_send, pkt1);


	 if (sendto(sock_tx, pkt1, len_send, 0, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0)
	 {
		 perror("sendto() failed ");
		 exit(EXIT_FAILURE);
	 }


	 /**
	  * Drop original packet.
	  */
	 return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static void w2e_server_deinit()
{
	server_stop = 1;

	w2e_log_printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	w2e_log_printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	w2e_log_printf("closing library handle\n");
	nfq_close(h);

	/**
	 * Crypto lib deinit.
	 */
	w2e_crypto_deinit();

	// Close socket descriptor.
	close(sock_tx);
}

void sig_handler(int n)
{
	(void)n;
	w2e_server_deinit();
}

int main(int argc, char** argv)
{
	int fd;
	int rv;
	int val;
	char buf[W2E_MAX_PACKET_SIZE] __attribute__((aligned));

	w2e_log_printf("Server is starting...\n");

	signal(SIGINT, sig_handler);

	/**
	 * TX raw socket init.
	 */
	sock_tx = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock_tx < 0)
	{
		w2e_print_error("Socket init error\n");
		return 1;
	}

	// Set flag so socket expects us to provide IPv4 header.
	val = 1;
	if (setsockopt(sock_tx, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0)
	{
		w2e_print_error("setsockopt() failed to set IP_HDRINCL\n");
		return 1;
	}
	// Set flag so socket will not discover path MTU.
	val = 0;
	if (setsockopt(sock_tx, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0)
	{
		w2e_print_error("setsockopt() failed to set IP_HDRINCL\n");
		return 1;
	}


	/**
	 * Crypto lib init.
	 */
	w2e_log_printf("crypto lib init\n");
	if (w2e_crypto_init((const u8*)"0000000000000000", W2E_KEY_LEN) != 0)
	{
		w2e_print_error("Crypto init error\n");
		return 1;
	}

	w2e_log_printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		w2e_print_error("error during nfq_open()\n");
		exit(1);
	}

	w2e_log_printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		w2e_print_error("error during nfq_unbind_pf()\n");
		exit(1);
	}

	w2e_log_printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		w2e_print_error("error during nfq_bind_pf()\n");
		exit(1);
	}

	w2e_log_printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh)
	{
		w2e_print_error("error during nfq_create_queue()\n");
		exit(1);
	}

	w2e_log_printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		w2e_print_error("can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	// para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

	while (!server_stop && (rv = recv(fd, buf, sizeof(buf), 0)))
	{
		w2e_dbg_printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	w2e_log_printf("deinit\n");


	return 0;
}

