/*****************************************************************//**
 * \file   w2e_server.c
 * \brief  W2E server application (Linux)
 *
 * \author 6uoMycop
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
w2e_cfg_server_ctx_t w2e_ctx = { 0 };


/**
 * INI config parser.
 */
static int __w2e_server__ini_handler(void* cfg, const char* section, const char* name, const char* value)
{
	w2e_cfg_server_ctx_t* pconfig = (w2e_cfg_server_ctx_t*)cfg;

	unsigned int tmp_len = 0;

	static uint16_t tmp_id = 0; /** TODO test it // Saves last client's ID */

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)
	if (MATCH("client", "id"))
	{
		tmp_id = atoi(value);
		if (tmp_id > 0xFF)
		{
			w2e_print_error("INI: [client] id: value must be in (0-255). Given %s\n", value);
			return 0;
		}
		if (pconfig->client_ctx[tmp_id].is_configured)
		{
			w2e_print_error("INI: [client] id: Client ID %s duplicates in configuration file\n", value);
			return 0;
		}

		/** Client configured */
		pconfig->client_ctx[tmp_id].is_configured = 1;
		/** Port number calculation */
		pconfig->client_ctx[tmp_id].port = htons(W2E_CLIENT_PORT_HB | tmp_id);

		w2e_log_printf("\tINI: [client] id: %s (Port in net order: 0x%04X)\n", value, pconfig->client_ctx[tmp_id].port);
	}
	else if (MATCH("client", "key"))
	{
		tmp_len = strlen(value) - 1;
		if (tmp_len != W2E_KEY_LEN)
		{
			w2e_print_error("INI: [client] key: wrong key length (%d). Must be %d\n", tmp_len, W2E_KEY_LEN);
		}
		memcpy(pconfig->client_ctx[tmp_id].key, value, W2E_KEY_LEN);

		w2e_log_printf("\tINI: [client] key: id %d, key %s\n", tmp_id, value);
	}
	else if (MATCH("server", "ip"))
	{
		if (inet_pton(AF_INET, value, &(pconfig->ip_server)) != 1)
		{
			w2e_print_error("INI: [server] ip: wrong IP %s\n", value);
			return 0;
		}

		w2e_log_printf("\tINI: [server] ip: %s (Net order 0x%08X)\n", value, pconfig->ip_server);
	}
	else if (MATCH("server", "dns"))
	{
		tmp_len = strlen(value);
		if (tmp_len == 0)
		{
			pconfig->ip_dns = 0;
		}
		else if (inet_pton(AF_INET, value, &(pconfig->ip_dns)) != 1)
		{
			w2e_print_error("INI: [server] dns: wrong IP %s\n", value);
			return 0;
		}

		w2e_log_printf("\tINI: [server] dns: %s (Net order 0x%08X)\n", tmp_len ? value : "COPY SAME", pconfig->ip_dns);
	}
	else
	{
		w2e_print_error("INI: unknown section/name, error\n");
		return 0;
	}
#undef MATCH
	return 1;
}


static int __w2e_server__cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data)
{
	//u_int32_t id = print_pkt(nfa);
	u_int32_t id;
	struct nfqnl_msg_packet_hdr* ph;
	unsigned char* pkt;
	struct iphdr* hdr_ip, *hdr_pre_ip = pkt1, *hdr_dec_ip = pkt1;
	struct udphdr* hdr_udp, *hdr_pre_udp = &(pkt1[20]), *hdr_dec_udp;
	u_int32_t len_recv;
	u_int32_t len_send;
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { 0 } };
	uint16_t id_client = 0;
	w2e_ct_entry_t* ct = NULL;

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
		 * Calculate client's id (lower port byte).
		 */
		id_client = ntohs(hdr_udp->source) & (uint16_t)(0x00FF);
		w2e_dbg_printf("id_client=%d (0x%04X)\n", id_client, ntohs(hdr_udp->source) & (uint16_t)(0xFF00));
		if (ntohs(hdr_udp->source) & (uint16_t)(0xFF00) != W2E_CLIENT_PORT_HB)
		{
			w2e_dbg_printf("id_client=%d (0x%04X)\n", id_client, ntohs(hdr_udp->source) & (uint16_t)(0xFF00));
			w2e_print_error("Malformed packet! Client port is 0x%04X, must be 0x%02Xxx\n",
				ntohs(hdr_udp->source), W2E_CLIENT_PORT_HB >> 8);
			w2e_ctrs.err_rx++;
		}

		/**
		 * Get client's IP.
		 */
		w2e_ctx.client_ctx[id_client].ip_client = hdr_ip->saddr;

		/**
		 * Decrypt payload.
		 */
		len_send = w2e_crypto_dec_pkt_ipv4(&(pkt[W2E_PREAMBLE_SIZE]), pkt1, len_recv - W2E_PREAMBLE_SIZE);

		/**
		 * Get decrypted packet's transport header address.
		 */
		hdr_dec_udp = &(pkt1[hdr_ip->ihl * 4]);

		/**
		 * Mangle source address.
		 */
		hdr_dec_ip->saddr = w2e_ctx.ip_server;

		/**
		 * Process DNS (if it is and set in config).
		 */
		if (w2e_ctx.ip_dns)
		{
			if (hdr_dec_ip->protocol == 0x11 // UDP
				&& hdr_dec_udp->dest == htons(53)) // DNS
			{
				w2e_dbg_printf("DNS processing OUT id_client=%d (plain sport=0x%04X)\n", id_client, ntohs(hdr_dec_udp->source));
				/** Remember client's DNS server address */
				w2e_ctx.client_ctx[id_client].ip_dns_last = hdr_dec_ip->daddr;
				/** Substitute ours DNS server */
				hdr_dec_ip->daddr = w2e_ctx.ip_dns;
			}
		}

		/** For send to socket */
		sin.sin_addr.s_addr = ntohl(hdr_dec_ip->daddr);


		/**
		 * Transport Layer CRC of decapsulated packet.
		 */
		if (hdr_dec_ip->protocol == 0x11) // UDP
		{
			nfq_udp_compute_checksum_ipv4(hdr_dec_udp, hdr_dec_ip);
		}
		else if (hdr_dec_ip->protocol == 0x06) // TCP
		{
			nfq_tcp_compute_checksum_ipv4(hdr_dec_udp, hdr_dec_ip);
		}

		/**
		 * Recalculate CRC (IPv4).
		 */
		nfq_ip_set_checksum(hdr_dec_ip);

		/**
		 * Create conntrack entry.
		 */
		w2e_conntrack__create(hdr_dec_ip, hdr_dec_udp, id_client);

		/** Send */
		goto send_modified;
	}
	else /* Encapsulation needed */
	{
		w2e_ctrs.encap++;
		w2e_dbg_printf("Encap\n");

		/**
		 * Get client's id from conntrack entry.
		 */
		ct = w2e_conntrack__resolve(hdr_ip, hdr_udp);
		if (!ct) /** Not resolved */
		{
			goto send_original;
		}
		id_client = ct->id_client;

		/**
		 * Substitute client's plain IP back.
		 */
		hdr_ip->daddr = w2e_ctx.client_ctx[id_client].ip_client;

		/**
		 * Process DNS (if it is and set in config).
		 */
		if (w2e_ctx.ip_dns)
		{
			if (hdr_ip->protocol == 0x11 // UDP
				&& hdr_udp->source == htons(53)) // DNS
			{
				w2e_dbg_printf("DNS processing IN id_client=%d (plain sport=0x%04X)\n", id_client, ntohs(hdr_udp->source));

				/** Substitute client's DNS server back */
				hdr_ip->saddr = w2e_ctx.client_ctx[id_client].ip_dns_last;

				/**
				 * Recalculate CRCs (IPv4 and UDP).
				 */
				nfq_udp_compute_checksum_ipv4(hdr_udp, hdr_ip);
				nfq_ip_set_checksum(hdr_ip);
			}
		}

		w2e_dbg_printf("len recv= %d\n", len_recv);
		w2e_dbg_dump(len_recv, pkt);

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


		/**
		 * New UDP header.
		 */
		/** Client's port */
		hdr_pre_udp->dest = htons(W2E_CLIENT_PORT_HB | id_client);
		//hdr_pre_udp->dest = htons(0x8880);

		/** Server's port */
		hdr_pre_udp->source = htons(W2E_UDP_SERVER_PORT_MARKER);

		/** Datagram length */
		hdr_pre_udp->len = htons(len_send + sizeof(w2e_template_udph));


		len_send += W2E_PREAMBLE_SIZE;


		/** New IPv4 header */
		hdr_pre_ip->tot_len = htons((u_short)(len_send));
		/** Server src address */
		hdr_pre_ip->saddr = w2e_ctx.ip_server;
		/** Remote w2e client address */
		hdr_pre_ip->daddr = w2e_ctx.client_ctx[id_client].ip_client;
		//hdr_pre_ip->saddr = htonl(/*0x0A00A084*/ 0x0a800002); // My src address
		//hdr_pre_ip->daddr = htonl(0xb2da7529); // Remote w2e server address // @TODO Substitute real address
		//hdr_pre_ip->SrcAddr = ppIpHdr->SrcAddr; // Same src address
		//hdr_pre_ip->DstAddr = htonl(0xc0000001); // Remote w2e server address // @TODO Substitute real address


		/** For send to socket -- destination address */
		sin.sin_addr.s_addr = ntohl(w2e_ctx.client_ctx[id_client].ip_client);
		//sin.sin_addr.s_addr = htonl(w2e_client_ctxt.addr);


		/**
		 * Recalculate CRCs (IPv4 and UDP).
		 */
		//hdr_pre_icmp->checksum = htons(calculate_checksum_icmp((unsigned char*)&hdr_pre_icmp, sizeof(hdr_pre_icmp)));
		//hdr_pre_udp->checksum = htons(calculate_checksum_icmp((unsigned char*)&hdr_pre_icmp, sizeof(hdr_pre_icmp)));
		nfq_udp_compute_checksum_ipv4(hdr_pre_udp, hdr_pre_ip);
		nfq_ip_set_checksum(hdr_pre_ip);

		/** Send */
		goto send_modified;
	}



	/**
	 * Send original packet.
	 */
 send_original:
	w2e_ctrs.total_tx++;
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);


	/**
	 * Send modified packet.
	 */
send_modified:
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

	/**
	 * Conntrack deinit.
	 */
	w2e_log_printf("Conntrack deinit\n");
	if (w2e_conntrack__deinit() != 0)
	{
		w2e_print_error("Conntrack deinit error\n");
	}

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
	const char ini_default[] = W2E_INI_DEFAULT_NAME;
	const char* ini_fname = ini_default;

	w2e_log_printf("Server is starting...\n");

	signal(SIGINT, sig_handler);

	/**
	 * Conntrack init.
	 */
	if (w2e_conntrack__init() != 0)
	{
		w2e_print_error("Conntrack init error\n");
		return 1;
	}

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
	 * INI parser.
	 */
	if (argc > 1)
	{
		ini_fname = argv[1];
	}
	w2e_log_printf("INI: Reading config file %s...\n", ini_fname);
	if (ini_parse(ini_fname, __w2e_server__ini_handler, &w2e_ctx) != 0)
	{
		w2e_print_error("INI: Error in file %s\n", ini_fname);
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
	qh = nfq_create_queue(h, 0, &__w2e_server__cb, NULL);
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
