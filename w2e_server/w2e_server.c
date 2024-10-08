﻿/*****************************************************************//**
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
static w2e_ctrs_t w2e_ctrs = { 0 };

/**
 * TX raw socket.
 */
static int sock_tx = -1;

/**
 * NFQUEUE.
 */
static struct nfq_handle* h = NULL;
static struct nfq_q_handle* qh = NULL;
static int fd;

/**
 * Send buffer.
 */
static unsigned char pkt1[W2E_MAX_PACKET_SIZE] = { 0 };

static volatile sig_atomic_t server_stop = 0;

/**
 * Context.
 */
static w2e_cfg_server_ctx_t w2e_ctx = { 0 };

/**
 * INI config parser.
 */
static int __w2e_server__ini_handler(void* cfg, const char* section, const char* name, const char* value)
{
	w2e_cfg_server_ctx_t* pconfig = (w2e_cfg_server_ctx_t*)cfg;

	unsigned int tmp_len = 0;

	static uint8_t tmp_id = 0; /** TODO test it // Saves last client's ID */

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)
	if (MATCH("client", "id"))
	{
		tmp_id = atoi(value);
		if (pconfig->client_ctx[tmp_id].is_configured)
		{
			w2e_print_error("INI: [client] id: Client ID %s duplicates in configuration file\n", value);
			return 0;
		}

		/** Client configured */
		pconfig->client_ctx[tmp_id].is_configured = 1;
		/** Port number calculation */
		pconfig->client_ctx[tmp_id].id = tmp_id;

		w2e_log_printf("\tINI: [client] id: %s (0x%02X)\n", value, pconfig->client_ctx[tmp_id].id);
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


/**
 * Packet processing point.
 */
static int __w2e_server__cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data)
{
	u_int32_t						id;
	struct nfqnl_msg_packet_hdr		*ph;
	unsigned char					*pkt;
	struct iphdr					*hdr_ip,  *hdr_pre_ip = (struct iphdr*)pkt1,          *hdr_dec_ip = (struct iphdr*)pkt1;
	struct udphdr					*hdr_udp, *hdr_pre_udp = (struct udphdr*)&(pkt1[20]), *hdr_dec_udp;
	int								len_recv;
	int								len_send;
	struct sockaddr_in				sin = { .sin_family = AF_INET, .sin_port = 0, .sin_addr = { 0 } };
	uint16_t						id_client = 0;
	w2e_ct_entry_t					*ct = NULL;

	(void)nfmsg;
	(void)data;

	w2e_ctrs.total_rx++;

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
	hdr_ip = (struct iphdr*)pkt;
	if (hdr_ip->version != 4)
	{
		w2e_ctrs.total_tx++;
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	hdr_udp = (struct udphdr*)&(pkt[hdr_ip->ihl * 4]);

	/**
	 * Decapsulation needed.
	 */
	if (hdr_ip->protocol == 0x11 /** UDP */
		&& (ntohs(hdr_udp->dest) & (uint16_t)(0xFF00)) == W2E_SERVER_PORT_HB
	)
	{
		w2e_ctrs.decap++;
		w2e_dbg_printf("Decap\n");

		/**
		 * Calculate client's id (lower dst port byte).
		 */
		id_client = ntohs(hdr_udp->dest) & (uint16_t)(0x00FF);
		//w2e_dbg_printf("id_client=%d (0x%04X) 0x%08X\n", id_client, ntohs(hdr_udp->dest) & (uint16_t)(0xFF00), hdr_ip->saddr);
		if (!w2e_ctx.client_ctx[id_client].is_configured) /** Client not configured - drop */
		{
			w2e_print_error("Malformed packet! Client port 0x%04X, not configured. Drop\n", ntohs(hdr_udp->source));
			w2e_ctrs.err_rx++;
			goto drop;
		}

		/**
		 * Get clients src port.
		 */
		w2e_ctx.client_ctx[id_client].port_client = hdr_udp->source;

		/**
		 * Get client's IP.
		 */
		w2e_ctx.client_ctx[id_client].ip_client = hdr_ip->saddr;

		/**
		 * Decrypt payload.
		 */
		len_send = w2e_crypto__dec_pkt_ipv4(
			&(pkt[W2E_PREAMBLE_SIZE]),
			pkt1,
			len_recv - W2E_PREAMBLE_SIZE,
			&(w2e_ctx.client_ctx[id_client].handle));

		/**
		 * Validate.
		 */
		if (!w2e_common__validate_dec(pkt1))
		{
			w2e_print_error("Validation: Malformed packet (possibly wrong key)! Drop. Client port is 0x%04X\n",
							ntohs(hdr_udp->source));
			w2e_ctrs.err_rx++;
			goto drop;
		}

		/**
		 * Get decrypted packet's transport header address.
		 */
		hdr_dec_udp = (struct udphdr*)&(pkt1[hdr_ip->ihl * 4]);

		/**
		 * Mangle source address.
		 */
		hdr_dec_ip->saddr = w2e_ctx.ip_server;

		/**
		 * Process DNS (if it is and set in config).
		 */
		if (w2e_ctx.ip_dns)
		{
			if (hdr_dec_ip->protocol == 0x11 /** UDP */
				&& hdr_dec_udp->dest == htons(53)) /** DNS */
			{
				w2e_dbg_printf("DNS processing OUT id_client=%d (plain sport=0x%04X)\n", id_client, ntohs(hdr_dec_udp->source));
				/** Remember client's DNS server address */
				w2e_ctx.client_ctx[id_client].ip_dns_last = hdr_dec_ip->daddr;
				/** Substitute ours DNS server */
				hdr_dec_ip->daddr = w2e_ctx.ip_dns;
			}
		}

		/** Address for socket send */
		sin.sin_addr.s_addr = ntohl(hdr_dec_ip->daddr);


		/**
		 * Transport Layer CRC of decapsulated packet.
		 */
		if (hdr_dec_ip->protocol == 0x11) /** UDP */
		{
			nfq_udp_compute_checksum_ipv4(hdr_dec_udp, hdr_dec_ip);
		}
		else if (hdr_dec_ip->protocol == 0x06) /** TCP */
		{
			nfq_tcp_compute_checksum_ipv4((struct tcphdr*)hdr_dec_udp, hdr_dec_ip);
		}
		else
		{
			w2e_print_error("WARN: id_client=%d unknown transport protocol 0x%02X)\n", id_client, hdr_dec_ip->protocol);
		}

		/**
		 * Recalculate CRC (IPv4).
		 */
		nfq_ip_set_checksum(hdr_dec_ip);

		/**
		 * Create conntrack entry.
		 */
		w2e_conntrack__create((uint8_t*)hdr_dec_ip, (uint8_t*)hdr_dec_udp, id_client);

		/** Send */
		goto send_modified;
	}
	/**
	 * Encapsulation needed.
	 */
	else
	{
		/**
		 * Get client's id from conntrack entry.
		 */
		ct = w2e_conntrack__resolve((uint8_t*)hdr_ip, (uint8_t*)hdr_udp);
		if (!ct) /** Not resolved */
		{
			goto send_original;
		}
		id_client = ct->id_client;

		w2e_dbg_printf("Encap\n");
		w2e_ctrs.encap++;

		/**
		 * Process DNS (if it is and set in config).
		 */
		if (w2e_ctx.ip_dns)
		{
			if (hdr_ip->protocol == 0x11 /** UDP */
				&& hdr_udp->source == htons(53)) /** DNS */
			{
				w2e_dbg_printf("DNS processing IN id_client=%d (plain sport=0x%04X) 0x%08X\n",
								id_client, ntohs(hdr_udp->source), w2e_ctx.client_ctx[id_client].ip_client);

				/** Substitute client's DNS server back */
				hdr_ip->saddr = w2e_ctx.client_ctx[id_client].ip_dns_last;

				/**
				 * Recalculate CRCs (IPv4 and UDP).
				 */
				nfq_udp_compute_checksum_ipv4(hdr_udp, hdr_ip);
				nfq_ip_set_checksum(hdr_ip);
			}
		}

		//w2e_dbg_printf("len recv= %d\n", len_recv);
		//w2e_dbg_dump(len_recv, pkt);

		/**
		 * Encrypt payload.
		 */
		len_send = w2e_crypto__enc(
			pkt,
			&(pkt1[W2E_PREAMBLE_SIZE]),
			len_recv,
			W2E_MAX_PACKET_SIZE - W2E_PREAMBLE_SIZE,
			&(w2e_ctx.client_ctx[id_client].handle));

		/**
		 * Add incapsulation header.
		 */

		/** IPv4 header */
		memcpy(pkt1, w2e_template_iph, sizeof(w2e_template_iph));
		/** UDP header */
		memset(&(pkt1[sizeof(w2e_template_iph)]), 0, 8);


		/**
		 * New UDP header.
		 */
		/** Client's port */
		hdr_pre_udp->dest = w2e_ctx.client_ctx[id_client].port_client;
		/** Server's port */
		hdr_pre_udp->source = htons(W2E_SERVER_PORT_HB | id_client);
		/** Datagram length */
		hdr_pre_udp->len = htons(len_send + 8);


		len_send += W2E_PREAMBLE_SIZE;


		/**
		 * New IPv4 header.
		 */
		/** Total packet length */
		hdr_pre_ip->tot_len = htons((u_short)(len_send));
		/** Server src address */
		hdr_pre_ip->saddr = w2e_ctx.ip_server;
		/** Remote w2e client address */
		hdr_pre_ip->daddr = w2e_ctx.client_ctx[id_client].ip_client;


		/**
		 * For send to socket -- destination address.
		 */
		sin.sin_addr.s_addr = ntohl(w2e_ctx.client_ctx[id_client].ip_client);


		/**
		 * Recalculate CRCs (IPv4 and UDP).
		 */
		nfq_udp_compute_checksum_ipv4(hdr_pre_udp, hdr_pre_ip);
		nfq_ip_set_checksum(hdr_pre_ip);

		/** Send */
		goto send_modified;
	}


	/**
	 * Send modified packet (then drop original).
	 */
send_modified:
	w2e_dbg_printf("len= %d, daddr= 0x%08X\n", len_send, sin.sin_addr.s_addr);
	w2e_dbg_dump(len_send, pkt1);


	if (sendto(sock_tx, pkt1, len_send, 0, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0)
	{
		w2e_ctrs.err_tx++;
		w2e_print_error("Sendto failed! Length %d. Drop\n", len_send);
		perror("sendto() failed ");
		w2e_dbg_dump(len_send, pkt1);
	}
	else
	{
		w2e_ctrs.total_tx++;
	}

	/**
	 * Drop original packet.
	 */
drop:
	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);

	/**
	 * Send original packet.
	 */
send_original:
	w2e_ctrs.total_tx++;
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static void __w2e_server__deinit()
{
	/** Server already stopped (double signal failure pervention) */
	if (server_stop)
	{
		w2e_print_error("Server is already stopped or being stopped\n");
		return;
	}

	/**
	 * Stop server worker.
	 */
	server_stop = 1;

	/**
	 * Conntrack deinit.
	 */
	w2e_log_printf("Conntrack deinit\n");
	if (w2e_conntrack__deinit() != 0)
	{
		w2e_print_error("Conntrack deinit error\n");
	}

	/**
	 * NFQUEUE deinit.
	 */
	w2e_log_printf("Unbinding from queue\n");
	nfq_destroy_queue(qh);
	w2e_log_printf("Closing library handle\n");
	nfq_close(h);

	/**
	 * Crypto lib deinit.
	 */
	w2e_log_printf("Crypto deinit\n");
	/** For all clients */
	for (int i = 0; i < W2E_MAX_CLIENTS; i++)
	{
		/** If client is configured */
		if (w2e_ctx.client_ctx[i].is_configured)
		{
			/** Denit crypto lib */
			w2e_crypto__deinit(&(w2e_ctx.client_ctx[i].handle));
			/** Zero ctx */
			memset(&(w2e_ctx.client_ctx[i]), 0, sizeof(w2e_cfg_client_ctx_t));
		}
	}

	/**
	 * Close socket descriptor.
	 */
	w2e_log_printf("TX socket close\n");
	close(sock_tx);
}

void __w2e_server__sig_handler(int n)
{
	(void)n;
	__w2e_server__deinit();
}


/**
 * Main recv loop.
 */
static void* __w2e_server__worker_main(void* data)
{
	int		rv;
	char	buf[W2E_MAX_PACKET_SIZE] __attribute__((aligned));
	(void)data;

	w2e_log_printf("worker main start\n");

	while (!server_stop)
	{
		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv >= 0)
		{
			//w2e_dbg_printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
		}
		else
		{
			w2e_print_error("recv() error %s\n", strerror(errno));
		}
	}

	w2e_log_printf("worker main exit\n");
	return NULL;
}


int main(int argc, char** argv)
{
	int			val;
	const char	ini_default[] = W2E_INI_DEFAULT_NAME;
	const char	*ini_fname = ini_default;


	/**
	 * Print art.
	 */
	printf("%s\n\n", w2e_art__combined_sml);

	w2e_log_printf("Server is starting...\n");


	/**
	 * SIGINT handler.
	 */
	signal(SIGINT, __w2e_server__sig_handler);


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
	/** Create socket. */
	sock_tx = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock_tx < 0)
	{
		w2e_print_error("Socket init error\n");
		return 1;
	}
	/** Bind to configured interface //@TODO from config */
	const char* interface_name = "ens4";
	if (setsockopt(sock_tx, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) < 0)
	{
		w2e_print_error("setsockopt() failed SO_BINDTODEVICE %s\n", interface_name);
		return 1;
	}
	////** Set flag so socket expects us to provide IPv4 header. */
	///val = 1;
	///if (setsockopt(sock_tx, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0)
	///{
	///	w2e_print_error("setsockopt() failed to set IP_HDRINCL\n");
	///	return 1;
	///}
	/** Set flag so socket will not discover path MTU. */
	val = 0;
	if (setsockopt(sock_tx, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0)
	{
		w2e_print_error("setsockopt() failed to set IP_HDRINCL\n");
		return 1;
	}
	/** Test if the socket is in blocking mode. */
	if (!(fcntl(sock_tx, F_GETFL) & O_NONBLOCK))
	{
		/** Put the socket in non-blocking mode. */
		if (fcntl(sock_tx, F_SETFL, fcntl(sock_tx, F_GETFL) | O_NONBLOCK) < 0)
		{
			w2e_print_error("fcntl() failed to set O_NONBLOCK\n");
			return 1;
		}
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
	/** For all clients */
	for (int i = 0; i < W2E_MAX_CLIENTS; i++)
	{
		/** If client is configured */
		if (w2e_ctx.client_ctx[i].is_configured)
		{
			/** Init crypto lib with given in INI key */
			if (w2e_crypto__init(
				w2e_ctx.client_ctx[i].key,
				W2E_KEY_LEN,
				&(w2e_ctx.client_ctx[i].handle)) != 0)
			{
				w2e_print_error("Crypto init error\n");
				return 1;
			}
		}
	}


	/**
	 * NFQUEUE init.
	 */

	w2e_log_printf("Opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		w2e_print_error("Error during nfq_open()\n");
		exit(1);
	}

	w2e_log_printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		w2e_print_error("Error during nfq_unbind_pf()\n");
		exit(1);
	}

	w2e_log_printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		w2e_print_error("Error during nfq_bind_pf()\n");
		exit(1);
	}

	w2e_log_printf("Binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &__w2e_server__cb, NULL);
	if (!qh)
	{
		w2e_print_error("Error during nfq_create_queue()\n");
		exit(1);
	}

	w2e_log_printf("Setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		w2e_print_error("Can't set packet_copy mode\n");
		exit(1);
	}

	w2e_log_printf("Setting queue length\n");
	if (nfq_set_queue_maxlen(qh, 0xFFFFFFFF) < 0)
	{
		w2e_print_error("Can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);


	/**
	 * Start.
	 */
	__w2e_server__worker_main(NULL);


	w2e_log_printf("Exiting now\n");


	return 0;
}
