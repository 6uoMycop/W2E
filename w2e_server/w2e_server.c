/*****************************************************************//**
 * \file   w2e_server.c
 * \brief  W2E server application (Linux)
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#include "w2e_server.h"


#if 0
static u_int32_t print_pkt(struct nfq_data* tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr* ph;
	struct nfqnl_msg_packet_hw* hwph;
	u_int32_t mark, ifi;
	int ret;
	char* data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph)
	{
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
		{
			printf("%02x:", hwph->hw_addr[i]);
		}
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
	{
		printf("mark=%u ", mark);
	}

	ifi = nfq_get_indev(tb);
	if (ifi)
	{
		printf("indev=%u ", ifi);
	}

	ifi = nfq_get_outdev(tb);
	if (ifi)
	{
		printf("outdev=%u ", ifi);
	}
	ifi = nfq_get_physindev(tb);
	if (ifi)
	{
		printf("physindev=%u ", ifi);
	}

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
	{
		printf("physoutdev=%u ", ifi);
	}

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
	{
		printf("payload_len=%d ", ret);
		//processPacketData (data, ret);
	}
	fputc('\n', stdout);

	return id;
}
#endif /* 0 */


/**
 * Global counters.
 */
w2e_ctrs_t w2e_ctrs = { 0 };

static struct nfq_handle* h = NULL;
static struct nfq_q_handle* qh = NULL;

static unsigned char pkt1[W2E_MAX_PACKET_SIZE] = { 0 };


static uint16_t calculate_checksum_icmp(unsigned char* buffer, int bytes)
{
	uint32_t checksum = 0;
	unsigned char* end = buffer + bytes;

	// odd bytes add last byte and reset end
	if (bytes % 2 == 1)
	{
		end = buffer + bytes - 1;
		checksum += (*end) << 8;
	}

	// add words of two bytes, one by one
	while (buffer < end)
	{
		checksum += buffer[0] << 8;
		checksum += buffer[1];
		buffer += 2;
	}

	// add carry if any
	uint32_t carray = checksum >> 16;
	while (carray)
	{
		checksum = (checksum & 0xffff) + carray;
		carray = checksum >> 16;
	}

	// negate it
	checksum = ~checksum;

	return checksum & 0xffff;
}


static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data)
{
	//u_int32_t id = print_pkt(nfa);
	u_int32_t id;
	struct nfqnl_msg_packet_hdr* ph;
	unsigned char* pkt;
	struct pkt_buff* pktb;
	struct iphdr* hdr_ip, *hdr_pre_ip = pkt1;
	struct icmphdr* hdr_icmp, *hdr_pre_icmp = &(pkt1[20]);
	u_int32_t len_recv;
	u_int32_t len_send;

	w2e_ctrs.total_rx++;

	w2e_dbg_printf("entering callback\n");

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);

	len_recv = nfq_get_payload(nfa, &pkt);
	if (len_recv < 0)
	{
		w2e_print_error("nfq_get_payload() error\n");
		w2e_ctrs.err_rx++;
		goto send_unmodified;
	}

	w2e_dbg_printf("payload_len=%d\n", len_recv);

	/**
	 * Packet processing.
	 */
	//pktb = pktb_alloc(AF_INET, data, len_recv, 0);
	//hdr_ip = nfq_ip_get_hdr(pktb);
	hdr_ip = pkt;
	if (hdr_ip->version != 4)
	{
		pktb_free(pktb);
		goto send_unmodified;
	}

	hdr_icmp = &(pkt[hdr_ip->ihl * 4]);

	if (hdr_ip->protocol == 0x01 // ICMP
		&& hdr_icmp->type == W2E_ICMP_TYPE_MARKER
		&& hdr_icmp->code == W2E_ICMP_CODE_MARKER
		&& hdr_icmp->un.gateway == W2E_ICMP_BODY_MARKER
	) /* Decapsulation needed */
	{
		w2e_ctrs.decap++;
		w2e_dbg_printf("Decap\n");

		/**
		 * Decrypt payload.
		 */
		len_send = w2e_crypto_dec_pkt_ipv4(&(pkt[W2E_PREAMBLE_SIZE]), pkt1, len_recv - W2E_PREAMBLE_SIZE);


		/**
		 * Send modified packet.
		 */
		pktb_free(pktb);
		goto send_modified;
	}
	else /* Encapsulation needed */
	{
		w2e_ctrs.encap++;
		w2e_dbg_printf("Encap\n");

		/**
		 * Encrypt payload.
		 */
		len_send = w2e_crypto_enc(
			pkt,
			&(pkt1[W2E_PREAMBLE_SIZE]),
			len_recv,
			W2E_MAX_PACKET_SIZE - W2E_PREAMBLE_SIZE);

		len_send += W2E_PREAMBLE_SIZE;

		/**
		 * Add incapsulation header.
		 */

		 /** IPv4 header */
		memcpy(pkt1, w2e_template_iph, sizeof(w2e_template_iph));
		/** ICMPv4 header */
		memcpy(&(pkt1[sizeof(w2e_template_iph)]), w2e_template_icmph, sizeof(w2e_template_icmph));

		/** New IPv4 header */
		hdr_pre_ip->tot_len = htons((u_short)(len_send));
		hdr_pre_ip->saddr = htonl(/*0x0A00A084*/ 0x0a800002); // My src address
		hdr_pre_ip->daddr = htonl(0xb2da7529); // Remote w2e server address // @TODO Substitute real address
		//hdr_pre_ip->SrcAddr = ppIpHdr->SrcAddr; // Same src address
		//hdr_pre_ip->DstAddr = htonl(0xc0000001); // Remote w2e server address // @TODO Substitute real address

		/**
		 * Recalculate CRCs (IPv4 and ICMP).
		 */
		hdr_pre_icmp->checksum = htons(calculate_checksum_icmp((unsigned char*)&hdr_pre_icmp, sizeof(hdr_pre_icmp)));
		nfq_ip_set_checksum(hdr_pre_ip);

		/**
		 * Send modified packet.
		 */
		pktb_free(pktb);
		goto send_modified;
	}

send_modified:
	w2e_ctrs.total_tx++;
	return nfq_set_verdict(qh, id, NF_ACCEPT, len_send, pkt1);

send_unmodified:
	w2e_ctrs.total_tx++;
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static void w2e_server_deinit()
{
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
	char buf[4096] __attribute__((aligned));

	w2e_log_printf("Server is starting...\n");

	signal(SIGINT, sig_handler);

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

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		w2e_dbg_printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	w2e_log_printf("deinit\n");


	return 0;
}

