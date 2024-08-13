/*****************************************************************//**
 * \file   w2e_server.c
 * \brief  W2E server application (Linux)
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#include "w2e_server.h"


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


static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data)
{
	u_int32_t id = print_pkt(nfa);
	//u_int32_t id;

	struct nfqnl_msg_packet_hdr* ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
	w2e_dbg_printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char** argv)
{
	struct nfq_handle* h;
	struct nfq_q_handle* qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	w2e_log_printf("Server is starting...\n");

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

	exit(0);
}

