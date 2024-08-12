/*****************************************************************//**
 * \file   w2e_client.c
 * \brief  W2E client application
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#include "w2e_client.h"


/**
 * Have to be global because they are passed to signal handler.
 */
static HANDLE filters[W2E_MAX_FILTERS];
static int filter_num = 0;

static volatile uint8_t client_stop = 0;


static void w2c_client__sigint_handler(int sig)
{
	client_stop = 1;
	w2e_common__deinit_all(filters, filter_num);
	printf("Client stop\n");
	exit(EXIT_SUCCESS);
}

static void w2c_client__main_loop(HANDLE w_filter)
{
	struct {
		uint8_t preamble[W2E_PREAMBLE_SIZE];
		uint8_t packet[W2E_MAX_PACKET_SIZE - W2E_PREAMBLE_SIZE];
	} p = {
		.preamble = {               //  IPv4 and UDP headers. <These> fields will be edited.
			0x45, 0x00, 0x00, 0x00, // |version=4,ihl=5| tos=0  |     <packet size>    |
			0x00, 0x00, 0x40, 0x00, // |           id=0         |R=0,DF=1,MF=0,offset=0|
			0xFF, 0x11, 0x00, 0x00, // |   TTL=255     |proto=17|         <crc>        |
			0x00, 0x00, 0x00, 0x00, // |                    <IP src>                   |
			0x00, 0x00, 0x00, 0x00, // |                    <IP dst>                   |
			0x00, 0x00, 0x00, 0x00, // |      <UDP src>         |       <UDP dst>      |
			0x00, 0x00, 0x00, 0x00  // |      <UDP len>         |       <UDP crc>      |
		},
		.packet = { 0 }
	};

	UINT packetLen;
	WINDIVERT_ADDRESS addr;
	PVOID packet_data;
	UINT packet_dataLen;
	PWINDIVERT_IPHDR ppIpHdr;
	PWINDIVERT_IPV6HDR ppIpV6Hdr;
	PWINDIVERT_TCPHDR ppTcpHdr;
	PWINDIVERT_UDPHDR ppUdpHdr;
	int packet_v4, packet_v6;

	PWINDIVERT_IPHDR ppIpHdr_pre = &(p.preamble[0]);  // Preamble IPv4 header
	PWINDIVERT_UDPHDR ppUdpHdr_pre = &(p.preamble[20]); // Preamble UDP header

	static enum packet_type_e {
		unknown,
		ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
		ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
	} packet_type;

	w2e_log_printf("Client loop operating\n");

	while (!client_stop)
	{
		if (WinDivertRecv(w_filter, p.packet, sizeof(p.packet), &packetLen, &addr))
		{
			w2e_dbg_printf("Got %s packet, len=%d\n", addr.Outbound ? "outbound" : "inbound", packetLen);

			//should_reinject = 1;
			//should_recalc_checksum = 0;
			//sni_ok = 0;

			ppIpHdr = (PWINDIVERT_IPHDR)NULL;
			ppIpV6Hdr = (PWINDIVERT_IPV6HDR)NULL;
			ppTcpHdr = (PWINDIVERT_TCPHDR)NULL;
			ppUdpHdr = (PWINDIVERT_UDPHDR)NULL;
			packet_v4 = packet_v6 = 0;
			packet_type = unknown;

			// Parse network packet and set it's type
			if (WinDivertHelperParsePacket(
				p.packet,
				packetLen,
				&ppIpHdr,
				&ppIpV6Hdr,
				NULL, NULL, NULL,
				&ppTcpHdr,
				&ppUdpHdr,
				&packet_data,
				&packet_dataLen,
				NULL, NULL))
			{
				if (ppIpHdr)
				{
					packet_v4 = 1;
					if (ppTcpHdr)
					{
						w2e_dbg_printf("\tTCP src=%u.%u.%u.%u:%d\tdst=%u.%u.%u.%u:%d\n",
									   ppIpHdr->SrcAddr & 0xFF,
									   (ppIpHdr->SrcAddr >> 8) & 0xFF,
									   (ppIpHdr->SrcAddr >> 16) & 0xFF,
									   (ppIpHdr->SrcAddr >> 24) & 0xFF,
									   ntohs(ppTcpHdr->SrcPort),
									   ppIpHdr->DstAddr & 0xFF,
									   (ppIpHdr->DstAddr >> 8) & 0xFF,
									   (ppIpHdr->DstAddr >> 16) & 0xFF,
									   (ppIpHdr->DstAddr >> 24) & 0xFF,
									   ntohs(ppTcpHdr->DstPort)
						);
						packet_type = ipv4_tcp;
						if (packet_data)
						{
							packet_type = ipv4_tcp_data;
						}
					}
					else if (ppUdpHdr && packet_data)
					{
						w2e_dbg_printf("\tUDP src=%u.%u.%u.%u:%d\tdst=%u.%u.%u.%u:%d\n",
									   ppIpHdr->SrcAddr & 0xFF,
									   (ppIpHdr->SrcAddr >> 8) & 0xFF,
									   (ppIpHdr->SrcAddr >> 16) & 0xFF,
									   (ppIpHdr->SrcAddr >> 24) & 0xFF,
									   ntohs(ppUdpHdr->SrcPort),
									   ppIpHdr->DstAddr & 0xFF,
									   (ppIpHdr->DstAddr >> 8) & 0xFF,
									   (ppIpHdr->DstAddr >> 16) & 0xFF,
									   (ppIpHdr->DstAddr >> 24) & 0xFF,
									   ntohs(ppUdpHdr->DstPort)
						);

						packet_type = ipv4_udp_data;
					}
				}
				else if (ppIpV6Hdr)
				{
					w2e_print_error("IPv6 packet processed\n");
					WinDivertSend(w_filter, p.packet, packetLen, NULL, &addr);
					continue;
				}

				w2e_dbg_printf("packet_type: %d, packet_v4: %d, packet_v6: %d\n", packet_type, packet_v4, packet_v6);

				
				/**
				 * Add incapsulation header.
				 */

				packetLen += W2E_PREAMBLE_SIZE;

				/** New IPv4 header */
				ppIpHdr_pre->Length = htons(packetLen);
				ppIpHdr_pre->SrcAddr = ppIpHdr->SrcAddr; // Same src address
				ppIpHdr_pre->DstAddr = htonl(0xc0000001); // Remote w2e server address // @TODO Substitute real address


				/** New UDP header */
				ppUdpHdr_pre->SrcPort = htons(W2E_CLIENT_PORT); // Constant port - marker of encrypted traffic
				ppUdpHdr_pre->DstPort = htons(55000); // Remote w2e server port (client-bent) // @TODO Substitute actual port
				ppUdpHdr_pre->Length = htons(packetLen - 20); // minus IPv4 header length


				/**
				 * Encrypt payload.
				 */
				//@TODO


				/** Recalculate CRCs (IPv4 and UDP) */
				WinDivertHelperCalcChecksums(
					&p, packetLen, &addr,
					(UINT64)(WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM | WINDIVERT_HELPER_NO_TCP_CHECKSUM)); //(UINT64)0LL);

				/** Send modified packet */
				WinDivertSend(w_filter, &p, packetLen, NULL, &addr);
			}
			else
			{
				// error, ignore
				//if (!exiting)
				w2e_print_error("Error receiving packet!\n");
				break;
			}
		}
	}
}

/**
 * W2E Client main.
 */
int main(int argc, char* argv[])
{
	HANDLE w_filter = NULL;

	w2e_log_printf("Client is starting...\n");

	signal(SIGINT, w2c_client__sigint_handler);

	/**
	 * Filters initialization.
	 */
	//filters[filter_num] = w2e_common__init("outbound and !loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	//filters[filter_num] = w2e_common__init("!loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	filters[filter_num] = w2e_common__init(
		" !loopback"
		" and ip"
		" and (tcp.SrcPort == 80 or tcp.DstPort == 80 or udp.SrcPort == 53 or udp.DstPort == 53)"
		, 0);
	w_filter = filters[filter_num];
	filter_num++;

	w2c_client__main_loop(w_filter);

	return 0;
}
