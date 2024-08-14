/*****************************************************************//**
 * \file   w2e_client.c
 * \brief  W2E client application (Windows)
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#include "w2e_client.h"


/**
 * Have to be global because they are passed to signal handler.
 */
static HANDLE g_filters[W2E_MAX_FILTERS];
static int g_filter_num = 0;

static volatile uint8_t client_stop = 0;


static HANDLE w2e_common__init(char* filter, UINT64 flags)
{
	LPTSTR errormessage = NULL;
	DWORD errorcode = 0;

	w2e_log_printf("Init...\n");

	filter = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);

	if (filter != INVALID_HANDLE_VALUE)
	{
		w2e_log_printf("Init OK\n");
		return filter;
	}

	errorcode = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorcode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&errormessage, 0, NULL);

	w2e_print_error("Error opening filter: %d %s\n", errorcode, errormessage);

	LocalFree(errormessage);

	if (errorcode == 2)
	{
		w2e_print_error("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
	}
	else if (errorcode == 654)
	{
		w2e_print_error(
			"An incompatible version of the WinDivert driver is currently loaded.\n"
			"Please unload it with the following commands ran as administrator:\n\n"
			"sc stop windivert\n"
			"sc delete windivert\n"
			"sc stop windivert14"
			"sc delete windivert14\n");
	}
	else if (errorcode == 1275)
	{
		w2e_print_error(
			"This error occurs for various reasons, including:\n"
			"the WinDivert driver is blocked by security software; or\n"
			"you are using a virtualization environment that does not support drivers.\n");
	}
	else if (errorcode == 1753)
	{
		w2e_print_error(
			"This error occurs when the Base Filtering Engine service has been disabled.\n"
			"Enable Base Filtering Engine service.\n");
	}
	else if (errorcode == 577)
	{
		w2e_print_error(
			"Could not load driver due to invalid digital signature.\n"
			"Windows Server 2016 systems must have secure boot disabled to be \n"
			"able to load WinDivert driver.\n"
			"Windows 7 systems must be up-to-date or at least have KB3033929 installed.\n"
			"https://www.microsoft.com/en-us/download/details.aspx?id=46078\n\n"
			"WARNING! If you see this error on Windows 7, it means your system is horribly "
			"outdated and SHOULD NOT BE USED TO ACCESS THE INTERNET!\n"
			"Most probably, you don't have security patches installed and anyone in you LAN or "
			"public Wi-Fi network can get full access to your computer (MS17-010 and others).\n"
			"You should install updates IMMEDIATELY.\n");
	}

	return NULL;
}

static int __w2e_common__deinit(HANDLE handle)
{
	if (handle)
	{
		WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
		WinDivertClose(handle);
		return TRUE;
	}
	return FALSE;
}

static void w2e_common__deinit_all(HANDLE* filters, int filter_num)
{
	w2e_log_printf("Deinitialize...\n");
	for (int i = 0; i < filter_num; i++)
	{
		__w2e_common__deinit(filters[i]);
	}
}


static void w2c_client__sigint_handler(int sig)
{
	(void)sig;
	
	client_stop = 1;
	w2e_common__deinit_all(g_filters, g_filter_num);
	printf("Client stop\n");
	exit(EXIT_SUCCESS);
}


static void w2c_client__main_loop(HANDLE w_filter)
{
	static w2e_pkt_t pkt1 = {
		.split = {
			.p_1 = {               //  IPv4 and UDP headers.
				W2E_TEMPLATE_IPH,
				W2E_TEMPLATE_ICMPH
			},
			.p0 = { 0 },
			.p1 = { 0 }
		}
	};
	static w2e_pkt_t pkt2 = {
		.split = {
			.p_1 = {               //  IPv4 and UDP headers.
				W2E_TEMPLATE_IPH,
				W2E_TEMPLATE_ICMPH
			},
			.p0 = { 0 },
			.p1 = { 0 }
		}
	};

	UINT packetLen;
	WINDIVERT_ADDRESS addr;
	PVOID packet_data;
	UINT packet_dataLen;

	PWINDIVERT_IPHDR ppIpHdr;
	PWINDIVERT_IPV6HDR ppIpV6Hdr;
	PWINDIVERT_TCPHDR ppTcpHdr;
	PWINDIVERT_UDPHDR ppUdpHdr;
	PWINDIVERT_ICMPHDR ppIcmpHdr;
	PWINDIVERT_ICMPV6HDR ppIcmpv6Hdr;

	PWINDIVERT_IPHDR ppIpHdr_pre = (PWINDIVERT_IPHDR) & (pkt1.split.p_1[0]);  // Preamble IPv4 header
	PWINDIVERT_ICMPHDR ppIcmpHdr_pre = (PWINDIVERT_ICMPHDR) & (pkt1.split.p_1[20]); // Preamble ICMP header
	//PWINDIVERT_UDPHDR ppUdpHdr_pre = (PWINDIVERT_UDPHDR) & (pkt1.split.p_1[20]); // Preamble UDP header
	int sz_real = 0;

	static enum packet_type_e {
		unknown,
		ipv4_tcp, ipv4_tcp_data, ipv4_udp_data, ipv4_icmp_data,
		ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
	} packet_type;

	w2e_log_printf("Client loop operating\n");

	while (!client_stop)
	{
		//if (WinDivertRecv(w_filter, p.packet, sizeof(p.packet), &packetLen, &addr))
		if (WinDivertRecv(w_filter, recv_pkt, sizeof(recv_pkt), &packetLen, &addr))
		{
			w2e_dbg_printf("Got %s packet, len=%d\n", addr.Outbound ? "outbound" : "inbound", packetLen);

			//should_reinject = 1;
			//should_recalc_checksum = 0;
			//sni_ok = 0;

			ppIpHdr = (PWINDIVERT_IPHDR)NULL;
			ppIpV6Hdr = (PWINDIVERT_IPV6HDR)NULL;
			ppTcpHdr = (PWINDIVERT_TCPHDR)NULL;
			ppUdpHdr = (PWINDIVERT_UDPHDR)NULL;
			ppIcmpHdr = (PWINDIVERT_ICMPHDR)NULL;
			packet_type = unknown;

			// Parse network packet and set it's type
			if (WinDivertHelperParsePacket(
				recv_pkt,
				packetLen,
				&ppIpHdr,
				&ppIpV6Hdr,
				NULL,
				&ppIcmpHdr,
				NULL,
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
					else if (ppIcmpHdr && packet_data)
					{
						w2e_dbg_printf("\tUDP src=%u.%u.%u.%u\tdst=%u.%u.%u.%u\t0x%04X\n",
									   ppIpHdr->SrcAddr & 0xFF,
									   (ppIpHdr->SrcAddr >> 8) & 0xFF,
									   (ppIpHdr->SrcAddr >> 16) & 0xFF,
									   (ppIpHdr->SrcAddr >> 24) & 0xFF,
									   ppIpHdr->DstAddr & 0xFF,
									   (ppIpHdr->DstAddr >> 8) & 0xFF,
									   (ppIpHdr->DstAddr >> 16) & 0xFF,
									   (ppIpHdr->DstAddr >> 24) & 0xFF,
									   ntohl(ppIcmpHdr->Body)
						);

						packet_type = ipv4_icmp_data;
					}
				}
				else if (ppIpV6Hdr)
				{
					w2e_print_error("IPv6 packet processed\n");
					WinDivertSend(w_filter, recv_pkt, packetLen, NULL, &addr);
					continue;
				}
				else
				{
					continue;
				}

				w2e_dbg_printf("packet_type: %d, packet_v4: %d, packet_v6: %d\n", packet_type, packet_v4, packet_v6);

				if (packet_type != ipv4_icmp_data || (packet_type == ipv4_icmp_data && ppIcmpHdr->Body != 0x01020201)) /** Encryption needed */
				{
					/**
					 * Encrypt payload.
					 */
					sz_real = w2e_crypto_enc(recv_pkt, pkt1.split.packet, packetLen, sizeof(recv_pkt));


					/**
					 * Add incapsulation header.
					 */

					 /** New IPv4 header */
					ppIpHdr_pre->Length = htons((u_short)(sz_real + W2E_PREAMBLE_SIZE));
					//ppIpHdr_pre->SrcAddr = ppIpHdr->SrcAddr; // Same src address
					ppIpHdr_pre->SrcAddr = htonl(0x0A00A084); // My src address
					ppIpHdr_pre->DstAddr = htonl(0x23E26FD3); // Remote w2e server address // @TODO Substitute real address
					//ppIpHdr_pre->DstAddr = htonl(0xc0000001); // Remote w2e server address // @TODO Substitute real address


					///** New UDP header */
					//ppUdpHdr_pre->SrcPort = htons(W2E_CLIENT_PORT); // Constant port - marker of encrypted traffic
					//ppUdpHdr_pre->DstPort = htons(55000); // Remote w2e server port (client-bent) // @TODO Substitute actual port
					//ppUdpHdr_pre->Length = htons((u_short)packetLen - 20); // minus IPv4 header length



					/** Recalculate CRCs (IPv4 and ICMP) */
					WinDivertHelperCalcChecksums(
						&pkt1, sz_real + W2E_PREAMBLE_SIZE, &addr,
						(UINT64)0LL);
					//(UINT64)(WINDIVERT_HELPER_NO_UDP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM | WINDIVERT_HELPER_NO_TCP_CHECKSUM)); //(UINT64)0LL);
					//(UINT64)(WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM | WINDIVERT_HELPER_NO_TCP_CHECKSUM)); //(UINT64)0LL);

					/** Send modified packet */
					WinDivertSend(w_filter, &pkt1, sz_real + W2E_PREAMBLE_SIZE, NULL, &addr);
					continue;
				}
				else if (packet_type == ipv4_icmp_data && ppIcmpHdr->Body == 0x01020201) /** Decryption needed */
				{
					/**
					 * Decrypt payload.
					 */
					sz_real = w2e_crypto_dec_pkt_ipv4(&(recv_pkt[W2E_PREAMBLE_SIZE]), pkt1.split.packet, packetLen - W2E_PREAMBLE_SIZE);

					/** Recalculate CRCs (IPv4 and ICMP) */
					//WinDivertHelperCalcChecksums(
					//	&p, sz_real + W2E_PREAMBLE_SIZE, &addr,
					//	(UINT64)0LL);

					/** Send modified packet */
					WinDivertSend(w_filter, pkt1.split.packet, sz_real, NULL, &addr);
					continue;
				}

				/** Send packet */
				WinDivertSend(w_filter, &recv_pkt, packetLen, NULL, &addr);
			}
			else
			{
				w2e_print_error("Error parsing packet!\n");
			}
		}
	}
}


/**
 * W2E Client main.
 */
int main(int argc, char* argv[])
{
	(void)argc;
	(void)argv;

	HANDLE w_filter = NULL;

	w2e_log_printf("Client is starting...\n");

	signal(SIGINT, w2c_client__sigint_handler);

	/**
	 * Crypto lib init.
	 */

	if (w2e_crypto_init((const u8*)"0000000000000000", W2E_KEY_LEN) != 0)
	{
		w2e_print_error("Crypto init error\n");
		return 1;
	}

#if 0
	//uint8_t p[] = "STARTqwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm123END";
	//uint8_t p[] = "STARTqwertyuiopasdfghjklzxcvbnm1234567890END";
	uint8_t c[] = {
  0x13, 0x7b, 0x92, 0x41,
  0xc4, 0x24, 0x26, 0x4d, 0x52, 0xd2, 0x81, 0x4e,
  0x7d, 0x1a, 0x30, 0xff, 0x7c, 0x82, 0x49, 0xc2,
  0x8f, 0xbd, 0xb2, 0x3e, 0x4f, 0x38, 0x9a, 0xc9,
  0xad, 0x0c, 0xc4, 0xdb, 0x07, 0x3a, 0x49, 0xea,
  0xc8, 0x6b, 0xe2, 0xfe, 0x16, 0xa5, 0xd6, 0xd9,
  0x41, 0x16, 0x87, 0x3f, 0x52, 0x95, 0x09, 0x6e,
  0xbc, 0x4e, 0x6f, 0x7b, 0x4f, 0x1c, 0x4a, 0x2e,
  0x31, 0xb6, 0xec, 0x22, 0x25, 0x26, 0xd4, 0x60,
  0x80, 0x35, 0xd9, 0x19, 0x6c, 0x2d, 0xd4, 0xc7,
  0xcf, 0x3d, 0x27, 0xfd
	};
	//uint8_t c[129] = { 0 };
	uint8_t r[129] = { 0 };

	//for (int i = 0; i < sizeof(p); i++)
	//{
	//	printf("%02X ", p[i]);
	//}
	//printf("\n\n");

	//int sz = w2e_crypto_enc(p, c, sizeof(p), sizeof(c));
	int sz = 80;

	for (int i = 0; i < sizeof(c); i++)
	{
		printf("%02X ", c[i]);
	}
	printf("\n\n");
	w2e_crypto_dec(c, r, sz);
	for (int i = 0; i < sizeof(r); i++)
	{
		printf("%02X ", r[i]);
	}
	printf("\n\n");
	printf("%s\n", r);
	printf("\n\n");
	w2e_crypto_deinit();
	return 0;
#endif /* 0 */


	/**
	 * Filters initialization.
	 */
	 //g_filters[g_filter_num] = w2e_common__init("outbound and !loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	 //g_filters[g_filter_num] = w2e_common__init("!loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	g_filters[g_filter_num] = w2e_common__init(
		" !loopback"
		" and ip"
		" and (icmp)"
		//" and (tcp.SrcPort == 80 or tcp.DstPort == 80 or udp.SrcPort == 53 or udp.DstPort == 53 or icmp)"
		, 0);
	w_filter = g_filters[g_filter_num];
	g_filter_num++;

	w2c_client__main_loop(w_filter);


	/**
	 * Crypto lib deinit.
	 */
	w2e_crypto_deinit();

	return 0;
}
