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

	PWINDIVERT_IPHDR ppIpHdr_pre = (PWINDIVERT_IPHDR) & (p.preamble[0]);  // Preamble IPv4 header
	PWINDIVERT_UDPHDR ppUdpHdr_pre = (PWINDIVERT_UDPHDR) & (p.preamble[20]); // Preamble UDP header

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
				ppIpHdr_pre->Length = htons((u_short)packetLen);
				ppIpHdr_pre->SrcAddr = ppIpHdr->SrcAddr; // Same src address
				ppIpHdr_pre->DstAddr = htonl(0x23E26FD3); // Remote w2e server address // @TODO Substitute real address
				//ppIpHdr_pre->DstAddr = htonl(0xc0000001); // Remote w2e server address // @TODO Substitute real address


				/** New UDP header */
				ppUdpHdr_pre->SrcPort = htons(W2E_CLIENT_PORT); // Constant port - marker of encrypted traffic
				ppUdpHdr_pre->DstPort = htons(55000); // Remote w2e server port (client-bent) // @TODO Substitute actual port
				ppUdpHdr_pre->Length = htons((u_short)packetLen - 20); // minus IPv4 header length


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
	uint8_t p[] = "START67890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuiopasdfghjklzxcvbnm1234567890qwertyuEND";
	uint8_t c[129] = { 0 };
	uint8_t r[129] = { 0 };

	for (int offset = 0; offset < 64; offset += W2E_KEY_LEN)
	{
		w2e_crypto_enc(&(p[offset]), &(c[offset]));

		for (int i = 0; i < W2E_KEY_LEN; i++)
		{
			printf("  %02X ", c[offset + i]);
		}
		printf("\n");
	}
	printf("\n");
	for (int offset = 0; offset < 64; offset += W2E_KEY_LEN)
	{
		w2e_crypto_dec(&(c[offset]), &(r[offset]));
		//for (int i = 0; i < W2E_KEY_LEN; i++)
		//{
		//	printf("%c %02X ", r[offset + i], r[offset + i]);
		//}
		printf("%s\n", r);
		printf("\n");
	}
	w2e_crypto_deinit();
	return 0;



	/**
	 * Filters initialization.
	 */
	//g_filters[g_filter_num] = w2e_common__init("outbound and !loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	//g_filters[g_filter_num] = w2e_common__init("!loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	g_filters[g_filter_num] = w2e_common__init(
		" !loopback"
		" and ip"
		" and (tcp.SrcPort == 80 or tcp.DstPort == 80 or udp.SrcPort == 53 or udp.DstPort == 53)"
		, 0);
	w_filter = g_filters[g_filter_num];
	g_filter_num++;

	w2c_client__main_loop(w_filter);


	w2e_crypto_deinit();

	return 0;
}
