/*****************************************************************//**
 * \file   w2e_client.c
 * \brief  W2E client application (Windows)
 *
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/


#include "w2e_client.h"


/**
 * Have to be global because they are passed to signal handler.
 */
static HANDLE g_filters[W2E_MAX_FILTERS];
static int g_filter_num = 0;

/** Crypto lib handle */
w2e_crypto__handle_t crypto_handle = { 0 };

static volatile uint8_t client_stop = 0;

/**
 * Global counters.
 */
w2e_ctrs_t w2e_ctrs = { 0 };

/**
 * Config.
 */
w2e_cfg_client_t w2e_cfg_client = { 0 };


/**
 * INI config parser.
 */
static int __w2e_client__ini_handler(void* cfg, const char* section, const char* name, const char* value)
{
	w2e_cfg_client_t* pconfig = (w2e_cfg_client_t*)cfg;

	unsigned int tmp_len = 0;

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)
	if (MATCH("client", "id"))
	{
		pconfig->id = atoi(value);
		if (pconfig->id > 0xFF)
		{
			w2e_print_error("INI: [client] id: value must be in (0-255). Given %s\n", value);
			return 0;
		}
		/** Port number calculation */
		pconfig->port_client = htons(W2E_CLIENT_PORT_HB | pconfig->id);

		w2e_log_printf("\tINI: [client] id: %s (Port in net order: 0x%04X)\n", value, pconfig->port_client);
	}
	else if (MATCH("client", "ip"))
	{
		if (inet_pton(AF_INET, value, &(pconfig->ip_client)) != 1)
		{
			w2e_print_error("INI: [client] ip: wrong IP %s\n", value);
			return 0;
		}

		w2e_log_printf("\tINI: [client] ip: %s (Net order 0x%08X)\n", value, pconfig->ip_server);
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
	else if (MATCH("client", "key"))
	{
		tmp_len = strlen(value) - 1;
		if (tmp_len != W2E_KEY_LEN)
		{
			w2e_print_error("INI: [client] key: wrong key length (%d). Must be %d\n", tmp_len, W2E_KEY_LEN);
		}
		memcpy(pconfig->key, value, W2E_KEY_LEN);

		w2e_log_printf("\tINI: [client] key: %s\n", value);
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
 * WinDivert initialization.
 */
static HANDLE __w2e_client__init(char* filter, UINT64 flags)
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


/**
 * WinDivert deinitialization.
 */
static int __w2e_client__deinit(HANDLE handle)
{
	if (handle)
	{
		WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
		WinDivertClose(handle);
		return TRUE;
	}
	return FALSE;
}


/**
 * WinDivert deinitialization of all filters.
 */
static void __w2e_client__deinit_all(HANDLE* filters, int filter_num)
{
	w2e_log_printf("Deinitialize...\n");
	for (int i = 0; i < filter_num; i++)
	{
		__w2e_client__deinit(filters[i]);
	}
}


/**
 * SIGINT handler.
 */
static void __w2c_client__sigint_handler(int sig)
{
	(void)sig;
	
	client_stop = 1;
	__w2e_client__deinit_all(g_filters, g_filter_num);
	w2e_crypto__deinit(&crypto_handle);
	printf("Client stop\n");
	exit(EXIT_SUCCESS);
}


/**
 * Send WinDivert packet.
 */
static BOOL __w2e_client__pkt_send(HANDLE handle, const VOID* pPacket, UINT packetLen, UINT* pSendLen, const WINDIVERT_ADDRESS* pAddr)
{
	DWORD errorcode = 0;

	w2e_ctrs.total_tx++; /* Send attempted */

	if (WinDivertSend(handle, pPacket, packetLen, pSendLen, pAddr))
	{
		w2e_ctrs.ok_tx++; /* Send success */
	}
	else
	{
		errorcode = GetLastError();
		w2e_print_error("Error sending unmodified packet! 0x%X\n", errorcode);
		w2e_ctrs.err_tx++;

		switch (errorcode)
		{
		case 1232:
		{
			w2e_print_error(
				"ERROR_HOST_UNREACHABLE: This error occurs when an impostor packet "
				"(with pAddr->Impostor set to 1) is injected and the ip.TTL or ipv6. "
				"HopLimit field goes to zero. This is a defense of \"last resort\" against "
				"infinite loops caused by impostor packets. \n");
			break;
		}
		default:
		{
			w2e_print_error("Unexpected error 0x%X\n", errorcode);
			break;
		}
		}
		return FALSE;
	}

	return TRUE;
}


/**
 * Mangle MSS in TCP segment. Returns 0 on success.
 */
static inline int __w2c_client__tcp_set_mss(PWINDIVERT_TCPHDR hdr_tcp, uint16_t value)
{
	uint8_t* p = (uint8_t*)hdr_tcp + 20; /** Options start here */
	uint8_t* end = (uint8_t*)hdr_tcp + hdr_tcp->HdrLength * 4; /** Options end here */
	uint8_t size, kind;

	while (p < end)
	{
		kind = *p++;
		if (kind == 0) /** End of the Options List */
		{
			w2e_log_printf("MSS: End of the Options List\n");
			return 1;
		}
		if (kind == 1) /** NOP */
		{
			continue;
		}
		size = *p++;
		if (kind == 2) /** MSS */
		{
			w2e_dbg_printf("MSS: Changing MSS from %d to %d\n", ntohs(*(uint16_t*)p), value);
			*(uint16_t*)p = htons(value);
			return 0;
		}
		p += (size - 2);
	}

	w2e_log_printf("MSS: Not found MSS\n");
	return 1;
}


/**
 * Client's main packet processing loop.
 */
static void __w2c_client__main_loop(HANDLE w_filter)
{
	DWORD					errorcode = 0;

	UINT					len_recv;
	UINT					len_send;

	WINDIVERT_ADDRESS		addr;
	UINT8					proto;

	PWINDIVERT_IPHDR		hdr_ip;
	PWINDIVERT_UDPHDR		hdr_udp;
	PWINDIVERT_TCPHDR		hdr_tcp;

	PVOID					data;
	UINT					len_data;

	static uint8_t			pkt[2][W2E_MAX_PACKET_SIZE] = { 0 };

	PWINDIVERT_IPHDR		hdr_pre_ip		= (PWINDIVERT_IPHDR)	& (pkt[1][0]);  // Preamble IPv4 header
	PWINDIVERT_UDPHDR		hdr_pre_udp		= (PWINDIVERT_UDPHDR)	& (pkt[1][20]); // Preamble UDP header //@TODO recalculate from IHL on every decap

	w2e_log_printf("Client loop operating\n");

	while (!client_stop)
	{
		/**
		 * Receive packet.
		 */
		if (WinDivertRecv(w_filter, pkt[0], sizeof(pkt[0]), &len_recv, &addr))
		{
			//w2e_dbg_printf("Got %s packet, len=%d\n", addr.Outbound ? "outbound" : "inbound", len_recv);
			w2e_ctrs.total_rx++; /* RX succeeded */

			hdr_ip			= (PWINDIVERT_IPHDR)NULL;
			hdr_udp			= (PWINDIVERT_UDPHDR)NULL;
			hdr_tcp			= (PWINDIVERT_TCPHDR)NULL;

			/**
			 * Parse packet.
			 */
			if (WinDivertHelperParsePacket(
				pkt[0],
				len_recv,
				&hdr_ip,
				NULL, //&hdr_ipv6,
				&proto,
				NULL, //&hdr_icmp,
				NULL, //&hdr_icmpv6,
				&hdr_tcp,
				&hdr_udp,
				&data,
				&len_data,
				NULL,
				NULL))
			{
				w2e_ctrs.ok_rx++;

				if (hdr_ip)
				{
					if (hdr_udp && data && !addr.Outbound && hdr_udp->SrcPort == htons(W2E_UDP_SERVER_PORT_MARKER)) /* Inbound UDP with marker */
					{ /* Decapsulation needed */
						w2e_dbg_printf("DEcap Got %s packet, len=%d\n", addr.Outbound ? "outbound" : "inbound", len_recv); w2e_dbg_printf("Got %s packet, len=%d\n", addr.Outbound ? "outbound" : "inbound", len_recv);
						w2e_ctrs.decap++;

						/**
						 * Decrypt payload.
						 */
						len_send = w2e_crypto__dec_pkt_ipv4(
							&(pkt[0][W2E_PREAMBLE_SIZE]),
							pkt[1],
							len_recv - W2E_PREAMBLE_SIZE,
							&crypto_handle);

						/**
						 * Validate.
						 */
						if (!w2e_common__validate_dec(pkt[1]))
						{
							w2e_print_error("Validation: Malformed packet (possibly wrong key)! Drop\n");
							w2e_ctrs.err_rx++;
							continue;
						}

						/** TODO check SYN in incoming, i.e. remote server establishes connection */
						if ((pkt[1][9] == 0x06) && (*(((uint8_t*)(hdr_pre_ip)) + 33) == 0x02))
						{
							w2e_print_error("WARN: SYN in incoming packet\n");
						}

						/**
						 * Substitute local IP.
						 */
						hdr_pre_ip->DstAddr = w2e_cfg_client.ip_client; // My src address

						/**
						 * Recalculate CRCs (all).
						 */
						WinDivertHelperCalcChecksums(
							pkt[1], len_send, &addr,
							(UINT64)(WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM));

						/**
						 * Send modified packet.
						 */
						w2e_dbg_dump(len_send, pkt[1]);
						__w2e_client__pkt_send(w_filter, pkt[1], len_send, NULL, &addr);
						continue;
					}
					else if (addr.Outbound) /* Any outbound traffic */
					{ /* Encapsulation needed */
						w2e_dbg_printf("ENCAP Got %s packet, len=%d\n", addr.Outbound ? "outbound" : "inbound", len_recv);
						w2e_ctrs.encap++;

						w2e_dbg_dump(len_recv, pkt[0]);
						

						if (hdr_tcp)
						{
							/**
							 * TCP MSS set to prevent fragmentation.
							 */
							if (hdr_tcp->Syn && !hdr_tcp->Ack /** SYN */
								&& hdr_tcp->HdrLength > 5 /** > 20 bytes, i.e. options present */
								)
							{
								if (__w2c_client__tcp_set_mss(hdr_tcp, W2E_TCP_MSS) != 0)
								{
									w2e_print_error("Unable to set MSS! Drop\n");
									w2e_ctrs.err_rx++;
									continue;
								}
							}
							/**
							 * Packet too long & it's not SYN -- reset connection.
							 */
							else if (len_data > W2E_TCP_MSS)
							{
								w2e_print_error("Too long packet encapsulating ( %s%s%s). Send RST\n",
									hdr_ip ? "IP " : "",
									hdr_udp ? "UDP " : "",
									hdr_tcp ? "TCP " : ""
								);
								w2e_dbg_dump(len_recv, pkt[0]);

								*(((uint8_t*)(hdr_tcp)) + 13) = 0x04;
								//hdr_tcp->Rst = 1;

								hdr_ip->Length = hdr_ip->HdrLength * 4 + 20;
								len_recv = hdr_ip->Length;
								hdr_tcp->HdrLength = 5;
							}
						}

						/**
						 * Encrypt payload.
						 */
						len_send = w2e_crypto__enc(
							pkt[0],
							&(pkt[1][W2E_PREAMBLE_SIZE]),
							len_recv,
							W2E_MAX_PACKET_SIZE - W2E_PREAMBLE_SIZE,
							&crypto_handle);

						/**
						 * Add incapsulation header.
						 */

						/** IPv4 header */
						memcpy(pkt[1], w2e_template_iph, sizeof(w2e_template_iph));
						/** UDP header */
						memcpy(&(pkt[1][sizeof(w2e_template_iph)]), w2e_template_udph, sizeof(w2e_template_udph));

						/** New UDP header */
						hdr_pre_udp->SrcPort = w2e_cfg_client.port_client;
						hdr_pre_udp->Length = htons(len_send + sizeof(w2e_template_udph));


						len_send += W2E_PREAMBLE_SIZE;


						/** New IPv4 header */
						hdr_pre_ip->Length = htons((u_short)(len_send));

						/** Configured in INI address or the same address from plain */
						hdr_pre_ip->SrcAddr = w2e_cfg_client.ip_client;
						//hdr_pre_ip->SrcAddr = w2e_cfg_client.ip_client ? w2e_cfg_client.ip_client : hdr_ip->SrcAddr;
						/** Remote w2e server address */
						hdr_pre_ip->DstAddr = w2e_cfg_client.ip_server;

						//hdr_pre_ip->SrcAddr = htonl(/*0xc0a832f5*/ 0x0A00A084); // My src address
						//hdr_pre_ip->SrcAddr = htonl(0xc0a832f5); // My src address

						/**
						 * Recalculate CRCs (IPv4 and UDP).
						 */
						WinDivertHelperCalcChecksums(pkt[1], len_send, &addr,
							(UINT64)(WINDIVERT_HELPER_NO_TCP_CHECKSUM | WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM));

						/**
						 * Send modified packet.
						 */
						w2e_dbg_dump(len_send, pkt[1]);
						__w2e_client__pkt_send(w_filter, pkt[1], len_send, NULL, &addr);
						continue;
					}
				}

				/** Send unmodified packet */
				__w2e_client__pkt_send(w_filter, pkt[0], len_recv, NULL, &addr);
			}
			else
			{
				w2e_print_error("Error parsing packet!\n");
				w2e_ctrs.err_rx++;
			}
		}
		else
		{
			errorcode = GetLastError();
			w2e_print_error("Error receiving packet! 0x%X\n", errorcode);
			w2e_ctrs.err_rx++;

			switch (errorcode)
			{
			case 122:
			{
				w2e_print_error("ERROR_INSUFFICIENT_BUFFER: The captured packet is larger than the pPacket buffer\n");
				break;
			}
			case 232:
			{
				w2e_print_error("ERROR_NO_DATA: The handle has been shutdown using WinDivertShutdown() and the packet queue is empty.\n");
				break;
			}
			default:
			{
				w2e_print_error("Unexpected error 0x%X\n", errorcode);
				break;
			}
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
	const char ini_default[] = W2E_INI_DEFAULT_NAME;
	const char* ini_fname = ini_default;

	w2e_log_printf("Client is starting...\n");

	/**
	 * SIGINT handler.
	 */
	signal(SIGINT, __w2c_client__sigint_handler);

	/**
	 * shmm create.
	 * @TODO
	 */

	
	/**
	 * INI parser.
	 */
	if (argc > 1)
	{
		ini_fname = argv[1];
	}
	w2e_log_printf("INI: Reading config file %s...\n", ini_fname);
	if (ini_parse(ini_fname, __w2e_client__ini_handler, &w2e_cfg_client) != 0)
	{
		w2e_print_error("INI: Error in file %s\n", ini_fname);
		return 1;
	}

	/**
	 * Crypto lib init.
	 */
	if (w2e_crypto__init((const u8*)w2e_cfg_client.key, W2E_KEY_LEN, &crypto_handle) != 0)
	{
		w2e_print_error("Crypto init error\n");
		return 1;
	}


	/**
	 * Filters initialization.
	 */
	 //g_filters[g_filter_num] = __w2e_client__init("outbound and !loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	 //g_filters[g_filter_num] = __w2e_client__init("!loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	g_filters[g_filter_num] = __w2e_client__init(
		" !loopback"
		" and ip"
		//" and (tcp or udp)"
		" and (" "udp.SrcPort == 5256"
			" or tcp.DstPort == 443"
			" or tcp.DstPort == 80"
			/////////" ((tcp.DstPort == 443 or tcp.DstPort == 80) and ip.DstAddr != 35.226.111.211)"
			" or udp.DstPort == 53"
			" or udp.DstPort == 443" /* QUIC */
			//" or udp.DstPort == 1900" /* SSDP */
			//" udp.DstPort == 53"
		")"
		//" and (udp.DstPort == 53 or udp.SrcPort == 53)"
		//" and (tcp.SrcPort == 80 or tcp.DstPort == 80 or udp.SrcPort == 53 or udp.DstPort == 53 or icmp)"
		, 0);
	w_filter = g_filters[g_filter_num];
	g_filter_num++;

	if (!w_filter)
	{
		w2e_print_error("Filter init error\n");
		return 1;
	}

	__w2c_client__main_loop(w_filter);


	return 0;
}
