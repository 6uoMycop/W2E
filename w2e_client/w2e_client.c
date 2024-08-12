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


static void sigint_handler(int sig)
{
	//exiting = 1;
	w2e_common__deinit_all(filters, filter_num);
	printf("Client stop\n");
	exit(EXIT_SUCCESS);
}

/**
 * W2E Client main.
 */
int main(int argc, char* argv[])
{
	HANDLE w_filter = NULL;
	uint8_t packet[W2E_MAX_PACKET_SIZE];
	UINT packetLen;
	WINDIVERT_ADDRESS addr;
	PVOID packet_data;
	UINT packet_dataLen;
	PWINDIVERT_IPHDR ppIpHdr;
	PWINDIVERT_IPV6HDR ppIpV6Hdr;
	PWINDIVERT_TCPHDR ppTcpHdr;
	PWINDIVERT_UDPHDR ppUdpHdr;
	int packet_v4, packet_v6;

	static enum packet_type_e {
		unknown,
		ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
		ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
	} packet_type;

	printf("TEST client\n");

	signal(SIGINT, sigint_handler);

	/**
	 * Filters initialization.
	 */
	//filters[filter_num] = w2e_common__init("outbound and !loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	//filters[filter_num] = w2e_common__init("!loopback and (tcp.DstPort == 80 or udp.DstPort == 53)", 0);
	filters[filter_num] = w2e_common__init(
		"!loopback "
		"and (tcp.SrcPort == 80 or tcp.DstPort == 80 or udp.SrcPort == 53 or udp.DstPort == 53)"
		, 0);
	w_filter = filters[filter_num];
	filter_num++;

	while (1)
	{
		if (WinDivertRecv(w_filter, packet, sizeof(packet), &packetLen, &addr))
		{
			w2e_dbg_printf("Got %s packet, len=%d\n",
				addr.Outbound ? "outbound" : "inbound", packetLen);

			//	addr.Flow.LocalAddr[0] & 0xFF, (addr.Flow.LocalAddr[0] >> 8) & 0xFF, (addr.Flow.LocalAddr[0] >> 16) & 0xFF, (addr.Flow.LocalAddr[0] >> 24) & 0xFF, addr.Flow.LocalPort,
			//	addr.Flow.RemoteAddr[0] & 0xFF, (addr.Flow.RemoteAddr[0] >> 8) & 0xFF, (addr.Flow.RemoteAddr[0] >> 16) & 0xFF, (addr.Flow.RemoteAddr[0] >> 24) & 0xFF, addr.Flow.LocalPort
			//	);
			//should_reinject = 1;
			//should_recalc_checksum = 0;
			//sni_ok = 0;

			ppIpHdr		= (PWINDIVERT_IPHDR)NULL;
			ppIpV6Hdr	= (PWINDIVERT_IPV6HDR)NULL;
			ppTcpHdr	= (PWINDIVERT_TCPHDR)NULL;
			ppUdpHdr	= (PWINDIVERT_UDPHDR)NULL;
			packet_v4	= packet_v6 = 0;
			packet_type	= unknown;

			// Parse network packet and set it's type
			if (WinDivertHelperParsePacket(
				packet,
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
					packet_v6 = 1;
					if (ppTcpHdr)
					{
						packet_type = ipv6_tcp;
						if (packet_data)
						{
							packet_type = ipv6_tcp_data;
						}
					}
					else if (ppUdpHdr && packet_data)
					{
						packet_type = ipv6_udp_data;
					}
				}
			}

			w2e_dbg_printf("packet_type: %d, packet_v4: %d, packet_v6: %d\n", packet_type, packet_v4, packet_v6);

#if 0
			if (packet_type == ipv4_tcp_data || packet_type == ipv6_tcp_data)
			{
				//printf("Got parsed packet, len=%d!\n", packet_dataLen);
				/* Got a TCP packet WITH DATA */

				/* Handle INBOUND packet with data and find HTTP REDIRECT in there */
				if (!addr.Outbound && packet_dataLen > 16)
				{
					/* If INBOUND packet with DATA (tcp.Ack) */

					/* Drop packets from filter with HTTP 30x Redirect */
					if (do_passivedpi && is_passivedpi_redirect(packet_data, packet_dataLen))
					{
						if (packet_v4)
						{
							//printf("Dropping HTTP Redirect packet!\n");
							should_reinject = 0;
						}
						else if (packet_v6 && WINDIVERT_IPV6HDR_GET_FLOWLABEL(ppIpV6Hdr) == 0x0)
						{
							/* Contrary to IPv4 where we get only packets with IP ID 0x0-0xF,
							 * for IPv6 we got all the incoming data packets since we can't
							 * filter them in a driver.
							 *
							 * Handle only IPv6 Flow Label == 0x0 for now
							 */
							 //printf("Dropping HTTP Redirect packet!\n");
							should_reinject = 0;
						}
					}
				}
				/* Handle OUTBOUND packet on port 443, search for something that resembles
				 * TLS handshake, send fake request.
				 */
				else if (addr.Outbound &&
					((do_fragment_https ? packet_dataLen == https_fragment_size : 0) ||
						packet_dataLen > 16) &&
					ppTcpHdr->DstPort != htons(80) &&
					(do_fake_packet || do_native_frag)
					)
				{
					/**
					 * In case of Window Size fragmentation=2, we'll receive only 2 byte packet.
					 * But if the packet is more than 2 bytes, check ClientHello byte.
					*/
					if ((packet_dataLen == 2 && memcmp(packet_data, "\x16\x03", 2) == 0) ||
						(packet_dataLen >= 3 && (memcmp(packet_data, "\x16\x03\x01", 3) == 0 || memcmp(packet_data, "\x16\x03\x03", 3) == 0)))
					{
						if (do_blacklist || do_fragment_by_sni)
						{
							sni_ok = extract_sni(packet_data, packet_dataLen,
								&host_addr, &host_len);
						}
						if (
							(do_blacklist && sni_ok &&
								blackwhitelist_check_hostname(host_addr, host_len)
								) ||
							(do_blacklist && !sni_ok && do_allow_no_sni) ||
							(!do_blacklist)
							)
						{
#ifdef DEBUG
							char lsni[W2E_HOST_MAXLEN + 1] = { 0 };
							extract_sni(packet_data, packet_dataLen,
								&host_addr, &host_len);
							memcpy(lsni, host_addr, host_len);
							printf("Blocked HTTPS website SNI: %s\n", lsni);
#endif
							if (do_fake_packet)
							{
								TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_https_request);
							}
							if (do_native_frag)
							{
								// Signal for native fragmentation code handler
								should_recalc_checksum = 1;
							}
						}
					}
				}
				/* Handle OUTBOUND packet on port 80, search for Host header */
				else if (addr.Outbound &&
					packet_dataLen > 16 &&
					(do_http_allports ? 1 : (ppTcpHdr->DstPort == htons(80))) &&
					find_http_method_end(packet_data,
						(do_fragment_http ? http_fragment_size : 0u),
						&http_req_fragmented) &&
					(do_host || do_host_removespace ||
						do_host_mixedcase || do_fragment_http_persistent ||
						do_fake_packet))
				{

					/* Find Host header */
					if (find_header_and_get_info(packet_data, packet_dataLen,
						http_host_find, &hdr_name_addr, &hdr_value_addr, &hdr_value_len) &&
						hdr_value_len > 0 && hdr_value_len <= W2E_HOST_MAXLEN &&
						(do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len) : 1))
					{
						host_addr = hdr_value_addr;
						host_len = hdr_value_len;
#ifdef DEBUG
						char lhost[W2E_HOST_MAXLEN + 1] = { 0 };
						memcpy(lhost, host_addr, host_len);
						printf("Blocked HTTP website Host: %s\n", lhost);
#endif

						if (do_native_frag)
						{
							// Signal for native fragmentation code handler
							should_recalc_checksum = 1;
						}

						if (do_fake_packet)
						{
							TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_http_request);
						}

						if (do_host_mixedcase)
						{
							mix_case(host_addr, host_len);
							should_recalc_checksum = 1;
						}

						if (do_host)
						{
							/* Replace "Host: " with "hoSt: " */
							memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
							should_recalc_checksum = 1;
							//printf("Replaced Host header!\n");
						}

						/* If removing space between host header and its value
						 * and adding additional space between Method and Request-URI */
						if (do_additional_space && do_host_removespace)
						{
							/* End of "Host:" without trailing space */
							method_addr = find_http_method_end(packet_data,
								(do_fragment_http ? http_fragment_size : 0),
								NULL);

							if (method_addr)
							{
								memmove(method_addr + 1, method_addr,
									(size_t)(host_addr - method_addr - 1));
								should_recalc_checksum = 1;
							}
						}
						/* If just removing space between host header and its value */
						else if (do_host_removespace)
						{
							if (find_header_and_get_info(packet_data, packet_dataLen,
								http_useragent_find, &hdr_name_addr,
								&hdr_value_addr, &hdr_value_len))
							{
								useragent_addr = hdr_value_addr;
								useragent_len = hdr_value_len;

								/* We move Host header value by one byte to the left and then
								 * "insert" stolen space to the end of User-Agent value because
								 * some web servers are not tolerant to additional space in the
								 * end of Host header.
								 *
								 * Nothing is done if User-Agent header is missing.
								 */
								if (useragent_addr && useragent_len > 0)
								{
									/* useragent_addr is in the beginning of User-Agent value */

									if (useragent_addr > host_addr)
									{
										/* Move one byte to the LEFT from "Host:"
										* to the end of User-Agent
										*/
										memmove(host_addr - 1, host_addr,
											(size_t)(useragent_addr + useragent_len - host_addr));
										host_addr -= 1;
										/* Put space in the end of User-Agent header */
										*(char*)((unsigned char*)useragent_addr + useragent_len - 1) = ' ';
										should_recalc_checksum = 1;
										//printf("Replaced Host header!\n");
									}
									else
									{
										/* User-Agent goes BEFORE Host header */

										/* Move one byte to the RIGHT from the end of User-Agent
										* to the "Host:"
										*/
										memmove(useragent_addr + useragent_len + 1,
											useragent_addr + useragent_len,
											(size_t)(host_addr - 1 - (useragent_addr + useragent_len)));
										/* Put space in the end of User-Agent header */
										*(char*)((unsigned char*)useragent_addr + useragent_len) = ' ';
										should_recalc_checksum = 1;
										//printf("Replaced Host header!\n");
									}
								} /* if (host_len <= W2E_HOST_MAXLEN && useragent_addr) */
							} /* if (find_header_and_get_info http_useragent) */
						} /* else if (do_host_removespace) */
					} /* if (find_header_and_get_info http_host) */
				} /* Handle OUTBOUND packet with data */

				/*
				* should_recalc_checksum mean we have detected a packet to handle and
				* modified it in some way.
				* Handle native fragmentation here, incl. sending the packet.
				*/
				if (should_reinject && should_recalc_checksum && do_native_frag)
				{
					current_fragment_size = 0;
					if (do_fragment_http && ppTcpHdr->DstPort == htons(80))
					{
						current_fragment_size = http_fragment_size;
					}
					else if (do_fragment_https && ppTcpHdr->DstPort != htons(80))
					{
						if (do_fragment_by_sni && sni_ok)
						{
							current_fragment_size = (void*)host_addr - packet_data;
						}
						else
						{
							current_fragment_size = https_fragment_size;
						}
					}

					if (current_fragment_size)
					{
						send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
							packet_dataLen, packet_v4, packet_v6,
							ppIpHdr, ppIpV6Hdr, ppTcpHdr,
							current_fragment_size, do_reverse_frag);

						send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
							packet_dataLen, packet_v4, packet_v6,
							ppIpHdr, ppIpV6Hdr, ppTcpHdr,
							current_fragment_size, !do_reverse_frag);
						continue;
					}
				}
			} /* Handle TCP packet with data */

			/* Else if we got TCP packet without data */
			else if (packet_type == ipv4_tcp || packet_type == ipv6_tcp)
			{
				/* If we got INBOUND SYN+ACK packet */
				if (!addr.Outbound &&
					ppTcpHdr->Syn == 1 && ppTcpHdr->Ack == 1)
				{
					//printf("Changing Window Size!\n");
					/*
					 * Window Size is changed even if do_fragment_http_persistent
					 * is enabled as there could be non-HTTP data on port 80
					 */

					if (do_fake_packet && (do_auto_ttl || ttl_min_nhops))
					{
						if (!((packet_v4 && tcp_handle_incoming(&ppIpHdr->SrcAddr, &ppIpHdr->DstAddr,
							ppTcpHdr->SrcPort, ppTcpHdr->DstPort,
							0, ppIpHdr->TTL))
							||
							(packet_v6 && tcp_handle_incoming((uint32_t*)&ppIpV6Hdr->SrcAddr,
								(uint32_t*)&ppIpV6Hdr->DstAddr,
								ppTcpHdr->SrcPort, ppTcpHdr->DstPort,
								1, ppIpV6Hdr->HopLimit))))
						{
							if (do_tcp_verb)
								puts("[TCP WARN] Can't add TCP connection record.");
						}
					}

					if (!do_native_frag)
					{
						if (do_fragment_http && ppTcpHdr->SrcPort == htons(80))
						{
							change_window_size(ppTcpHdr, http_fragment_size);
							should_recalc_checksum = 1;
						}
						else if (do_fragment_https && ppTcpHdr->SrcPort != htons(80))
						{
							change_window_size(ppTcpHdr, https_fragment_size);
							should_recalc_checksum = 1;
						}
					}
				}
			}

			/* Else if we got UDP packet with data */
			else if ((do_dnsv4_redirect && (packet_type == ipv4_udp_data)) ||
				(do_dnsv6_redirect && (packet_type == ipv6_udp_data)))
			{
				if (!addr.Outbound)
				{
					if ((packet_v4 && dns_handle_incoming(&ppIpHdr->DstAddr, ppUdpHdr->DstPort,
						packet_data, packet_dataLen,
						&dns_conn_info, 0))
						||
						(packet_v6 && dns_handle_incoming(ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
							packet_data, packet_dataLen,
							&dns_conn_info, 1)))
					{
						/* Changing source IP and port to the values
						 * from DNS conntrack */
						if (packet_v4)
							ppIpHdr->SrcAddr = dns_conn_info.dstip[0];
						else if (packet_v6)
							ipv6_copy_addr(ppIpV6Hdr->SrcAddr, dns_conn_info.dstip);
						ppUdpHdr->DstPort = dns_conn_info.srcport;
						ppUdpHdr->SrcPort = dns_conn_info.dstport;
						should_recalc_checksum = 1;
					}
					else
					{
						if (dns_is_dns_packet(packet_data, packet_dataLen, 0))
							should_reinject = 0;

						if (do_dns_verb && !should_reinject)
						{
							printf("[DNS] Error handling incoming packet: srcport = %hu, dstport = %hu\n",
								ntohs(ppUdpHdr->SrcPort), ntohs(ppUdpHdr->DstPort));
						}
					}
				}

				else if (addr.Outbound)
				{
					if ((packet_v4 && dns_handle_outgoing(&ppIpHdr->SrcAddr, ppUdpHdr->SrcPort,
						&ppIpHdr->DstAddr, ppUdpHdr->DstPort,
						packet_data, packet_dataLen, 0))
						||
						(packet_v6 && dns_handle_outgoing(ppIpV6Hdr->SrcAddr, ppUdpHdr->SrcPort,
							ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
							packet_data, packet_dataLen, 1)))
					{
						/* Changing destination IP and port to the values
						 * from configuration */
						if (packet_v4)
						{
							ppIpHdr->DstAddr = dnsv4_addr;
							ppUdpHdr->DstPort = dnsv4_port;
						}
						else if (packet_v6)
						{
							ipv6_copy_addr(ppIpV6Hdr->DstAddr, (uint32_t*)dnsv6_addr.s6_addr);
							ppUdpHdr->DstPort = dnsv6_port;
						}
						should_recalc_checksum = 1;
					}
					else
					{
						if (dns_is_dns_packet(packet_data, packet_dataLen, 1))
							should_reinject = 0;

						if (do_dns_verb && !should_reinject)
						{
							printf("[DNS] Error handling outgoing packet: srcport = %hu, dstport = %hu\n",
								ntohs(ppUdpHdr->SrcPort), ntohs(ppUdpHdr->DstPort));
						}
					}
				}
			}

			if (should_reinject)
			{
				//printf("Re-injecting!\n");
				if (should_recalc_checksum)
				{
					WinDivertHelperCalcChecksums(packet, packetLen, &addr, (UINT64)0LL);
				}
#endif // 0
				WinDivertSend(w_filter, packet, packetLen, NULL, &addr);
			//}
		}
		else
		{
			// error, ignore
			//if (!exiting)
				printf("Error receiving packet!\n");
			break;
		}
	}

	return 0;
}
