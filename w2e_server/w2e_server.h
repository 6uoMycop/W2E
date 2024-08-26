﻿/*****************************************************************//**
 * \file   w2e_server.h
 * \brief  W2E server application (Linux)
 *
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_SERVER_H
#define __W2E_SERVER_H


#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "w2e_common.h"
#include "w2e_crypto.h"
#include "w2e_conntrack.h"

#include "inih.h"


#ifndef W2E_MAX_CLIENTS
/**
 * Maximum number of clients.
 */
#define W2E_MAX_CLIENTS 2
#endif // !W2E_MAX_CLIENTS


/**
 * Client context.
 */
typedef struct {
	uint8_t		is_configured;		/** Is this client configured from INI file? */
	/** INI configured */
	uint16_t	port;				/** This client's UDP port (in network byte order) */
	uint8_t		key[W2E_KEY_LEN];	/** AES key */
	/** Runtime context */
	uint32_t	ip_client;			/** Client's IP address (in network byte order) */
	uint32_t	ip_dns_last;		/** Last client DNS address in network byte order */
} w2e_cfg_client_ctx_t;


/**
 * Server runtime context.
 */
typedef struct {
	/**
	 * INI configured // DNS server's IP address (in network byte order). If 0 -- don't substitute.
	 */
	uint32_t				ip_dns;

	/**
	 * INI configured // DNS server's IP address (in network byte order). If 0 -- don't substitute.
	 */
	uint32_t				ip_server;

	/**
	 * Clients' contexts. Index in this array is client's ID.
	 */
	w2e_cfg_client_ctx_t	client_ctx[W2E_MAX_CLIENTS];
} w2e_cfg_server_ctx_t;

#endif // __W2E_SERVER_H
