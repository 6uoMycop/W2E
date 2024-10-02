/*****************************************************************//**
 * \file   w2e_server.h
 * \brief  W2E server application (Linux)
 *
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_SERVER_H
#define __W2E_SERVER_H


#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "w2e_common.h"
#include "w2e_art.h"
#include "w2e_crypto.h"
#include "w2e_conntrack.h"

#include "inih.h"


#ifndef W2E_MAX_CLIENTS
/**
 * Maximum number of clients.
 */
#define W2E_MAX_CLIENTS 255
#endif // !W2E_MAX_CLIENTS

#ifndef W2E_SERVER_NFQUEUE_NUM
 /**
  * Number of NFQUEUEs (and threads - 1 per queue) on server.
  */
#define W2E_SERVER_NFQUEUE_NUM 1
#endif // !W2E_SERVER_NFQUEUE_NUM

/**
 * Client context.
 */
typedef struct {
	uint8_t		is_configured;		/** Is this client configured from INI file? */
	/** INI configured */
	uint8_t		id;					/** This client's ID */
	uint8_t		key[W2E_KEY_LEN];	/** AES key */
	/** Runtime context */
	w2e_crypto__handle_t handle;	/** Cryptographic library handle */
	uint32_t	ip_client;			/** Server visible client's IP address (in network byte order) */
	uint16_t	port_client;		/** Server visible client's port of encapsulated UDP packets (in network byte order) */
	uint32_t	ip_dns_last;		/** Last client DNS address in network byte order */
} w2e_cfg_client_ctx_t;


/**
 * NFUQEUE context. Also passed to __w2e_server__cb() as last arg.
 */
typedef struct {
	/**
	 * Raw socket.
	 */
	int						sock_tx;

	/**
	 * NFQUEUE.
	 */
	int						id;			/** NFQUEUE id */
	struct nfq_handle*		h;
	struct nfq_q_handle*	qh;
	int						fd;
} w2e_nfqueue_ctx;


/**
 * Server runtime context.
 */
typedef struct {
	/**
	 * INI configured // DNS server's IP address (in network byte order). If 0 -- don't substitute.
	 */
	uint32_t				ip_dns;

	/**
	 * INI configured // Local server's IP address (in network byte order).
	 */
	uint32_t				ip_server;

	/**
	 * Clients' contexts. Index in this array is client's ID.
	 */
	w2e_cfg_client_ctx_t	client_ctx[W2E_MAX_CLIENTS];
} w2e_cfg_server_ctx_t;

#endif // __W2E_SERVER_H
