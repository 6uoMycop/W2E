/*****************************************************************//**
 * \file   w2e_server.h
 * \brief  W2E server application (Linux)
 *
 * \author ark
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


/**
 * Open DNS server address to substitute.
 */
#ifndef W2E_DNS
#define W2E_DNS 0x08080808
#endif // !W2E_DNS



#endif // __W2E_SERVER_H
