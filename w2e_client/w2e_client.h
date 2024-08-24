/*****************************************************************//**
 * \file   w2e_client.h
 * \brief  W2E client application (Windows)
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_CLIENT_H
#define __W2E_CLIENT_H


#include <signal.h>
#include <ws2tcpip.h>

#include "w2e_common.h"
#include "inih.h"
#include "w2e_crypto.h"
#include "windivert.h"


//@TODO delete this, use config
#ifndef W2E_CLIENT_PORT
/**
 * Client's UDP source port.
 */
#define W2E_CLIENT_PORT 55888
#endif // !W2E_CLIENT_PORT


/**
 * Client configuration.
 */
typedef struct {
    uint32_t    ip_server;          /** Server's IP address (in network byte order) */
    uint16_t    port_client;        /** This client's UDP port (in network byte order) */
    uint8_t     key[W2E_KEY_LEN];   /** AES key */
} w2e_cfg_client_t;



#endif // __W2E_CLIENT_H
