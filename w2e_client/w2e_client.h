/*****************************************************************//**
 * \file   w2e_client.h
 * \brief  W2E client application
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_CLIENT_H
#define __W2E_CLIENT_H


#include "w2e_common.h"


/**
 * "Preamble" is placed before packet and used for insertion of new IP + UDP header.
 * Currently IPv4 without options + UDP
 */
#define W2E_PREAMBLE_SIZE 20 + 8

#ifndef W2E_CLIENT_PORT
/**
 * Client's UDP source port.
 */
#define W2E_CLIENT_PORT 55888
#endif // !W2E_CLIENT_PORT


#endif // __W2E_CLIENT_H
