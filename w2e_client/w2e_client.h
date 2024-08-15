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

#include "w2e_common.h"
#include "w2e_crypto.h"
#include "windivert.h"


#ifndef W2E_CLIENT_PORT
/**
 * Client's UDP source port.
 */
#define W2E_CLIENT_PORT 55888
#endif // !W2E_CLIENT_PORT


#endif // __W2E_CLIENT_H
