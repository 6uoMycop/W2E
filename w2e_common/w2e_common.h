/*****************************************************************//**
 * \file   w2e_common.h
 * \brief  Static library - Common W2E includes, macros and functions
 * 
 * \author ark
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_COMMON_H
#define __W2E_COMMON_H


#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <winsock.h>

#include "windivert.h"


/**
 * Default constants.
 */

#ifndef W2E_HOST_MAXLEN
#define W2E_HOST_MAXLEN 253
#endif // W2E_HOST_MAXLEN

#ifndef W2E_MAX_PACKET_SIZE
#define W2E_MAX_PACKET_SIZE 9016
#endif // W2E_MAX_PACKET_SIZE

#ifndef W2E_MAX_FILTERS
#define W2E_MAX_FILTERS 4
#endif // !W2E_MAX_FILTERS


#ifndef W2E_DEBUG
#define w2e_dbg_printf(...) do {} while (0);
#else
#define w2e_dbg_printf(...) printf(__VA_ARGS__);
#endif


HANDLE w2e_common__init(char* filter, UINT64 flags);

void w2e_common__deinit_all(HANDLE * filters, int filter_num);


#endif // __W2E_COMMON_H