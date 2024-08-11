/*****************************************************************//**
 * \file   w2e_common.h
 * \brief  Common W2E includes
 * 
 * \author ark
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_COMMON_H
#define __W2E_COMMON_H


#include <stdio.h>
#include <stdint.h>
#include <signal.h>

#define HOST_MAXLEN 253
#define MAX_PACKET_SIZE 9016

#ifndef W2E_DEBUG
#define w2e_dbg_printf(...) do {} while (0);
#else
#define w2e_dbg_printf(...) printf(__VA_ARGS__);
#endif


#endif // __W2E_COMMON_H



