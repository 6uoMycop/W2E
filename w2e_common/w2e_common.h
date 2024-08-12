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
#endif // !W2E_HOST_MAXLEN

#ifndef W2E_MAX_PACKET_SIZE
/**
 * Effective packet length is reduced because of insertion of new headers.
 * Refer to client's and server's source code.
 */
#define W2E_MAX_PACKET_SIZE 9016
#endif // !W2E_MAX_PACKET_SIZE

#ifndef W2E_MAX_FILTERS
#define W2E_MAX_FILTERS 4
#endif // !W2E_MAX_FILTERS


/**
 * Debug log.
 */
#ifndef W2E_DEBUG
 /** Debug printf macro NOP */
#define w2e_dbg_printf(...) do {} while (0);
#else // W2E_DEBUG
/** Enable verbose logging anyway */
#ifndef W2E_VERBOSE
#define W2E_VERBOSE
#endif // !W2E_VERBOSE
/** Define debug printf macro */
#define w2e_dbg_printf(fmt, ...) printf("[DBG] %s()\t%s:%d:\t" fmt, __func__, __FILE__, __LINE__, ##__VA_ARGS__);
#endif // W2E_DEBUG


/**
 * Verbose log.
 */
#ifndef W2E_VERBOSE
 /** Verbose printf macro NOP */
#define w2e_log_printf(...) do {} while (0);
#else
/** Define verbose printf macro */
#define w2e_log_printf(fmt, ...) printf("[LOG] %s()\t%s:%d:\t" fmt, __func__, __FILE__, __LINE__, ##__VA_ARGS__);
#endif // !W2E_VERBOSE


/** Define error printf macro */
#define w2e_print_error(fmt, ...) fprintf(stderr, "[ERROR] %s()\t%s:%d:\t" fmt, __func__, __FILE__, __LINE__, ##__VA_ARGS__);


/**
 * For packed structures.
 */
#ifdef _MSC_VER
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
#else
#error NOT MSVC
#endif



HANDLE w2e_common__init(char* filter, UINT64 flags);

void w2e_common__deinit_all(HANDLE * filters, int filter_num);


#endif // __W2E_COMMON_H
