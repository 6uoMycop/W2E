/*****************************************************************//**
 * \file   w2e_common.h
 * \brief  Common W2E includes and macros (cross-platform)
 * 
 * \author ark
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_COMMON_H
#define __W2E_COMMON_H


#include <stdio.h>
#include <stdint.h>

#ifdef _MSC_VER
#include <winsock.h>
#else

#endif // _MSC_VER


/**
 * Default constants.
 */

#ifndef W2E_HOST_MAXLEN
#define W2E_HOST_MAXLEN 253
#endif // !W2E_HOST_MAXLEN

/**
 * Effective packet length is reduced because of insertion of new headers.
 * Refer to client's and server's source code.
 */
#ifndef W2E_MAX_PACKET_SIZE
#define W2E_MAX_PACKET_SIZE 9016
#endif // !W2E_MAX_PACKET_SIZE

#ifndef W2E_MAX_FILTERS
#define W2E_MAX_FILTERS 4
#endif // !W2E_MAX_FILTERS

/**
 * AES key length in bytes.
 */
#ifndef W2E_KEY_LEN
#define W2E_KEY_LEN (128 / 8)
#endif // !W2E_KEY_LEN


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
 * "Preamble" is placed before packet and used for insertion of new IP + UDP header.
 * Currently IPv4 without options + ICMPv4 (or UDP)
 */
#define W2E_PREAMBLE_SIZE 20 + 8 // IPv4 + ICMPv4 (or UDP)

/**
 * Packet data. Has free space at the beginning for inserting preamble.
 */
typedef union {
	struct {
		uint8_t p_1[W2E_PREAMBLE_SIZE];							 // To add preamble on encode
		uint8_t p0[W2E_PREAMBLE_SIZE];							 // Base
		uint8_t p1[W2E_MAX_PACKET_SIZE - 2 * W2E_PREAMBLE_SIZE]; // To remove preamble on decode
	} split;
	uint8_t raw[W2E_MAX_PACKET_SIZE];
} w2e_pkt_t;



// IPv4 header template. <These> fields will be edited.
// |version=4,ihl=5| tos=0  |     <packet size>    |
// |           id=0         |R=0,DF=1,MF=0,offset=0|
// |   TTL=255     |proto=07|         <crc>        |
// |                    <IP src>                   |
// |                    <IP dst>                   |
#define W2E_TEMPLATE_IPH \
0x45, 0x00, 0x00, 0x00,\
0x00, 0x00, 0x40, 0x00,\
0xFF, 0x01, 0x00, 0x00,\
0x00, 0x00, 0x00, 0x00,\
0x00, 0x00, 0x00, 0x00


// ICMPv4 header template. <These> fields will be edited.
// |  type=8   |  code=0    |       <ICMP crc>     |
// |          <id>          |       <seq>          |
#define W2E_TEMPLATE_ICMPH \
0x08, 0x00, 0x00, 0x00,\
0xde, 0xad, 0xfa, 0xce
//0x00, 0x00, 0x00, 0x00


// UDP header template. <These> fields will be edited.
// |      <UDP src>         |       <UDP dst>      |
// |      <UDP len>         |       <UDP crc>      |
#define W2E_TEMPLATE_UDPH \
0x00, 0x00, 0x00, 0x00,\
0x00, 0x00, 0x00, 0x00


#endif // __W2E_COMMON_H
