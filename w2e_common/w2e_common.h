/*****************************************************************//**
 * \file   w2e_common.h
 * \brief  Common W2E includes and macros (cross-platform)
 * 
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_COMMON_H
#define __W2E_COMMON_H


#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef _MSC_VER // Windows
#include <winsock.h>
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else // Linux
#include <netinet/in.h>
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#if 0
#include <sys/mman.h>
#endif /* 0 */
#endif // ?_MSC_VER


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

#ifndef W2E_KEY_LEN
/**
 * AES key length in bytes.
 */
#define W2E_KEY_LEN (128 / 8)
#endif // !W2E_KEY_LEN

#ifndef W2E_SERVER_PORT_HB
 /**
  * Higher byte of server's port (prefix). //@TODO add [server] id somehow here
  */
#define W2E_SERVER_PORT_HB (uint16_t)(0xAA00)
#endif // !W2E_SERVER_PORT_HB

#ifndef W2E_TCP_MSS
  /**
   * TCP MSS size.
   */
#define W2E_TCP_MSS (uint16_t)(1340)
#endif // !W2E_TCP_MSS

/**
 * Debug log.
 */

#ifndef W2E_DEBUG

	/** Debug printf macro NOP */
	#define w2e_dbg_printf(...) do {} while (0)
	/** Debug buffer hex dump macro NOP */
	#define w2e_dbg_dump(len, buf) do {} while (0)

#else // W2E_DEBUG

	/** Enable verbose logging anyway */
	#ifndef W2E_VERBOSE
		#define W2E_VERBOSE
	#endif // !W2E_VERBOSE

	/** Define debug printf macro */
	#define w2e_dbg_printf(fmt, ...) do { printf("[DBG]  %16s:%-5d %32s():  " fmt, __FILENAME__, __LINE__, __func__, ##__VA_ARGS__); } while (0)

	#ifndef W2E_DEBUG_NO_HEX
	/** Debug buffer hex dump macro */
		#define w2e_dbg_dump(len, buf) \
		do { \
			for (int __i = 0; __i < len; __i++) printf("%02X ", (unsigned char)(buf[__i])); \
			printf("\n"); \
		} while (0)
	#else
		/** Debug buffer hex dump macro NOP */
		#define w2e_dbg_dump(len, buf) do {} while (0)
	#endif // !W2E_DEBUG_NO_HEX

#endif // W2E_DEBUG


/**
 * Verbose log.
 */
#ifndef W2E_VERBOSE
 /** Verbose printf macro NOP */
#define w2e_log_printf(...) do {} while (0)
#else
/** Define verbose printf macro */
#define w2e_log_printf(fmt, ...) do { printf("[LOG]  %16s:%-5d %32s():  " fmt, __FILENAME__, __LINE__, __func__, ##__VA_ARGS__); } while (0)
#endif // !W2E_VERBOSE


/**
 * Define error printf macro.
 */
#define w2e_print_error(fmt, ...) do { fprintf(stderr, "[ERROR]%16s:%-5d %32s():  " fmt, __FILENAME__, __LINE__, __func__, ##__VA_ARGS__); } while (0)


/**
 * Counters.
 */
typedef struct {
	unsigned int total_rx;	/* Total received packets */
	unsigned int total_tx;	/* Total sent packets (attempts: including errors in err_tx) */
	unsigned int ok_rx;		/* Correct packets received */
	unsigned int ok_tx;		/* Correct packets sent */
	unsigned int err_rx;	/* Malformed packets received */
	unsigned int err_tx;	/* Packets loss on send */
	unsigned int encap;		/* Number of encapsulated packets */
	unsigned int decap;		/* Number of decapsulated packets */
} w2e_ctrs_t;

/**
 * Shared-memory (platform-specific).
 * @TODO
 */
#if 0
#ifdef _MSC_VER // Windows

#else // Linux
void* shmm_create(size_t size)
{
	return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, -1, 0);
}
#endif // ?_MSC_VER
#endif /* 0 */


///**
// * UDP encrypted marker.
// */
//#define W2E_UDP_SERVER_PORT_MARKER 0x1488


/**
 * "Preamble" is placed before packet and used for insertion of new IP + UDP header.
 * Currently IPv4 without options + ICMPv4 (or UDP)
 */
#define W2E_PREAMBLE_SIZE 20 + 8 // IPv4 + ICMPv4 (or UDP)


// IPv4 header template. <These> fields will be edited.
// |version=4,ihl=5| tos=0  |     <packet size>    |
// |           id=0         |R=0,DF=1,MF=0,offset=0|
// |   TTL=255     |proto=17|         <crc>        |
// |                    <IP src>                   |
// |                    <IP dst>                   |
static const uint8_t w2e_template_iph[] = {
	0x45, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00,
	0xFF, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};


/**
 * Vaildate decapsulated packet.
 * Check if packet starts from IPv4 header (4) length of 40 bytes (5).
 */
#define w2e_common__validate_dec(p) (p[0] == 0x45)


#endif // __W2E_COMMON_H
