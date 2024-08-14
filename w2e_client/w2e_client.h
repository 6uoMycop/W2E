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
#include <winsock.h>

#include "w2e_common.h"
#include "w2e_crypto.h"
#include "windivert.h"



#ifndef W2E_CLIENT_PORT
/**
 * Client's UDP source port.
 */
#define W2E_CLIENT_PORT 55888
#endif // !W2E_CLIENT_PORT

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

// UDP header template. <These> fields will be edited.
// |      <UDP src>         |       <UDP dst>      |
// |      <UDP len>         |       <UDP crc>      |
#define W2E_TEMPLATE_UDPH \
0x00, 0x00, 0x00, 0x00,\
0x00, 0x00, 0x00, 0x00

// ICMPv4 header template. <These> fields will be edited.
// |  type=8   |  code=0    |       <ICMP crc>     |
// |          <id>          |       <seq>          |
#define W2E_TEMPLATE_ICMPH \
0x08, 0x00, 0x00, 0x00,\
0x00, 0x00, 0x00, 0x00


/**
 * "Preamble" is placed before packet and used for insertion of new IP + UDP header.
 * Currently IPv4 without options + ICMPv4 (or UDP)
 */
#define W2E_PREAMBLE_SIZE 20 + 8 // IPv4 + ICMPv4 (or UDP)


#endif // __W2E_CLIENT_H
