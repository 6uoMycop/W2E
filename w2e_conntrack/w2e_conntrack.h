/*****************************************************************//**
 * \file   w2e_conntrack.h
 * \brief  Conntrack implementation for secure connections
 * 
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_CONNTRACK_H
#define __W2E_CONNTRACK_H


#include "w2e_common.h"
#include <time.h>
#include <stdatomic.h>
//@TODO #include "linux/xxhash.h"


#ifndef W2E_CT_SESSION_TTL
 /**
  * Time to session live in conntrack in seconds.
  */
#define W2E_CT_SESSION_TTL 300
#endif // !W2E_CT_SESSION_TTL


/**
 * Number of conntrack buckets. Equals hash length.
 */
#define W2E_CT_BUCKETS UINT32_MAX


/**
 * The 5-tuple structure.
 * 
 */
typedef struct {
	uint32_t addr[2];
	uint16_t port[2];
	uint8_t proto;
} w2e_ct_tuple_t;


/**
 * Conntrack entry.
 */
typedef struct {
	/** Linked list */
	w2e_ct_entry_t* prev;
	w2e_ct_entry_t* next;

	/** Atomic entry status. 0 - unused, 1 - alive, 2 - mark to deletion */
	//_Atomic char status;
	char status; //@TODO atomic
	/** 5-tuple of connection */
	w2e_ct_tuple_t tuple;
	/** 5-tuple hash */
	uint32_t hash;
	/** Timeout timer */
	uint32_t timeout;
	/** Corresponding client ID */
	uint16_t id_client;
} w2e_ct_entry_t;


#endif /* __W2E_CONNTRACK_H */
