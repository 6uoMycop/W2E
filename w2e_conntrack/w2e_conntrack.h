/*****************************************************************//**
 * \file   w2e_conntrack.h
 * \brief  Conntrack implementation for secure connections
 * 
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_CONNTRACK_H
#define __W2E_CONNTRACK_H


#include <time.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <unistd.h>

#include "w2e_common.h"
#include "w2e_crypto.h"
#include "w2e_linux_list.h"


#ifndef W2E_CT_SESSION_TTL
 /**
  * Time to session live in conntrack in seconds.
  */
#define W2E_CT_SESSION_TTL 300
#endif // !W2E_CT_SESSION_TTL

/**
 * Hash length in bits.
 */
#define W2E_CT_HASHSIZE 16

/**
 * Number of conntrack buckets.
 */
#define W2E_CT_BUCKETS (1 << W2E_CT_HASHSIZE)


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
	struct list_head list;
	/** 5-tuple of connection */
	w2e_ct_tuple_t tuple;
	/** Timeout timer */
	uint32_t timeout;
	/** Corresponding client ID */
	uint16_t id_client;
	/** Bucket mutex (initialized once per bucket only in head) //@TODO make adequate sync */
	pthread_mutex_t mutex;
} w2e_ct_entry_t;


int w2e_conntrack__init(void);

int w2e_conntrack__deinit(void);

w2e_ct_entry_t* w2e_conntrack__create(uint8_t* l3, uint8_t* l4, uint16_t client);

w2e_ct_entry_t* w2e_conntrack__resolve(uint8_t* l3, uint8_t* l4);


#endif /* __W2E_CONNTRACK_H */
