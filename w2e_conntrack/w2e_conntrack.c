/*****************************************************************//**
 * \file   w2e_conntrack.c
 * \brief  Conntrack implementation for secure connections
 * 
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/

#include "w2e_conntrack.h"


/**
 * Conntrack table.
 */
static w2e_ct_entry_t **w2e_ct = NULL;


/**
 * Returns current time in seconds.
 */
static inline uint32_t __w2e_conntrack__seconds()
{

#if !defined(_WIN32) && !defined(__APPLE__)
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1)
	{
		w2e_print_error("clock gettime error\n");
		return 0xFFFFFFFF;
	}
	return t.tv_sec;
#else
	return clock() / CLOCKS_PER_SEC; // For Windows debug //@TODO remove
#endif
}


/**
 * Hash function wrapper.
 */
static inline uint32_t __w2e_conntrack__hash(const w2e_ct_tuple_t* tuple)
{
	//@TODO add real hash

	return tuple->addr[0] ^ tuple->addr[1] ^ tuple->port[0] ^ tuple->port[1] ^ tuple->proto;
}


/**
 * Conntrack initialization. Allocates memory for hash table. Returns 0 on success.
 */
int w2e_conntrack__init()
{
	w2e_log_printf("Conntrack initialization...");

	if (w2e_ct)
	{
		w2e_print_error("Conntrack seems to be initialized already\n");
		return 1;
	}

	w2e_ct = (w2e_ct_entry_t**)calloc(W2E_CT_BUCKETS, sizeof(w2e_ct_entry_t*));

	return 0;
}


static inline uint8_t __w2e_conntrack__is_expired(const w2e_ct_entry_t* c)
{
	return (int32_t)(c->timeout - __w2e_conntrack__seconds()) <= 0;
}


/**
 * Conntrack deinitialization. Deallocates memory for hash table. Returns 0 on success.
 */
int w2e_conntrack__deinit()
{
	w2e_log_printf("Conntrack deinitialization...");

	if (!w2e_ct)
	{
		w2e_print_error("Conntrack seems to be uninitialized already\n");
		return 1;
	}

	for (int i = 0; i < W2E_CT_BUCKETS; i++) /** In every bucket */
	{
		for (w2e_ct_entry_t* p = w2e_ct[i], *p_cur = p; p; p_cur = p) /** Free all entries */
		{
			p = p->next;
			free(p_cur);
		}
	}

	free(w2e_ct);
	w2e_ct = NULL;

	return 0;
}


/**
 * Initialize conntrack entry. If input is NULL, allocate memory. Returns entry (or NULL on error).
 */
static inline w2e_ct_entry_t* __w2e_conntrack__create(w2e_ct_entry_t* entry, const w2e_ct_tuple_t* tuple)
{
	if (!entry)
	{

	}

	return entry;
}


/**
 * Resolve conntrack entry of given tuple.
 * If doesn't exist - create new.
 */
w2e_ct_entry_t* w2e_conntrack__resolve(const w2e_ct_tuple_t* tuple)
{
	w2e_ct_entry_t* ptr = NULL;

	if (!w2e_ct)
	{
		w2e_print_error("Conntrack uninitialized\n");
		return NULL;
	}

	/** Get bucket and go through collisions list */
	for (ptr = &(w2e_ct[__w2e_conntrack__hash(tuple)]); ptr; ptr = ptr->next)
	{
		if (ptr->status == 0) /** Unused (first) entry */
		{
			/** Create new entry here */


		}
	}

	return ptr;
}

