/*****************************************************************//**
 * \file   w2e_conntrack.c
 * \brief  Conntrack implementation for secure connections
 * 
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/

#include "w2e_conntrack.h"

/**
 * xxHash.
 */

#define XXH_IMPLEMENTATION		/* access definitions */
#define XXH_NO_STDLIB		/* Disable invocation of <stdlib.h> functions, notably malloc() and free().
libxxhash's XXH*_createState() will always fail and return NULL. But one-shot hashing (like XXH32())
or streaming using statically allocated states still work as expected. This build flag is useful for
embedded environments without dynamic allocation. */
#define XXH_NO_XXH3			/* removes symbols related to XXH3 */
#define XXH_NO_LONG_LONG	/* Only XXH32 will be compiled */
#define XXH_NO_STREAM		/* Disables the streaming API, limiting the library to single shot variants only. */
#include "xxhash.h"


/**
 * Prototypes.
 */

static void* __w2e_conntrack__gc_worker(void* vptr_args);
static uint32_t __w2e_conntrack__reciprocal_scale(uint32_t val, uint32_t ep_ro);
static uint32_t __w2e_conntrack__seconds(void);
static uint32_t __w2e_conntrack__hash_raw(const w2e_ct_tuple_t* tuple);
static uint32_t __w2e_conntrack__hash(const w2e_ct_tuple_t* tuple);
static uint8_t __w2e_conntrack__is_expired(const w2e_ct_entry_t* c);
static uint8_t __w2e_conntrack__compare_tuples(const w2e_ct_tuple_t* t1, const w2e_ct_tuple_t* t2);
static void __w2e_conntrack__create_tuple(uint32_t a0, uint32_t a1, uint16_t p0, uint16_t p1, uint8_t proto, w2e_ct_tuple_t* tuple);
static void __w2e_conntrack__create_tuple_raw(uint8_t* l3, uint8_t* l4, w2e_ct_tuple_t* tuple);
static void __w2e_conntrack__insert(w2e_ct_entry_t* entry);
w2e_ct_entry_t* __w2e_conntrack__resolve(const w2e_ct_tuple_t* tuple);
static void __w2e_conntrack__upd_timeout(w2e_ct_entry_t* entry);
static w2e_ct_entry_t* __w2e_conntrack__create(const w2e_ct_tuple_t* tuple, uint16_t client);


/**
 * Conntrack table. Index in this array is hash itself.
 */
static w2e_ct_entry_t *w2e_ct = NULL;

/**
 * Garbage collector thread.
 */
static pthread_t gc_thread;
static volatile int gc_stop = 0;


/**
 * Garbage collector thread worker.
 */
static void* __w2e_conntrack__gc_worker(void* vptr_args)
{
	(void)vptr_args;

	w2e_ct_entry_t* bucket = NULL;
	w2e_ct_entry_t* ct = NULL;
	w2e_ct_entry_t* tmp = NULL;

	while (!gc_stop)
	{
		/** In every bucket */
		for (unsigned int i = 0; i < W2E_CT_BUCKETS; i++)
		{
			/** Get bucket */
			bucket = &(w2e_ct[i]);
			/** Check list */
			list_for_each_entry_safe(ct, tmp, &(bucket->list), list)
			{
				if (__w2e_conntrack__is_expired(ct))
				{
					pthread_mutex_lock(&(bucket->mutex));
					w2e_dbg_printf("Deleted ct entry by timeout: 0x%08X 0x%08X 0x%04X 0x%04X 0x%02X\n",
									ct->tuple.addr[0], ct->tuple.addr[1], ct->tuple.port[0], ct->tuple.port[1], ct->tuple.proto);
					/* Remove the component from the list */
					list_del(&(ct->list));
					/* Free the memory */
					free(ct);
					pthread_mutex_unlock(&(bucket->mutex));
				}
			}
		}

		sleep(W2E_CT_SESSION_TTL >> 1);
	}

	return NULL;
}



/**
 * __w2e_conntrack__reciprocal_scale - "scale" a value into range [0, ep_ro)
 * @val: value
 * @ep_ro: right open interval endpoint
 *
 * Perform a "reciprocal multiplication" in order to "scale" a value into
 * range [0, ep_ro), where the upper interval endpoint is right-open.
 * This is useful, e.g. for accessing a index of an array containing
 * ep_ro elements, for example. Think of it as sort of modulus, only that
 * the result isn't that of modulo. ;) Note that if initial input is a
 * small value, then result will return 0.
 *
 * Return: a result based on val in interval [0, ep_ro).
 */
static inline uint32_t __w2e_conntrack__reciprocal_scale(uint32_t val, uint32_t ep_ro)
{
	return (uint32_t)(((uint64_t)val * ep_ro) >> 32);
}


/**
 * Returns current time in seconds.
 */
static inline uint32_t __w2e_conntrack__seconds(void)
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
static inline uint32_t __w2e_conntrack__hash_raw(const w2e_ct_tuple_t* tuple)
{
	return XXH32(tuple, sizeof(w2e_ct_tuple_t), 0);
}


/**
 * Hash reduced to length. Can be used as index.
 */
static inline uint32_t __w2e_conntrack__hash(const w2e_ct_tuple_t* tuple)
{
	return __w2e_conntrack__reciprocal_scale(__w2e_conntrack__hash_raw(tuple), W2E_CT_HASHSIZE);
}


/**
 * Check if conntrack entry is expired.
 */
static inline uint8_t __w2e_conntrack__is_expired(const w2e_ct_entry_t* c)
{
	return (int32_t)(c->timeout - __w2e_conntrack__seconds()) <= 0;
}


/**
 * Compare if tuples are identical.
 */
static inline uint8_t __w2e_conntrack__compare_tuples(const w2e_ct_tuple_t* t1, const w2e_ct_tuple_t* t2)
{
	return !memcmp(t1, t2, sizeof(w2e_ct_tuple_t));
}


/**
 * Create w2e_ct_tuple_t from 5-tuple.
 */
static inline void __w2e_conntrack__create_tuple(
	uint32_t a0, uint32_t a1,
	uint16_t p0, uint16_t p1,
	uint8_t proto,
	w2e_ct_tuple_t* tuple)
{
	memset(tuple, 0, sizeof(w2e_ct_tuple_t));

	/**
	 * Store minimal address and port values first.
	 */

	tuple->addr[0] = (a0 < a1) ? a0 : a1;
	tuple->addr[1] = (a0 > a1) ? a0 : a1;

	tuple->port[0] = (p0 < p1) ? p0 : p1;
	tuple->port[1] = (p0 > p1) ? p0 : p1;

	tuple->proto = proto;

	//w2e_dbg_printf(
	//	"Create tuple: 0x%08X 0x%08X 0x%04X 0x%04X 0x%02X\n",
	//	tuple->addr[0], tuple->addr[1], tuple->port[0], tuple->port[1], tuple->proto);
}


/**
 * Create w2e_ct_tuple_t from raw headers.
 */
static inline void __w2e_conntrack__create_tuple_raw(uint8_t* l3, uint8_t* l4, w2e_ct_tuple_t* tuple)
{
	/**
	 * Fill in tuple.
	 * Don't call ntoh...(), doesn't matter.
	 */
	__w2e_conntrack__create_tuple(
		*((uint32_t*)(l3 + 12)),
		*((uint32_t*)(l3 + 16)),
		*((uint16_t*)(l4)),
		*((uint16_t*)(l4 + 2)),
		*((uint8_t*)(l3 + 9)),
		tuple
	);
}


/**
 * Insert entry into table.
 */
static inline void __w2e_conntrack__insert(w2e_ct_entry_t* entry)
{
	w2e_ct_entry_t* bucket = NULL;
	uint32_t idx;

	/** Get bucket address*/
	idx = __w2e_conntrack__hash(&(entry->tuple));
	bucket = &(w2e_ct[idx]);

	/** Insert entry to list */
	pthread_mutex_lock(&(bucket->mutex));
	list_add_tail(&(entry->list), &(bucket->list));
	pthread_mutex_unlock(&(bucket->mutex));

	//w2e_dbg_printf("Inserting to bucket %d\n", idx);
}


/**
 * Create new connection: allocate memory, initialize, insert to table.
 * l3/4 - pointers to IP and transport headers. client - client's ID.
 * Returns NULL on error.
 */
w2e_ct_entry_t* w2e_conntrack__create(uint8_t* l3, uint8_t* l4, uint16_t client)
{
	w2e_ct_tuple_t tuple;

	if (!w2e_ct)
	{
		w2e_print_error("Conntrack uninitialized\n");
		return NULL;
	}

	/** init tuple */
	__w2e_conntrack__create_tuple_raw(l3, l4, &tuple);

	return __w2e_conntrack__create(&tuple, client);
}


/**
 * Resolve conntrack entry of given tuple.
 * If doesn't exist - return NULL.
 */
w2e_ct_entry_t* __w2e_conntrack__resolve(const w2e_ct_tuple_t* tuple)
{
	w2e_ct_entry_t* bucket = NULL;
	struct list_head* p = NULL;
	w2e_ct_entry_t* ct = NULL;

	/** Get bucket */
	bucket = &(w2e_ct[__w2e_conntrack__hash(tuple)]);

	/* Go through collisions list */
	list_for_each(p, &(bucket->list))
	{
		ct = list_entry(p, w2e_ct_entry_t, list);
		if (__w2e_conntrack__compare_tuples(&(ct->tuple), tuple))
		{
			/** Set timeout */
			pthread_mutex_lock(&(bucket->mutex));
			__w2e_conntrack__upd_timeout(ct);
			pthread_mutex_unlock(&(bucket->mutex));

			return ct;
		}
	}

	/** None found */
	return NULL;
}


/**
 * Update entry timeout.
 */
static inline void __w2e_conntrack__upd_timeout(w2e_ct_entry_t* entry)
{
	entry->timeout = __w2e_conntrack__seconds() + W2E_CT_SESSION_TTL;
}


/**
 * Initialize conntrack entry. Insert into table. Returns the new entry (or NULL on error).
 */
static inline w2e_ct_entry_t* __w2e_conntrack__create(const w2e_ct_tuple_t* tuple, uint16_t client)
{
	w2e_ct_entry_t* entry = NULL;

	/** Try to find entry at first */
	entry = __w2e_conntrack__resolve(tuple);
	if (entry)
	{
		w2e_dbg_printf("Entry already exists\n");
		return entry;
	}

	entry = (w2e_ct_entry_t*)calloc(1, sizeof(w2e_ct_entry_t));
	if (!entry)
	{
		w2e_print_error("Can't allocate memory\n");
		return NULL;
	}

	/** Copy 5-tuple */
	memcpy(&(entry->tuple), tuple, sizeof(w2e_ct_tuple_t));
	/** Set timeout */
	__w2e_conntrack__upd_timeout(entry);
	/** Set client ID */
	entry->id_client = client;

	/** Insert entry into table */
	__w2e_conntrack__insert(entry);

	return entry;
}


/**
 * Resolve conntrack entry of given raw headers.
 * If doesn't exist - return NULL.
 * l3/4 - pointers to IP and transport headers.
 * * Assume that only clients can initiate connections.
 * * So call w2e_conntrack_create() on decapsulation //@TODO
 */
w2e_ct_entry_t* w2e_conntrack__resolve(uint8_t* l3, uint8_t* l4)
{
	w2e_ct_tuple_t tuple;

	if (!w2e_ct)
	{
		w2e_print_error("Conntrack uninitialized\n");
		return NULL;
	}

	/** init tuple */
	__w2e_conntrack__create_tuple_raw(l3, l4, &tuple);

	return __w2e_conntrack__resolve(&tuple);
}


/**
 * Conntrack initialization. Allocates memory for hash table. Returns 0 on success.
 */
int w2e_conntrack__init(void)
{
	w2e_log_printf("Conntrack initialization...\n");

	if (w2e_ct)
	{
		w2e_print_error("Conntrack seems to be initialized already\n");
		return 1;
	}

	w2e_ct = (w2e_ct_entry_t*)calloc(W2E_CT_BUCKETS, sizeof(w2e_ct_entry_t));
	if (!w2e_ct)
	{
		w2e_print_error("Can't allocate memory\n");
		return 1;
	}

	for (int i = 0; i < W2E_CT_BUCKETS; i++)
	{
		/** Init list in every bucket */
		INIT_LIST_HEAD(&(w2e_ct[i].list));
		/** Init mutex in every bucket //@TODO make adequate sync */
		pthread_mutex_init(&(w2e_ct[i].mutex), NULL);
	}

	/** Garbage collector thread start */
	pthread_create(&gc_thread, NULL, __w2e_conntrack__gc_worker, NULL);
	pthread_detach(gc_thread);

	return 0;
}


/**
 * Conntrack deinitialization. Deallocates memory for hash table. Returns 0 on success.
 */
int w2e_conntrack__deinit(void)
{
	w2e_ct_entry_t* bucket = NULL;
	w2e_ct_entry_t* ct = NULL;
	w2e_ct_entry_t* tmp = NULL;

	w2e_log_printf("Conntrack deinitialization...\n");

	if (!w2e_ct)
	{
		w2e_print_error("Conntrack seems to be uninitialized already\n");
		return 1;
	}

	/** Garbage collector thread stop */
	gc_stop = 1;

	/** In every bucket */
	for (unsigned int i = 0; i < W2E_CT_BUCKETS; i++)
	{
		/** Get bucket */
		bucket = &(w2e_ct[i]);
		/** Free list */
		list_for_each_entry_safe(ct, tmp, &(bucket->list), list)
		{
			w2e_dbg_printf("Deleted ct entry : 0x%08X 0x%08X 0x%04X 0x%04X 0x%02X\n",
				ct->tuple.addr[0], ct->tuple.addr[1], ct->tuple.port[0], ct->tuple.port[1], ct->tuple.proto);
			pthread_mutex_lock(&(bucket->mutex));
			/* Remove the component from the list */
			list_del(&(ct->list));
			/* Free the memory */
			free(ct);
			pthread_mutex_lock(&(bucket->mutex));
		}
	}

	/** Free hash table */
	free(w2e_ct);
	w2e_ct = NULL;

	return 0;
}
