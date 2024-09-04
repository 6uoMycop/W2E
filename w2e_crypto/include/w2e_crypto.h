/*****************************************************************//**
 * \file   w2e_crypto.h
 * \brief  Cross-platform cryptographic interface
 * 
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/


#ifndef __W2E_CRYPTO_H
#define __W2E_CRYPTO_H


#include "w2e_common.h"

#include "aes.h"


/**
 * AES.
 */

/**
 * Handles for encryption and decryption.
 */
typedef struct {
	void* enc;
	void* dec;
	int key_len; /** In bytes */
} w2e_crypto__handle_t;

/**
 * Initialize cryptographic context.
 */
int w2e_crypto__init(const u8* key, size_t len, w2e_crypto__handle_t* handle);


/**
 * Deinitialize cryptographic context.
 */
void w2e_crypto__deinit(w2e_crypto__handle_t* handle);

/**
 * Encrypt buffer of given size sz_fact.
 * sz_max must be equal to size of plains and crypt buffers.
 * Add 0 padding at the end of plaintext (if sz_max affords to).
 * Returns size of resulting array in bytes.
 */
int w2e_crypto__enc(u8* plain, u8* crypt, int sz_fact, int sz_max, const w2e_crypto__handle_t* handle);

/**
 * Decrypt buffer of given size sz_fact.
 * Be careful -- may contain padding
 */
void w2e_crypto__dec(const u8* crypt, u8* plain, int sz_fact, const w2e_crypto__handle_t* handle);

/**
 * Decrypt payload of IPv4-encapsulated packet.
 * I.e. obtain actual packet size from IPv4 header's total length.
 * Returns real packet's length (without padding).
 */
int w2e_crypto__dec_pkt_ipv4(const u8* crypt, u8* plain, int sz_total, const w2e_crypto__handle_t* handle);


#endif // __W2E_CRYPTO_H

