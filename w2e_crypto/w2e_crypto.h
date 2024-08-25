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
 * Initialize cryptographic context.
 */
int w2e_crypto_init(const u8* key, size_t len);


/**
 * Deinitialize cryptographic context.
 */
void w2e_crypto_deinit();

/**
 * Encrypt buffer of given size sz_fact.
 * sz_max must be equal to size of plains and crypt buffers.
 * Add 0 padding at the end of plaintext (if sz_max affords to).
 * Returns size of resulting array in bytes.
 */
int w2e_crypto_enc(u8* plain, u8* crypt, int sz_fact, int sz_max);

/**
 * Decrypt buffer of given size sz_fact.
 * Be careful -- may contain padding
 */
void w2e_crypto_dec(const u8* crypt, u8* plain, int sz_fact);

/**
 * Decrypt payload of IPv4-encapsulated packet.
 * I.e. obtain actual packet size from IPv4 header's total length.
 * Returns real packet's length (without padding).
 */
int w2e_crypto_dec_pkt_ipv4(const u8* crypt, u8* plain, int sz_total);


#endif // __W2E_CRYPTO_H
