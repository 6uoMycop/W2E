/*****************************************************************//**
 * \file   w2e_crypto.h
 * \brief  Cross-platform cryptographic interface
 * 
 * \author ark
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

void w2e_crypto_enc(const u8* plain, u8* crypt);

void w2e_crypto_dec(const u8* plain, u8* crypt);


#endif // __W2E_CRYPTO_H
