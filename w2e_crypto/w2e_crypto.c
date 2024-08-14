/*****************************************************************//**
 * \file   w2e_crypto.h
 * \brief  Cross-platform cryptographic interface
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#include "w2e_crypto.h"


static void*	_ctx_enc = NULL;
static void*	_ctx_dec = NULL;
static int		key_len = 0; /** In bytes */


int w2e_crypto_init(const u8* key, size_t len)
{
	w2e_log_printf("Crypto init...\n");

	_ctx_enc = aes_encrypt_init(key, len);
	if (!_ctx_enc)
	{
		w2e_print_error("aes_encrypt_init error\n");
		return -1;
	}

	_ctx_dec = aes_decrypt_init(key, len);
	if (!_ctx_dec)
	{
		w2e_print_error("aes_decrypt_init error\n");
		aes_encrypt_deinit(_ctx_enc);
		_ctx_enc = NULL;
		return -1;
	}

	key_len = (int)len;

	w2e_log_printf("Crypto init OK\n");

	return 0;
}


void w2e_crypto_deinit()
{
	w2e_log_printf("Crypto deinit...\n");

	aes_encrypt_deinit(_ctx_enc);
	aes_encrypt_deinit(_ctx_dec);
	_ctx_enc = NULL;
	_ctx_dec = NULL;
	key_len = 0;

	w2e_log_printf("Crypto deinit OK\n");
}


/**
 * Encrypt buffer of given size sz_fact.
 * sz_max must be equal to size of plains and crypt buffers.
 * Add 0 padding at the end of plaintext (if sz_max affords to).
 * Returns size of resulting array in bytes.
 */
int w2e_crypto_enc(u8* plain, u8* crypt, int sz_fact, int sz_max)
{
	int rem = sz_fact % key_len;
	int blks = sz_fact / key_len;

	if (rem && (sz_max - sz_fact - rem >= 0))
	{
		blks++;

		/** Add padding */
		os_memset(&(plain[sz_fact]), 0, rem);
		
		rem = 0; /** For return: if full block added - rem is 0. Else - return actual size */
	}

	for (int i = 0; i < blks; i++)
	{
		aes_encrypt(_ctx_enc, &(plain[i * key_len]), &(crypt[i * key_len]));
	}

	return blks * key_len + rem;
}


/**
 * Decrypt buffer of given size sz_fact.
 * Be careful -- may contain padding
 */
void w2e_crypto_dec(u8* crypt, const u8* plain, int sz_fact)
{
	if (sz_fact % key_len)
	{
		w2e_print_error("Buffer of wrong size (%d)\n", sz_fact);
	}

	for (int i = 0; i < sz_fact / key_len; i++)
	{
		aes_decrypt(_ctx_dec, &(crypt[i * key_len]), &(plain[i * key_len]));
	}
}

