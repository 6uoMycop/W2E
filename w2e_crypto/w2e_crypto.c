/*****************************************************************//**
 * \file   w2e_crypto.h
 * \brief  Cross-platform cryptographic interface
 *
 * \author ark
 * \date   August 2024
 *********************************************************************/


#include "w2e_crypto.h"


static void* _ctx_enc = NULL;
static void* _ctx_dec = NULL;


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

	w2e_log_printf("Crypto init OK\n");

	return 0;
}


void w2e_crypto_deinit()
{
	w2e_log_printf("Crypto deinit...\n");

	aes_encrypt_deinit(_ctx_enc);
	_ctx_enc = NULL;
	aes_encrypt_deinit(_ctx_dec);
	_ctx_dec = NULL;

	w2e_log_printf("Crypto deinit OK\n");
}



void w2e_crypto_enc(const u8* plain, u8* crypt)
{
	aes_encrypt(_ctx_enc, plain, crypt);
}


void w2e_crypto_dec(const u8* plain, u8* crypt)
{
	aes_decrypt(_ctx_dec, plain, crypt);
}
