/*****************************************************************//**
 * \file   w2e_crypto.h
 * \brief  Cross-platform cryptographic interface
 *
 * \author 6uoMycop
 * \date   August 2024
 *********************************************************************/


#include "w2e_crypto.h"


int w2e_crypto__init(const u8* key, size_t len, w2e_crypto__handle_t* handle)
{
	w2e_log_printf("Crypto init...\n");

	handle->enc = aes_encrypt_init(key, len);
	if (!handle->enc)
	{
		w2e_print_error("aes_encrypt_init error\n");
		return -1;
	}

	handle->dec = aes_decrypt_init(key, len);
	if (!handle->dec)
	{
		w2e_print_error("aes_decrypt_init error\n");
		aes_encrypt_deinit(handle->enc);
		handle->enc = NULL;
		return -1;
	}

	handle->key_len = (int)len;

	return 0;
}


void w2e_crypto__deinit(w2e_crypto__handle_t* handle)
{
	aes_encrypt_deinit(handle->enc);
	aes_encrypt_deinit(handle->dec);
	handle->enc = NULL;
	handle->dec = NULL;
	handle->key_len = 0;
}


/**
 * Encrypt buffer of given size sz_fact.
 * sz_max must be equal to size of plain and crypt buffers.
 * Add 0 padding at the end of plaintext (if sz_max affords to).
 * Returns size of resulting array in bytes.
 */
int w2e_crypto__enc(u8* plain, u8* crypt, int sz_fact, int sz_max, const w2e_crypto__handle_t* handle)
{
	int rem = sz_fact % handle->key_len;
	int blks = sz_fact / handle->key_len;

	if (rem && (sz_max - sz_fact - rem >= 0))
	{
		blks++;

		/** Add padding */
		os_memset(&(plain[sz_fact]), 0, rem);
		
		rem = 0; /** For return: if full block added - rem is 0. Else - return actual size */
	}

	for (int i = 0; i < blks; i++)
	{
		aes_encrypt(handle->enc, &(plain[i * handle->key_len]), &(crypt[i * handle->key_len]));
	}

	return blks * handle->key_len + rem;
}


/**
 * Decrypt buffer of given size sz_fact.
 * Be careful -- may contain padding
 */
void w2e_crypto__dec(const u8* crypt, u8* plain, int sz_fact, const w2e_crypto__handle_t* handle)
{
	if (sz_fact % handle->key_len)
	{
		w2e_print_error("Buffer of wrong size (%d)\n", sz_fact);
	}

	for (int i = 0; i < sz_fact / handle->key_len; i++)
	{
		aes_decrypt(handle->dec, &(crypt[i * handle->key_len]), &(plain[i * handle->key_len]));
	}
}


/**
 * Decrypt payload of IPv4-encapsulated packet.
 * I.e. obtain actual packet size from IPv4 header's total length.
 * Returns real packet's length (without padding).
 */
int w2e_crypto__dec_pkt_ipv4(const u8* crypt, u8* plain, int sz_total, const w2e_crypto__handle_t* handle)
{
	int sz_real = 0;

	/**
	 * Decrypt first block. First 20 bytes are always valid
	 */
	aes_decrypt(handle->dec, crypt, plain);

	/**
	 * Obtain IPv4 packet length field value.
	 * It is 2nd and 3rd IPv4 header bytes.
	 */
	sz_real = ntohs(*(u16*)(&(plain[2])));
	w2e_dbg_printf("Encapsulated payload length=%d\n", sz_real);

	/**
	 * Decrypt the rest of packet.
	 */
	w2e_crypto__dec(&(crypt[handle->key_len]), &(plain[handle->key_len]), sz_total - handle->key_len, handle);


	return sz_real;
}

