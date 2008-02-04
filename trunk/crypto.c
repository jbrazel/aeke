#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "buffer.h"
#include "io.h"
#include "common.h"
#include "crypto.h"
#include "log.h"

extern int debug;

const EVP_CIPHER *cipher = NULL;
int cipher_blk_size = 0;

void
initCrypto(void)
{
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  
  cipher = EVP_get_cipherbyname(AEKE_CIPHER);
  assert(EVP_CIPHER_key_length(cipher) == MD5_DIGEST_LENGTH);

  cipher_blk_size = EVP_CIPHER_block_size(cipher);
  atexit(cleanupCrypto);
}

void
cleanupCrypto(void)
{
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0);
}

void
makeHash(const unsigned char *input, unsigned int input_len,
	 unsigned char *output)
{
  MD5_CTX password_hash;
  
  MD5_Init(&password_hash);
  MD5_Update(&password_hash, input, input_len);
  MD5_Final(output, &password_hash);
  
  memset(&password_hash, 0, sizeof(password_hash));
}

int
initPkeyPair(Socket *s)
{
  /* Generate a Diffie-Hellman public/private key pair.
   * Encrypt the public key with the hash of our login password, prepend
   * it's (encrypted) length as a u_short (network-order), ready for
   * sending.
   */
  
  AekeSocket *a = (AekeSocket*)s->data;
  BIGNUM *generator = NULL, *prime = NULL;
  EVP_CIPHER_CTX cipherCtx;
  int sz, t, rv = 0;
  unsigned char *scratch, *sendBuf;
  
  /* DH */
  
  a->cryptoData.key = DH_new();
  
  BN_hex2bn(&generator, DH_GENERATOR);
  BN_hex2bn(&prime, DH_PRIME); 
  a->cryptoData.key->g = generator; 
  a->cryptoData.key->p = prime;
  
  DH_generate_key(a->cryptoData.key);
  
  /* AES */
  
  EVP_CIPHER_CTX_init(&cipherCtx);
  EVP_EncryptInit(&cipherCtx, cipher, a->cryptoData.password, NULL);
  
  /* Encrypt public key with hash of login password */
  
  sz = BN_num_bytes(a->cryptoData.key->pub_key);
  sz += cipher_blk_size - 1;
  sz /= cipher_blk_size;
  sz *= cipher_blk_size;

  /* Include extra space for CBC-mode initialisation vector,
   * and length prefix.
   */
  
  sendBuf = setupForWrite(s, cipher_blk_size + sz, 1);

  scratch = (unsigned char*)xmalloc(sz);
  BN_bn2bin(a->cryptoData.key->pub_key, scratch);

  dbgHexDump(3, "initPkeyPair: pubkey: ", scratch, sz);
  dbgMsg(3, "initPkeyPair: %i bytes to send\n", s->transferData.writeBuffer.totalLength);

  if (! EVP_EncryptUpdate(&cipherCtx, sendBuf, &t, scratch, sz))
    rv = -1;
  else if (! EVP_EncryptFinal(&cipherCtx, sendBuf + t, &t))
    rv = -1;

  if (rv == 0)
    dbgHexDump(3, "initPkeyPair: encrypted pubkey: ", sendBuf, sz);

  memset(scratch, 0, sz);
  xfree(scratch);

  EVP_CIPHER_CTX_cleanup(&cipherCtx);

  /* prime, generator freed when a->cryptoData.key is freed. */
  return rv;
}

int
generateSessionKey(Socket *s)
{
  EVP_CIPHER_CTX cipherCtx;
  unsigned char *decryptedData;
  unsigned int decryptDataLength;
  int sizeOfDecryptedData, t;
  int sharedKeyLength, rv = -1;
  unsigned char *sharedKey;
  AekeSocket *a = (AekeSocket*)s->data;

  decryptDataLength = s->transferData.readBuffer.totalLength + cipher_blk_size - 1;
  decryptDataLength /= cipher_blk_size;
  decryptDataLength *= cipher_blk_size;

  dbgHexDump(3, "genSessionKey: encrypted peer pubkey: ", 
	     s->transferData.readBuffer.b.buffer, 
	     s->transferData.readBuffer.totalLength);

  decryptedData = (unsigned char*)xmalloc(decryptDataLength);
  EVP_CIPHER_CTX_init(&cipherCtx);
  EVP_DecryptInit(&cipherCtx, cipher, a->cryptoData.password, NULL);

  if (! EVP_DecryptUpdate(&cipherCtx, decryptedData, &sizeOfDecryptedData,
			  s->transferData.readBuffer.b.buffer, 
			  s->transferData.readBuffer.totalLength))
    {
      errMsg("Decryption of peer DH key failed\n");
      goto cleanup_return;
    }

  if (! EVP_DecryptFinal(&cipherCtx, decryptedData + sizeOfDecryptedData, &t))
    {
      errMsg("Decryption of peer DH key failed! (Final block)\n");
      goto cleanup_return;
    }

  sizeOfDecryptedData += t;

  dbgHexDump(3, "genSessionKey: decrypted peer pubkey: ", 
	     decryptedData, sizeOfDecryptedData);

  {
    BIGNUM *pubkey = BN_bin2bn(decryptedData, sizeOfDecryptedData, NULL);

    if (pubkey == NULL)
      {
	errMsg("Bad key! (decrypted contents not a valid bignum)\n");
	goto cleanup_return;
      }

    sharedKey = (unsigned char*)xmalloc(DH_size(a->cryptoData.key));
    sharedKeyLength = DH_compute_key(sharedKey, pubkey, a->cryptoData.key);
    BN_free(pubkey);
  }

  if (sharedKeyLength < 0)
    {
      errMsg("DH key computation failed!\n");
      xfree(sharedKey);
      goto cleanup_return;
    }

  makeHash(sharedKey, sharedKeyLength, a->cryptoData.sessionKey);
  memset(sharedKey, 0, sharedKeyLength);
  xfree(sharedKey);

  dbgHexDump(3, "sessionKey: ", a->cryptoData.sessionKey, MD5_DIGEST_LENGTH);

  enableEncryption(s, cipher, a->cryptoData.sessionKey);
  rv = 0;

 cleanup_return:

  memset(decryptedData, 0, decryptDataLength);
  xfree(decryptedData);

  EVP_CIPHER_CTX_cleanup(&cipherCtx);  
  
  DH_free(a->cryptoData.key);
  a->cryptoData.key = NULL;

  return rv;
}

void
generateClientVerifier(Socket *s)
{
  /* The client generates a 'verifier' to send to the server.
   * This verifier both authenticates the child connection by
   * providing its plaintext password (which the server hashes
   * and compares to its password file), and a random nonce that
   * it expects the server to hash and return. The returned, 
   * hashed nonce indicates to the client that the server has 
   * successfully completed to handshake process.
   *
   * Bytes 0..15 - 16-byte random nonce
   * Bytes 16..N - n-bytes plaintext password (padded to blocksize
   *               bytes with random data prior to encryption).
   */

  int credLength, passwordLength;
  unsigned char *credentials;
  AekeSocket *a = (AekeSocket*)s->data;

  credLength = MD5_DIGEST_LENGTH + 
    strlen(a->cryptoData.authenticationData.clientSide.cleartextPassword) + 
    EVP_CIPHER_block_size(cipher);

  credLength /= EVP_CIPHER_block_size(cipher);
  credLength *= EVP_CIPHER_block_size(cipher);
  
  credentials = setupForWrite(s, credLength, 1);

  RAND_bytes(credentials, MD5_DIGEST_LENGTH);
  makeHash(credentials, MD5_DIGEST_LENGTH, 
	    a->cryptoData.authenticationData.clientSide.verifier);
  credentials += MD5_DIGEST_LENGTH;
  credLength -= MD5_DIGEST_LENGTH;
  
  passwordLength = strlen(a->cryptoData.authenticationData.clientSide.cleartextPassword) + 1;
  memcpy((char*)credentials, 
	 a->cryptoData.authenticationData.clientSide.cleartextPassword, 
	 passwordLength);
  credentials += passwordLength;
  credLength -= passwordLength;

  RAND_bytes(credentials, credLength);

  dbgHexDump(3, "Client verifier: ", s->transferData.writeBuffer.b.buffer + 2, 
	     s->transferData.writeBuffer.totalLength - 2);
}

int
checkServerAck(Socket *s)
{
  AekeSocket *a = (AekeSocket*)s->data;

  return memcmp(s->transferData.readBuffer.b.buffer,
		a->cryptoData.authenticationData.clientSide.verifier, 
		MD5_DIGEST_LENGTH);
}

int
verifyClient(Socket *s)
{
  AekeSocket *a = (AekeSocket*)s->data;

  /* Hash the password & compare to our copy.
   * Hash the random nonce and return it.
   */

  unsigned char hashedPassword[MD5_DIGEST_LENGTH];
  unsigned char *clearPassword = s->transferData.readBuffer.b.buffer + MD5_DIGEST_LENGTH;

  makeHash(clearPassword, strlen((char*)clearPassword), hashedPassword);
  
  if (memcmp(hashedPassword, a->cryptoData.password, MD5_DIGEST_LENGTH) == 0)
    {
      unsigned char *ack = setupForWrite(s, MD5_DIGEST_LENGTH, 1);
      makeHash(s->transferData.readBuffer.b.buffer, MD5_DIGEST_LENGTH, ack);
      dbgMsg(2, "Server: Passwords match, acking...\n");
      return 0;
    }
  else
    {
      errMsg("Server: Passwords don't match, denying.\n");
      return -1;
    }
}

void
cleanupConnCrypto(Socket *s)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (a->cryptoData.key != NULL)
    {
      DH_free(a->cryptoData.key);
      a->cryptoData.key = NULL;
    }

  memset(a->cryptoData.authenticationData.serverSide.clientVerifier, 0, 
	 sizeof(a->cryptoData.authenticationData.serverSide.clientVerifier));
}

/* EOF */
