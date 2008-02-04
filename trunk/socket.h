#ifndef SOCKET_H
#define SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/dh.h>

#define MAX_SOCKS 256

struct _Socket;

typedef void (*handler)(struct _Socket*);
typedef void (*completion_handler)(struct _Socket*, int status);

typedef struct _Socket
{
  /* Actual TCP/IP socket file decriptor. */
  int sock;

  handler readHandler, writeHandler;
  completion_handler readCompleteHandler;
  completion_handler writeCompleteHandler;

  struct {
    buffer readBuffer;
    buffer writeBuffer;
    buffer encryptBuffer;
    buffer decryptBuffer;

    EVP_CIPHER_CTX sessionCtx[2];
    int cipherBlkSize;
  } transferData;

  struct {
    time_t time;
    struct _Socket *next;
    completion_handler timeoutHandler;
  } timeout;

  void *data;
} Socket;

#endif /* SOCKET_H */
