#define MAX_SOCKS 256
#define FD_SETSIZE MAX_SOCKS
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <assert.h>
#include <signal.h>

#include "buffer.h"
#include "io.h"
#include "log.h"


static Socket *sockets[MAX_SOCKS];
static Socket *timeoutList = NULL;
static fd_set socketReadWatch, socketWriteWatch;
static int nSockets = 0;
static int shutdownSet = 0;

/*///////////////////////////////////////////////////////////////////////*/

/* Initialisation and shutdown routines for low-level I/O system. */

static void ioCleanup(void);

void
ioSetup(void)
{
  signal(SIGPIPE, SIG_IGN);

  FD_ZERO(&socketReadWatch);
  FD_ZERO(&socketWriteWatch);

  memset(sockets, 0, sizeof(sockets));

  atexit(ioCleanup);
}

static void
ioCleanup(void)
{
  int i;
  Socket *s;

  for(i=0; i<MAX_SOCKS; i++)
    if ((s = sockets[i]) != NULL)
      {
	shutdownSocket(s);
      }
}

/*///////////////////////////////////////////////////////////////////////*/

void
registerSocket(Socket *s)
{
  assert(sockets[s->sock] == NULL);
  sockets[s->sock] = s;
  nSockets++;

  dbgMsg(3, "%i sockets now registered\n", nSockets);
}

/*///////////////////////////////////////////////////////////////////////*/

static void onConnected(Socket *s);

void 
ioConnect(Socket *s, struct sockaddr_in *addr, completion_handler completionRoutine)
{
  /* This routine is necessary, as we need to reset the fd_set write bit once 
   * we've connected. Only AF_INET socks should block, which is why we don't have
   * ioUnixConnect() etc.
   */

  if (connect(s->sock, (struct sockaddr*)addr, sizeof(*addr)))
    {
      if (errno == EINPROGRESS)
	{
	  dbgMsg(2, "Connect in progress...\n");
	  s->writeCompleteHandler = completionRoutine;
	  onWrite(s, onConnected);
	  return;
	}
      else
	{
	  (*completionRoutine)(s, -errno);
	  return;
	}
    }
  else
    (*completionRoutine)(s, 0);
}

static void
onConnected(Socket *s)
{
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  int status = 0;

  dbgMsg(3, "Now connected.\n");
  FD_CLR(s->sock, &socketWriteWatch);

  if (getpeername(s->sock, (struct sockaddr*)&addr, &addr_len) < 0)  
    status = -1;

  (*s->writeCompleteHandler)(s, status);
}

/*///////////////////////////////////////////////////////////////////////*/

/* Routines that wrangle with the global fd_sets (I/O-driven state
 * machines).
 */

void
onRead(Socket *s, handler readRoutine)
{
  s->readHandler = readRoutine;
  FD_SET(s->sock, &socketReadWatch);
}

void
onWrite(Socket *s, handler writeRoutine)
{
  s->writeHandler = writeRoutine;
  FD_SET(s->sock, &socketWriteWatch);
}

void
onAccept(Socket *s, handler acceptRoutine)
{
  onRead(s, acceptRoutine);
}

void
ioLoop()
{
  while((!shutdownSet) && (nSockets > 0))
    {
      fd_set rTmp, wTmp;
      struct timeval t;
      Socket ** timedOut;
      int i, s;
      
      timedOut = &timeoutList;
      
      while(*timedOut != NULL)
	{
	  if ((*timedOut)->timeout.time <= time(NULL))
	    {
	      Socket *c = *timedOut;
	      *timedOut = (*timedOut)->timeout.next;
	      (*c->timeout.timeoutHandler)(c, -ETIMEDOUT);
	    }
	  else
	    timedOut = &(*timedOut)->timeout.next;
	}

      memcpy(&rTmp, &socketReadWatch, sizeof(fd_set));
      memcpy(&wTmp, &socketWriteWatch, sizeof(fd_set));
      
      if (timeoutList != NULL)
	{
	  t.tv_sec = timeoutList->timeout.time - time(NULL);
	  t.tv_usec = 0;
	  s = select(MAX_SOCKS, &rTmp, &wTmp, NULL, &t);
	}
      else
	s = select(MAX_SOCKS, &rTmp, &wTmp, NULL, NULL);
      
      if (s < 0)
	{
	  if (errno != EINTR)
	    {
	      errMsg("Select() failed: %s\n", strerror(errno));
	      exit(1);
	    }
	  else
	    continue;
	}
      
      if (s == 0)
	{
	  /* Timeout. Looping again will expire timed-out connections. */
	  continue;
	}

      for(i = 0; i < MAX_SOCKS && s > 0; i++)
	{
	  if (sockets[i] == NULL)
	    continue;
	  
	  if (FD_ISSET(i, &rTmp))
	    {
	      (*sockets[i]->readHandler)(sockets[i]);
	      s--;
	    }

	  if (FD_ISSET(i, &wTmp))
	    {
	      (*sockets[i]->writeHandler)(sockets[i]);
	      s--;
	    }
	}
    }
  
  dbgMsg(3, "Exitting ioLoop.\n");
}

void
ioShutdown()
{
  shutdownSet = 1;
}

/*///////////////////////////////////////////////////////////////////////*/

void 
setTimeout(Socket *s, int seconds, completion_handler timeoutHandler)
{
  Socket **ptr = &timeoutList;

  s->timeout.time = time(NULL) + seconds;
  s->timeout.timeoutHandler = timeoutHandler;

  while(*ptr && (*ptr)->timeout.time <= s->timeout.time)
    ptr = &(*ptr)->timeout.next;

  s->timeout.next = *ptr;
  *ptr = s;
}

void
cancelTimeout(Socket *s)
{
  Socket **t = &timeoutList;

  while(*t != NULL)
    {
      if (*t == s)
	{
	  dbgMsg(3, "Cancelling timeout for %i\n", s->sock);
	  *t = s->timeout.next;
	  break;
	}
      else
	t = &(*t)->timeout.next;
    }
}

/*///////////////////////////////////////////////////////////////////////*/

static void readLoop(Socket *s);

void
readData(Socket *s, int totalLength, completion_handler completionRoutine)
{
  setupBuffer(&s->transferData.readBuffer, totalLength);

  s->readCompleteHandler = completionRoutine;
  onRead(s, readLoop);
}

static void
readLoop(Socket *s)
{
  int status = readBuffer(s->sock, &s->transferData.readBuffer);

  if (status < 0)
    {
      /* Error. */
      FD_CLR(s->sock, &socketReadWatch);
      (*s->readCompleteHandler)(s, -errno);
      return;
    }
  
  if (s->transferData.readBuffer.length == 0)
    {
      FD_CLR(s->sock, &socketReadWatch);
      (*s->readCompleteHandler)(s, 0);
    }
  else if (status == 0)
    {
      /* Premature EOF */
      FD_CLR(s->sock, &socketReadWatch);
      (*s->readCompleteHandler)(s, -EIO);
    }

  /* else
     recall this routine the next time data is available. */
}

/*///////////////////////////////////////////////////////////////////////*/

static void sendLoop(Socket *s);

unsigned char*
setupForWrite(Socket *s, int totalLength, int prependLength)
{
  unsigned char *p;

  if (prependLength)
    {
      /* Include space for length field. */

      p = setupBuffer(&s->transferData.writeBuffer, totalLength + 2);
      *(unsigned short*)p = htons(totalLength + 2);
      p += 2;
    }
  else
    {
      p = setupBuffer(&s->transferData.writeBuffer, totalLength);
    }

  return p;
}

void 
sendData(Socket *s, completion_handler completionRoutine)
{
  s->writeCompleteHandler = completionRoutine;
  onWrite(s, sendLoop);
}

static void
sendLoop(Socket *s)
{
  if (writeBuffer(s->sock, &s->transferData.writeBuffer))
    {
      /* Error. */
      FD_CLR(s->sock, &socketWriteWatch);
      (*s->writeCompleteHandler)(s, -errno);
      return;
    }

  if (s->transferData.writeBuffer.length == 0)
    {
      FD_CLR(s->sock, &socketWriteWatch);
      (*s->writeCompleteHandler)(s, 0);
    }

  /* else
     recall this routine the next time we can write. */
}

/*///////////////////////////////////////////////////////////////////////*/

int
enableEncryption(Socket *s, const EVP_CIPHER *cipher, const unsigned char *sessionKey)
{
  s->transferData.cipherBlkSize = EVP_CIPHER_block_size(cipher);

  if (!EVP_DecryptInit(&s->transferData.sessionCtx[0], cipher, sessionKey, NULL))
    return -1;

  EVP_CIPHER_CTX_set_padding(&s->transferData.sessionCtx[0], 0);

  if (!EVP_EncryptInit(&s->transferData.sessionCtx[1], cipher, sessionKey, NULL))
    return -1;

  EVP_CIPHER_CTX_set_padding(&s->transferData.sessionCtx[1], 0);

  return 0;
}

/*///////////////////////////////////////////////////////////////////////*/

static void readDecryptLoop(Socket *s);

void
readDecryptData(Socket *s, int totalLength, 
		completion_handler completionRoutine)
{
  setupBuffer(&s->transferData.readBuffer, totalLength);
  setupBuffer(&s->transferData.decryptBuffer, s->transferData.cipherBlkSize);

  s->readCompleteHandler = completionRoutine;
  onRead(s, readDecryptLoop);
}

static void
readDecryptLoop(Socket *s)
{
  if (s->transferData.decryptBuffer.length != 0)
    {
      int status = readBuffer(s->sock, &s->transferData.decryptBuffer);

      if (status < 0)
	goto error;
      else if (status == 0)
	{
	  /* Premature EOF. */
	  errno = EIO;
	  goto error;
	}
    }
  
  if (s->transferData.decryptBuffer.length == 0)
    {
      unsigned char *plaintextBuffer = alloca(s->transferData.cipherBlkSize);
      int decrypted = 0;

      if (!EVP_DecryptUpdate(&s->transferData.sessionCtx[0], plaintextBuffer,
			   &decrypted, s->transferData.decryptBuffer.b.buffer,
			   s->transferData.decryptBuffer.totalLength))
        {
	  dbgMsg(2, "Failed to decrypt block\n");
          errno = EIO;
	  goto error;
        }

      if (s->transferData.readBuffer.totalLength < 0 && decrypted > 0)
	{
	  int dataLength = (int) ntohs(*(unsigned short*)plaintextBuffer);
	  setupBuffer(&s->transferData.readBuffer, dataLength - 2);
          plaintextBuffer += sizeof(unsigned short);
	  decrypted -= sizeof(unsigned short);
	}
      else if (s->transferData.readBuffer.totalLength < 0)
        dbgMsg(2, "Failed to decrypt total length field\n");

      /* Avoid potential segfault. */

      if (decrypted > s->transferData.readBuffer.length)
	decrypted = s->transferData.readBuffer.length;
      
      memcpy(s->transferData.readBuffer.ptr, plaintextBuffer, decrypted);
      
      s->transferData.readBuffer.ptr += decrypted;
      s->transferData.readBuffer.length -= decrypted;

      if (s->transferData.readBuffer.length == 0)
	{
	  cleanupBuffer(&s->transferData.decryptBuffer);
	  FD_CLR(s->sock, &socketReadWatch);
	  (*s->readCompleteHandler)(s, 0);
	}
      else
	{
	  /* Reset decrypt buffer. */
	  clearBuffer(&s->transferData.decryptBuffer);
	}
    }

  return;

 error:

  cleanupBuffer(&s->transferData.decryptBuffer);
  FD_CLR(s->sock, &socketReadWatch);
  (*s->readCompleteHandler)(s, -errno);
}

/*///////////////////////////////////////////////////////////////////////*/

static void encryptSendLoop(Socket *s);

void
encryptSendData(Socket *s, completion_handler completionRoutine)
{
  setupBuffer(&s->transferData.encryptBuffer, 2 * s->transferData.cipherBlkSize);
  s->transferData.encryptBuffer.length = 0;

  s->writeCompleteHandler = completionRoutine;
  onWrite(s, encryptSendLoop);
}

static void
encryptSendLoop(Socket *s)
{
  if (s->transferData.encryptBuffer.length == 0)
    {
      int encrypted = 0, dataLength = s->transferData.cipherBlkSize;
      unsigned char *encryptionBuffer = alloca(s->transferData.cipherBlkSize);
      
      if (dataLength > s->transferData.writeBuffer.length)
	dataLength = s->transferData.writeBuffer.length;

      memcpy(encryptionBuffer, s->transferData.writeBuffer.ptr,
	     dataLength);

      /* Automatically padded to transferData.cipherBlkSize. */

      if (!EVP_EncryptUpdate(&s->transferData.sessionCtx[1],
			     s->transferData.encryptBuffer.b.buffer,
			     &encrypted, encryptionBuffer, s->transferData.cipherBlkSize))
        {
	  dbgMsg(2, "Failed to encrypt block\n");
          errno = EIO;
	  goto error;
        }

      s->transferData.encryptBuffer.length = encrypted;
    }

  if (writeBuffer(s->sock, &s->transferData.encryptBuffer))
    goto error;

  if (s->transferData.encryptBuffer.length == 0)
    {
      s->transferData.writeBuffer.ptr += s->transferData.cipherBlkSize;
      s->transferData.writeBuffer.length -= s->transferData.cipherBlkSize;

      if (s->transferData.writeBuffer.length <= 0)
	{
	  cleanupBuffer(&s->transferData.encryptBuffer);
	  FD_CLR(s->sock, &socketWriteWatch);
	  (*s->writeCompleteHandler)(s, 0);
	}
      else
	{
	  /* Reset encrypt buffer. */
	  clearBuffer(&s->transferData.encryptBuffer);
          s->transferData.encryptBuffer.length = 0;
	}
    }
  
  return;

 error:
  
  cleanupBuffer(&s->transferData.encryptBuffer);
  FD_CLR(s->sock, &socketWriteWatch);
  (*s->writeCompleteHandler)(s, -errno);
}

/*///////////////////////////////////////////////////////////////////////*/

/* Designed only for use with unencrypted data (i.e. can't be used to read
 * from an encrypted stream).
 * If the value -1 is passed in as maxBytes, the default block transfer size is
 * used.
 */

static void readPartialLoop(Socket *s);

void
readPartialData(Socket *s, int maxBytes, completion_handler completionRoutine)
{
  if (maxBytes == -1)
    setupBuffer(&s->transferData.readBuffer, DEFAULT_XFER_BLKSIZE);
  else
    setupBuffer(&s->transferData.readBuffer, maxBytes);

  s->readCompleteHandler = completionRoutine;
  onRead(s, readPartialLoop);
}

static void
readPartialLoop(Socket *s)
{
  int status = 0;
  int len = read(s->sock, s->transferData.readBuffer.b.buffer, 
		 s->transferData.readBuffer.totalLength);

  if (len <= 0)
    {
      /* Error / EOF. */
      status = -1;
    }
  else
    {
      s->transferData.readBuffer.totalLength = len;
    }

  FD_CLR(s->sock, &socketReadWatch);
  (*s->readCompleteHandler)(s, status);
}

/*///////////////////////////////////////////////////////////////////////*/

void 
shutdownSocket(Socket *s)
{
  cancelTimeout(s);
  
  FD_CLR(s->sock, &socketReadWatch);
  FD_CLR(s->sock, &socketWriteWatch);
  
  sockets[s->sock] = NULL;
  nSockets--;

  dbgMsg(3, "%i sockets still remaining\n", nSockets);
}

void
cleanupSocket(Socket *s)
{
  shutdownSocket(s);

  cleanupBuffer(&s->transferData.encryptBuffer);
  cleanupBuffer(&s->transferData.decryptBuffer);

  EVP_CIPHER_CTX_cleanup(&s->transferData.sessionCtx[0]);
  EVP_CIPHER_CTX_cleanup(&s->transferData.sessionCtx[1]);

  cleanupBuffer(&s->transferData.readBuffer);
  cleanupBuffer(&s->transferData.writeBuffer);
}

/* EOF */

