#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define __USE_GNU
#include <fcntl.h>
#include <termios.h>
#if defined(__linux__) || defined(__CYGWIN__)
#include <pty.h>  
#endif
#ifdef __linux__
#include <utmp.h>
#elif !defined(__CYGWIN__)
#include <util.h>
#endif
#include <assert.h>

#include "buffer.h"
#include "io.h"
#include "common.h"
#include "log.h"
#include "crypto.h"

/*///////////////////////////////////////////////////////////////////////////*/

inline void 
pushReturn(Socket *s, completion_handler h)
{
  AekeSocket *a = (AekeSocket*)s->data;
  assert(a->stackPtr < MAX_STACK_DEPTH);
  a->stack[a->stackPtr++] = h;
}

inline void popReturn(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  assert(a->stackPtr > 0);
  (*a->stack[--a->stackPtr])(s, status); 
}

/*///////////////////////////////////////////////////////////////////////////*/

Socket*
createSocket()
{
  Socket *s = (Socket*)xmalloc(sizeof(*s));
  AekeSocket *a = (AekeSocket*)xmalloc(sizeof(AekeSocket));

  s->data = a;
  
  a->read_routine = readData;
  a->write_routine = sendData;

  return s;
}

/*///////////////////////////////////////////////////////////////////////////*/

static void doConnect(Socket *s);
static void onConnected(Socket *s, int status);
static void proxyResponse(Socket *s, int status);
static void proxyConnected(Socket *s, int status);
static void connectTimeout(Socket *s, int status);
static void wwwProxyConnected(Socket *s, int status);
static void connectStringSent(Socket *s, int status);
static void wwwProxyResponseRead(Socket *s, int status);
static void checkWwwProxyResponse(Socket *s, int status);

void
connectSocket(Socket *s, char *connectString, int timeout,
	      completion_handler connectedCallback)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (timeout >= 0)
    a->portknockTimeout = timeout;
  
  if (a->connected)
    {
      /* Proxy mode. */

      int msgLength = strlen(connectString) + 2;
      unsigned char *buf = setupForWrite(s, msgLength, 1);
      
      if (buf == NULL)
	{
	  (*connectedCallback)(s, -ENOMEM);
	  return;
	}

      pushReturn(s, connectedCallback);
      snprintf((char*)buf, msgLength, "F%s", connectString);
      (*a->write_routine)(s, proxyResponse);
    }
  else
    {
      char *copy = xstrdup(connectString), *arg;
      int knockNo = 0;

      if (copy == NULL)
	{
	  (*connectedCallback)(s, -ENOMEM);
	  return;
	}
      
      arg = strtok(copy, ":");

      if (!inet_aton(arg, &a->u.connectData.ip))
	{
	  errMsg("Bad IP addr '%s'\n", copy);
	  (*connectedCallback)(s, -EFAULT);
	  xfree(copy);
	  return;
	}

      while((knockNo < MAX_KNOCKS-1) && (arg = strtok(NULL, ":")) != NULL)
	{
	  if (!isdigit(*arg))
            break;

	  if (atoi(arg) <= 0 || atoi(arg) > 65535)
	    {
	      errMsg("Bad port '%s'\n", arg);
	      (*connectedCallback)(s, -EFAULT);
	      xfree(copy);
	      return;
	    }

	  a->u.connectData.knockSequence[knockNo++] = atoi(arg);
	}
      
      a->u.connectData.knockSequence[knockNo] = 0;
      xfree(copy);

      if (!a->u.connectData.knockSequence[0])
	{
	  errMsg("Need at least one port.\n");
	  popReturn(s, -EINVAL);
	  return;
	}

      if (arg != NULL)
	{
          char *option;

	  dbgMsg(3, "Connection options: %s\n", arg);

	  for(option = strtok(arg, ","); option != NULL; option = strtok(NULL, ","))
            {
	      if (option[1] != '=')
	        {
		  errMsg("Bad connect option %s\n", option);
		  popReturn(s, -EINVAL);
		  return;
	        }
	      
	      switch(option[0]) {
	      case 't':
		{
                  int sockTimeout = atoi(option+2);

	          if (!isdigit(option[2]) || sockTimeout < 0)
	            {
		      errMsg("Bad connect timeout value %s\n", option+2);
		      popReturn(s, -EINVAL);
		      return;
	            }

		  dbgMsg(3, "Assigning per-socket timeout value of %i\n", sockTimeout);
                  a->portknockTimeout = sockTimeout;
		}
		break;
	      default:
		errMsg("Bad connect option %s\n", option);
		popReturn(s, -EINVAL);
		return;
              }
            }
        }

      if (getenv("AEKE_WWW_PROXY") != NULL)
        {
	  char *proxy_details = strdup(getenv("AEKE_WWW_PROXY"));
	  char *port = strchr(proxy_details, ':');
	  char *login;

	  if (port == NULL)
	    a->u.connectData.proxy_addr.sin_port = htons(3128);
	  else
	    {
	      int p = atoi(port + 1);
	      
	      if (p < 1 || p > 65535)
		{
		  errMsg("Bad proxy port.\n");
		  free(proxy_details);
		  popReturn(s, -EINVAL);
		  return;
		}

	      a->u.connectData.proxy_addr.sin_port = htons(p);
	      *port = '\0';
	    }
	  
	  if (!inet_aton(proxy_details, &a->u.connectData.proxy_addr.sin_addr))
	    {
	      errMsg("Bad proxy address '%s'\n", proxy_details);
	      free(proxy_details);
	      popReturn(s, -EINVAL);
	      return;
	    }

	  if ((login = getenv("AEKE_WWW_PROXY_LOGIN")) != NULL)
	    a->u.connectData.proxyAuth = strdup(login);
	  else
	    a->u.connectData.proxyAuth = NULL;
	  
	  a->u.connectData.use_proxy = 1;
	  free(proxy_details);
	}
      
      pushReturn(s, connectedCallback);
      doConnect(s);
    }
}

static void 
doConnect(Socket *s)
{
  struct sockaddr_in addr;
  int flags;
  AekeSocket *a = (AekeSocket*)s->data;

  s->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (s->sock < 0)
    {
      popReturn(s, -errno);
      return;
    }

  flags = fcntl(s->sock, F_GETFL, 0);
  flags |= O_NONBLOCK;

  if (fcntl(s->sock, F_SETFL, flags))
    {
      errMsg("fcntl(F_SETFL(O_NONBLOCK)): %s\n", strerror(errno));
    }

  flags = 1;

  if (setsockopt(s->sock, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(int)))
    {
      errMsg("setsockopt(): %s\n", strerror(errno));
    }

  registerSocket(s);

  if (a->u.connectData.use_proxy)
    {
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = a->u.connectData.proxy_addr.sin_addr.s_addr;
      addr.sin_port = a->u.connectData.proxy_addr.sin_port;

      dbgMsg(3, "Connecting to WWW proxy...\n", ntohs(addr.sin_port));
      
      if (a->portknockTimeout > 0)
	setTimeout(s, a->portknockTimeout, connectTimeout);

      ioConnect(s, &addr, wwwProxyConnected);
    }
  else
    {
      addr.sin_family = AF_INET;
      addr.sin_addr.s_addr = a->u.connectData.ip.s_addr;
      addr.sin_port = htons(a->u.connectData.knockSequence[a->u.connectData.currentKnockPtr]);
      
      dbgMsg(3, "Knocking on port %i\n", ntohs(addr.sin_port));
      
      if (a->portknockTimeout > 0)
	setTimeout(s, a->portknockTimeout, connectTimeout);

      ioConnect(s, &addr, onConnected);
    }
}

static int
base64(const char *input, unsigned char *output)
{
  static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int length = 0, bufSz = 0;
  unsigned short buf = 0;

  do {
    if (bufSz < 6 && *input != '\0')
      {
        buf |= (unsigned short)*input++ << (8 - bufSz);
        bufSz += 8;
      }

    if (output != NULL)
      *output++ = b64[buf >> 10];
    length++;
    
    bufSz -= 6;
    buf <<= 6;
  }
  while(*input || bufSz > 0);

  if (output != NULL)
    *output++ = '\0';

  return length + 1;
}
  
static void 
wwwProxyConnected(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  cancelTimeout(s);

  dbgMsg(2, "WWW Proxy connected (status %i).\n", status);

  if (status < 0)
    popReturn(s, status);
  else
    {
      unsigned char *b;
      unsigned short port;
      char template[] = 
	"CONNECT xxx.xxx.xxx.xxx:nnnnn HTTP/1.1\r\n"
	"Host: xxx.xxx.xxx.xxx:nnnnn\r\n"
	"Proxy-Authorization: basic \r\n"
	"\r\n";
#define BASE64_PASSWD_LENGTH 63
      unsigned char base64Passwd[BASE64_PASSWD_LENGTH + 1];
      char proxyCmd[sizeof(template) + BASE64_PASSWD_LENGTH + 1];

      port = a->u.connectData.knockSequence[a->u.connectData.currentKnockPtr];

      /* Do _NOT_ send the trailing nul character. */

      if (a->u.connectData.proxyAuth != NULL)
	{
	  if (base64(a->u.connectData.proxyAuth, NULL) > BASE64_PASSWD_LENGTH)
	    {
	      errMsg("Proxy password exceeds hardwired limit of %u chars\n",
		     BASE64_PASSWD_LENGTH);
	      popReturn(s, -1);
	      return;
	    }

	  base64(a->u.connectData.proxyAuth, base64Passwd);

	  snprintf(proxyCmd, sizeof(proxyCmd), 
		   "CONNECT %s:%u HTTP/1.1\r\n"
		   "Host: %s:%u\r\n"
		   "Proxy-Authorization: basic %s\r\n"
		   "\r\n",
		   inet_ntoa(a->u.connectData.ip), port,
		   inet_ntoa(a->u.connectData.ip), port,
		   base64Passwd);

	  b = setupForWrite(s, strlen(proxyCmd), 0);
	  memcpy(b, proxyCmd, strlen(proxyCmd));
	}
      else
	{
	  b = setupForWrite(s, strlen(template), 0);

	  /* Special tricks to avoid overwriting our buffer with the
           * nul terminator.
           */
	  
	  snprintf(proxyCmd, sizeof(proxyCmd), 
		   "CONNECT %s:%u HTTP/1.1\r\n"
		   "Host: %s:%u\r\n"
		   "\r\n", 
		   inet_ntoa(a->u.connectData.ip), port,
		   inet_ntoa(a->u.connectData.ip), port);

	  b = setupForWrite(s, strlen(proxyCmd), 0);
	  memcpy(b, proxyCmd, strlen(proxyCmd));
	}

      (*a->write_routine)(s, connectStringSent);
    }
}

static void
connectStringSent(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  const char mandatoryHttpResponse[] = "HTTP/1.x nnn";
  
  cancelTimeout(s);
  
  if (status < 0)
    {
      dbgMsg(2, "Failed to connect to www proxy\n");
      popReturn(s, status);
      return;
    }
  
  dbgMsg(2, "Connect to www proxy, awaiting response...\n");

  /* Read HTTP proxy reply up to and including the blank line (i.e.
   * "\r\n\r\n". Read the reply one byte at a time, which is painful,
   * but prevents us from accidentally reading a chunk of whatever
   * data follows the connect response, which may be required by
   * higher-level protocols.
   */

  a->u.connectData.proxyEorMarker = 0;
  a->u.connectData.responseCode = 0;
  (*a->read_routine)(s, sizeof(mandatoryHttpResponse), wwwProxyResponseRead);
}

static void 
wwwProxyResponseRead(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      dbgMsg(2, "Failed to read response from www proxy.\n");
      popReturn(s, status);
      return;
    }
 
  /* Nul-terminate the result. */

  s->transferData.readBuffer.b.buffer[s->transferData.readBuffer.totalLength - 1] = '\0';
 
  dbgMsg(3, "Got Proxy response '%s'\n", 
	 s->transferData.readBuffer.b.buffer);

  /* For now, we assume that there's only a single space between the HTTP/1.x
   * and the response code.
   */

  a->u.connectData.responseCode = atoi((char*)s->transferData.readBuffer.b.buffer + 9);

  /* Read rest of response. */
  (*a->read_routine)(s, 1, checkWwwProxyResponse);
}

static void
checkWwwProxyResponse(Socket *s, int status)
{
  const char endOfResponse[] = "\r\n\r\n";
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      dbgMsg(2, "Failed to read response from www proxy.\n");
      popReturn(s, status);
      return;
    }

  dbgMsg(3, "Got Proxy response '%c'\n", *s->transferData.readBuffer.b.buffer);

  if (*s->transferData.readBuffer.b.buffer == 
      endOfResponse[a->u.connectData.proxyEorMarker])
    a->u.connectData.proxyEorMarker++;
  else
    a->u.connectData.proxyEorMarker = 0;

  if (a->u.connectData.proxyEorMarker == strlen(endOfResponse))
    {
      if (a->u.connectData.responseCode / 100 != 2)
        {
	  errMsg("Bad proxy response %i\n", a->u.connectData.responseCode);
	  popReturn(s, -1);
	}
      else
	{
	  dbgMsg(3, "Got proxy response %i\n", a->u.connectData.responseCode);
          onConnected(s, status);
	}
 
      return;
    }

  (*a->read_routine)(s, 1, checkWwwProxyResponse);
}

static void
onConnected(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  cancelTimeout(s);

  if (a->u.connectData.knockSequence[++a->u.connectData.currentKnockPtr] != 0)
    {
      /* Ignore return status of connect - we may be knocking on a closed port. */

      dbgMsg(3, "Knock on %hu returned, next port is %hu\n",
	     a->u.connectData.knockSequence[a->u.connectData.currentKnockPtr-1],
	     a->u.connectData.knockSequence[a->u.connectData.currentKnockPtr]);
      
      shutdownSocket(s);
      close(s->sock);

      doConnect(s);
      return;
    }

  dbgMsg(2, "Connected (status %i).\n", status);

  if (status < 0)
    popReturn(s, status);
  else
    {
      a->connected = 1;
      popReturn(s, 0);
    }
}

static void 
proxyResponse(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      dbgMsg(2, "Reading MOTD from next hop failed.\n");
      popReturn(s, status);
    }

  dbgMsg(2, "Next hop sent successfully, waiting for server ACK.\n");
  (*a->read_routine)(s, -1, proxyConnected);
}

static void 
proxyConnected(Socket *s, int status)
{
  if (status == 0)
    disableEncryption(s);
  
  popReturn(s, status);  
}

static void
connectTimeout(Socket *s, int status)
{
  dbgMsg(1, "Connect on %i timed out.\n", s->sock);
  onConnected(s, status);
}

/*////////////////////////////////////////////////////////////////////*/

static void authEncryptedPkeySent(Socket*, int status);
static void authServerPkeyRecvd(Socket*, int status);
static void authClientVerifierSent(Socket *s, int status);
static void authServerAckRecvd(Socket *s, int status);

void
authenticateToServer(Socket *s, const char *password, 
		     completion_handler onAuthenticated)
{
  AekeSocket *a = (AekeSocket*)s->data;

  dbgMsg(3, "authenticateToServer: '%s'\n", password);

  memcpy(a->cryptoData.authenticationData.clientSide.cleartextPassword, password, 
	 strlen(password)+1);
  makeHash((unsigned char*)password, strlen(password), a->cryptoData.password);
  pushReturn(s, onAuthenticated);

  dbgHexDump(3, "authenticateToServer: password-hash: ",  a->cryptoData.password,
	  MD5_DIGEST_LENGTH);

  initPkeyPair(s);
  (*a->write_routine)(s, authEncryptedPkeySent);
}

static void
authEncryptedPkeySent(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  dbgMsg(3, "Pkey sent, waiting on peer's pkey\n");

  if (status < 0)
    {
      dbgMsg(2, "AuthProto: Error sending client public key\n");
      popReturn(s, status);
      return;
    }

  (*a->read_routine)(s, -1, authServerPkeyRecvd);
}

static void
authServerPkeyRecvd(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  
  dbgMsg(3, "Peer pkey recv'd\n");

  if (status < 0 || (status = generateSessionKey(s)) != 0)
    {
      dbgMsg(2, "AuthProto: DH key exchange failed\n");
      popReturn(s, status);
      return;
    }

  /* Authenticating a socket connection automatically turns on 
   * encryption (until it is turned off using disable_encryption()).
   * The encryption keys are set up inside generateSessionKey().
   */

  a->read_routine = readDecryptData;
  a->write_routine = encryptSendData;

  generateClientVerifier(s);

  /* Socket set up for send inside generateClientVerifier(). */

  (*a->write_routine)(s, authClientVerifierSent);
}

static void
authClientVerifierSent(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      dbgMsg(2, "AuthProto: Error sending the client verifier\n");
      popReturn(s, status);
      return;
    }

  (*a->read_routine)(s, -1, authServerAckRecvd);
}

static void
authServerAckRecvd(Socket *s, int status)
{
  if (status < 0)
    dbgMsg(2, "AuthProto: Error reading server's ACK\n");
  else if (checkServerAck(s))
    dbgMsg(2, "AuthProto: Bad server ACK\n");

  popReturn(s, status);
}

/*////////////////////////////////////////////////////////////////////*/

static void authServerPkeySent(Socket *s, int status);
static void authClientPkeyRecvd(Socket *s, int status);
static void authClientVerifierRecvd(Socket *s, int status);
static void authServerAckSent(Socket *s, int status);

void
authenticateToClient(Socket *s, const unsigned char *password, 
		     completion_handler onAuthenticated)
{
  AekeSocket *a = (AekeSocket*)s->data;
  memcpy(a->cryptoData.password, password, MD5_DIGEST_LENGTH);
  pushReturn(s, onAuthenticated);
  
  dbgHexDump(3, "authenticateToClient: password-hash: ",  a->cryptoData.password,
	  MD5_DIGEST_LENGTH);

  initPkeyPair(s);
  (*a->write_routine)(s, authServerPkeySent);
}

static void
authServerPkeySent(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  dbgMsg(3, "Server pkey sent waiting on client pkey\n");

  if (status < 0)
    {
      dbgMsg(2, "AuthProto: Error sending server public key\n");
      popReturn(s, status);
      return;
    }

  (*a->read_routine)(s, -1, authClientPkeyRecvd);
}

static void
authClientPkeyRecvd(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  dbgMsg(3, "Got client pkey\n");

  if (status < 0 || (status = generateSessionKey(s)) != 0)
    {
      dbgMsg(2, "AuthProto: DH key exchange failed\n");
      popReturn(s, status);
      return;
    }

  /* Authenticating a socket connection automatically turns on 
   * encryption (until it is turned off using disable_encryption()).
   * The encryption keys are set up inside generateSessionKey().
   */

  a->read_routine = readDecryptData;
  a->write_routine = encryptSendData;

  (*a->read_routine)(s, -1, authClientVerifierRecvd);
}

static void
authClientVerifierRecvd(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0 || (status = verifyClient(s)) != 0)
    {
      dbgMsg(2, "AuthProto: Bad client verifier\n");
      popReturn(s, status);
      return;
    }

  /* Ack is generated inside verifyClient(). */

  (*a->write_routine)(s, authServerAckSent);
}

static void
authServerAckSent(Socket *s, int status)
{
  if (status < 0)
    dbgMsg(2, "AuthProto: Error sending server ACK\n");
    
  popReturn(s, status);
}

/*////////////////////////////////////////////////////////////////////*/

void
disableEncryption(Socket *s)
{
  AekeSocket *a = (AekeSocket*)s->data;

  a->read_routine = readData;
  a->write_routine = sendData;

  cleanupBuffer(&s->transferData.encryptBuffer);
  cleanupBuffer(&s->transferData.decryptBuffer);

  EVP_CIPHER_CTX_cleanup(&s->transferData.sessionCtx[0]);
  EVP_CIPHER_CTX_cleanup(&s->transferData.sessionCtx[1]);
}

/*////////////////////////////////////////////////////////////////////*/

static void fileSendBlock(Socket *s);
static void fileBlockSent(Socket *s, int status);
static void fileSendFinished(Socket *s, int status);
static void fileHashSent(Socket *s, int status);
static void eofReceived(Socket *s, int status);

void
sendFile(Socket *s, int fileFd, completion_handler completionRoutine)
{
  AekeSocket *a = (AekeSocket*)s->data;
  struct stat info;

  if (fstat(fileFd, &info) || !S_ISREG(info.st_mode))
    {
      int flags = fcntl(fileFd, F_GETFL, 0);
      fcntl(fileFd, F_SETFL, flags | O_NONBLOCK);
    }

  MD5_Init(&a->fileHash);

  a->fileFd = fileFd;
  pushReturn(s, completionRoutine);
  onWrite(s, fileSendBlock);
}

static void
fileSendBlock(Socket *s)
{
  AekeSocket *a = (AekeSocket*)s->data;
  char buf[FILE_SENDSIZE];
  unsigned char *b;
  int len = read(a->fileFd, buf, sizeof(buf));

  if (len < 0)
    {
      dbgMsg(1, "Bad file read.\n");
      popReturn(s, -1);
      return;
    }

  if (len == 0)
    {
      /* Write EOF */
      setupForWrite(s, 0, 1);
      (*a->write_routine)(s, fileSendFinished);
      return;
    }

  MD5_Update(&a->fileHash, buf, len);

  b = setupForWrite(s, len, 1);
  memcpy(b, buf, len);
  (*a->write_routine)(s, fileBlockSent);
}

static void
fileBlockSent(Socket *s, int status)
{
  if (status < 0)
    {
      dbgMsg(2, "Error while tranferring file\n");
      popReturn(s, status);
      return;
    }

  dbgMsg(2, "File block sent\n");

  /* Else on next write-available status in select(), will
   * re-call start_send_file().
   */

  onWrite(s, fileSendBlock);
}

static void
fileSendFinished(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  unsigned char *buf;

  if (status < 0)
    {
      dbgMsg(2, "Error while tranferring file EOF\n");
      popReturn(s, status);
      return;
    }

  buf = setupForWrite(s, MD5_DIGEST_LENGTH, 1);
  MD5_Final(buf, &a->fileHash);
  (*a->write_routine)(s, fileHashSent);
}

static void
fileHashSent(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  if (status < 0)
    {
      dbgMsg(2, "Failed to send file hash\n");
      popReturn(s, status);
      return;
    }

  /* Wait for the peer's EOF. This prevents issues found in some operating
   * systems where data is discarded if the non-blocking socket is closed 
   * before the data is put on the wire.
   */
  
  (*a->read_routine)(s, 1, eofReceived);
}

static void
eofReceived(Socket *s, int status)
{
  popReturn(s, 0);
}

/*////////////////////////////////////////////////////////////////////*/

static void fileBlockRecvd(Socket *s, int status);
static void fileHashRecvd(Socket *s, int status);

void
recvFile(Socket *s, int outFile, completion_handler completionRoutine)
{
  AekeSocket *a = (AekeSocket*)s->data;
  struct stat info;

  if (fstat(outFile, &info) || !S_ISREG(info.st_mode))
    {
      int flags = fcntl(outFile, F_GETFL, 0);
      fcntl(outFile, F_SETFL, flags | O_NONBLOCK);
    }

  MD5_Init(&a->fileHash);

  a->fileFd = outFile;
  pushReturn(s, completionRoutine);

  (*a->read_routine)(s, -1, fileBlockRecvd);
}

static void
fileBlockRecvd(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  int dataLen;

  if (status < 0)
    {
      popReturn(s, status);
      return;
    }

  dbgMsg(3, "File block recv'd (%u bytes)\n", 
	 s->transferData.readBuffer.totalLength);

  dataLen = s->transferData.readBuffer.totalLength;

  if (dataLen == 0)
    {
      /* EOF */
      (*a->read_routine)(s, -1, fileHashRecvd);
      return;
    }

  if (write(a->fileFd, s->transferData.readBuffer.b.buffer, dataLen) != dataLen)
    {
      dbgMsg(1, "Failed to write file to disk.\n");
      popReturn(s, -errno);
      return;
    }

  MD5_Update(&a->fileHash, s->transferData.readBuffer.b.buffer, dataLen);
  (*a->read_routine)(s, -1, fileBlockRecvd);
}

static void
fileHashRecvd(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  unsigned char hash[MD5_DIGEST_LENGTH];

  if (status >= 0)
    {
      MD5_Final(hash, &a->fileHash);

      if (memcmp(s->transferData.readBuffer.b.buffer, hash,
   	         MD5_DIGEST_LENGTH) != 0)
        status = -1;
    }

  dbgMsg(2, "File received with final status %i\n", status);
  memset(&a->fileHash, 0, sizeof(a->fileHash));
  popReturn(s, status);
}

/*////////////////////////////////////////////////////////////////////*/

static void writeToPeer(Socket *s, int status);
static void peerWrittenTo(Socket *s, int status);

void
joinSockets(Socket *s, Socket *newPeer, completion_handler closeRoutine)
{
  AekeSocket *a = (AekeSocket*)s->data;
  AekeSocket *peer = (AekeSocket*)newPeer->data;

  dbgMsg(3, "Joining %i and %i\n", s->sock, newPeer->sock);

  a->peer = newPeer;
  peer->peer = s;

  pushReturn(s, closeRoutine);
  pushReturn(newPeer, closeRoutine);

  (*a->read_routine)(s, -1, writeToPeer);
  (*peer->read_routine)(newPeer, -1, writeToPeer);
}

static void
writeToPeer(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  AekeSocket *peer = (AekeSocket*)a->peer->data;
  unsigned char *buf;

  if (status < 0)
    {
      popReturn(s, -1);
      return;
    }

  buf = setupForWrite(a->peer, s->transferData.readBuffer.totalLength, 
		      peer->rawMode ? 0 : 1);
  
  memcpy(buf, s->transferData.readBuffer.b.buffer, 
         s->transferData.readBuffer.totalLength);

  (*peer->write_routine)(a->peer, peerWrittenTo);
}

static void
peerWrittenTo(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  AekeSocket *peer = (AekeSocket*)a->peer->data;

  if (status < 0)
    {
      popReturn(s, -1);
      return;
    }

  (*peer->read_routine)(a->peer, -1, writeToPeer);
}

/*////////////////////////////////////////////////////////////////////*/

void
closeSocket(Socket *s)
{
  AekeSocket *a = (AekeSocket*)s->data;

  dbgMsg(3, "CloseSocket: Closing socket %i\n", s->sock);

  cleanupSocket(s);

  if (isatty(s->sock))
    {
      struct termios t;

      if (tcgetattr(s->sock, &t))
	dbgMsg(1, "tcgetattr: %s\n", strerror(errno));
      else
	{
	  t.c_lflag |= (ICANON|ECHO|ISIG);
	  
	  if (tcsetattr(s->sock, TCSANOW, &t))
	    dbgMsg(1, "tcsetattr: %s\n", strerror(errno));
	}
    }

  close(s->sock);
  cleanupConnCrypto(s);

  if (a != NULL)
    {
      char *proxyHops = a->u.connectData.connectionStrings[0];
      int i;

      for(i = 0; i < MAX_PROXY_HOPS; i++)
	if (a->u.connectData.connectionStrings[i] != NULL)
	  {
	    memset(a->u.connectData.connectionStrings[i], 0, 
		   strlen(a->u.connectData.connectionStrings[i]));
	    a->u.connectData.connectionStrings[i] = NULL;
	  }

      xfree(proxyHops);

      if (a->u.connectData.proxyAuth != NULL)
        free((char*)a->u.connectData.proxyAuth);
      
      if (a->commandData != NULL)
	{
	  memset(a->commandData, 0, strlen(a->commandData)); 
	  xfree(a->commandData);
	}
  
      if (a->cryptoData.key != NULL)
	DH_free(a->cryptoData.key);

      memset(a, 0, sizeof(*a));
      xfree(a);
    }

  memset(s, 0, sizeof(*s));
  xfree(s);
}

/*////////////////////////////////////////////////////////////////////*/

Socket*
openTty(const char *execString)
{
  int child;
  Socket *s;
  AekeSocket *a;

  switch(forkpty(&child, NULL, NULL, NULL)) {
  case -1:
    errMsg("OpenTTY: forkpty() failed: %s\n", strerror(errno));
    return NULL;

  case 0:
    execlp(execString, execString, (void*)0);
    exit(0);

  default:
    dbgMsg(2, "Tty sock\n");
    s = createSocket();
    s->sock = child;

    a = (AekeSocket*)s->data;
    a->read_routine = readPartialData;
    a->write_routine = sendData;
    a->rawMode = 1;

    s->data = a;
    registerSocket(s);
    return s;
  }
}

Socket*
openClientTty(const char *ttyName)
{
  struct termios t;
  Socket *tty;
  AekeSocket *a;
  int fd;

  if (ttyName == NULL)
    ttyName = "/dev/tty";

  fd = open(ttyName, O_RDWR);
  
  if (fd < 0) 
    {
      dbgMsg(1, "%s: %s\n", ttyName, strerror(errno));
      return NULL;
    }

  if (tcgetattr(fd, &t))
    {
      dbgMsg(1, "tcgetattr: %s\n", strerror(errno));
      close(fd);
      return NULL;
    }

  t.c_lflag &= ~(ICANON|ECHO|ISIG);

  if (tcsetattr(fd, TCSANOW, &t))
    {
      dbgMsg(1, "tcsetattr: %s\n", strerror(errno));
      close(fd);
      return NULL;
    }
      
  tty = createSocket();
  a = (AekeSocket*)tty->data;

  tty->sock = fd;
  a->read_routine = readPartialData;
  a->write_routine = sendData;
  a->rawMode = 1;

  registerSocket(tty);
  return tty;
}

/*/////////////////////////////////////////////////////////////////////*/

static void fileXferComplete(Socket *s, int status);

/* Server-side routine only: 
 * the socket is closed upon return, and no completion
 * routine is called.
 */

void
connectToFile(Socket *s, const char *filename, int mode, 
	      completion_handler transferComplete)
{
  int fd;

  pushReturn(s, transferComplete);

  if (tolower(mode) == 'r')
    {
#ifdef __linux__
      fd = open(filename, O_RDONLY);
#else
      fd = open(filename, O_RDONLY | O_BINARY);
#endif
      
      if (fd < 0)
	{
	  popReturn(s, errno);
	  return;
	}

      sendFile(s, fd, fileXferComplete);
    }
  else
    {
#ifdef __linux__
      fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0600);
#else
      fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY|O_BINARY, 0600);
#endif

      if (fd < 0)
	{
	  popReturn(s, errno);
	  return;
	}

      recvFile(s, fd, fileXferComplete);
    }
}

static void
fileXferComplete(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;
  dbgMsg(3, "File transfer complete.\n");
  close(a->fileFd);
  popReturn(s, status);
}

#if defined(__OpenBSD__) || defined(__linux__)
char*
mkxtemp(char *template)
{
  int suffix = 0, count = 0, fd;
  char *end = template + strlen(template) - 1;

  while(*end == 'X' && end-- != template) count++;

  do {
    int s = suffix++, i;
    end = template + strlen(template) - 1;

    for(i=0; i<count; i++)
      {
        char x = s % 16;
        x += ((x < 10) ? '0' : 'A' - 10);
        *end-- = x;
        s /= 16;
      }

    fd = open(template, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  } while(fd < 0);

  close(fd);
  return template;
}
#endif

/*///////////////////////////////////////////////////////////////////////////*/

void
closeSocketPair(Socket *s, int status)
{
  AekeSocket *a = (AekeSocket*)s->data;

  closeSocket(a->peer);
  closeSocket(s);
}

/* EOF */

