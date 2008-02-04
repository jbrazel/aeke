#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/wait.h>

#include "buffer.h"
#include "io.h"
#include "log.h"
#include "crypto.h"

#define AEKE_CIPHER    SN_aes_128_cbc

int debug = 0;

static void
childHandler(int ignored)
{
  int pid, status;

  pid = waitpid(-1, &status, WNOHANG);
  
  if (pid <= 0)
    {
      perror("waitpid(WNOHANG)");
      exit(-1);
    }

  if ((!WIFEXITED(status)) || WEXITSTATUS(status) != 0)
    {
      fprintf(stderr, "Unit tests failed\n");
      exit(-1);
    }

  printf("Tests passed successfully\n");
  exit(0);
}

static void
waitForServer(void)
{
  while(1) sleep(60);
}

static void
closeSocket(Socket *s)
{
  cleanupSocket(s);
  close(s->sock);
  memset(s, 0, sizeof(*s));
  xfree(s);
}

static const char test1Text[] = "This is test 1.\n";
static const char test2Text[] = "Presenting: test 2.\n";
static const char test3Text[] = "Test 3 (partial read).\n";
static const char test5Text[] = "Test 5 (no timeout).\n";
static const char test5Text2[] = "Test 5 (part 2).\n";
static const char test6Text[] = "Some text for test 6.\n";
static const char test7Text[] = "Encryption / Decryption test (test #7).\n";

static const unsigned char sessionKey[MD5_DIGEST_LENGTH] = "\xDE\xAD\xBE\xEF\x0B\xAD\x5E\xED\x13\x37\x5E\x75\x01\x23\x45\x67";

static void
setupEncryption(Socket *s)
{
  const EVP_CIPHER *cipher;

  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  
  cipher = EVP_get_cipherbyname(AEKE_CIPHER);
  assert(EVP_CIPHER_key_length(cipher) == MD5_DIGEST_LENGTH);

  enableEncryption(s, cipher, sessionKey);
}

static void serverTest1Complete(Socket *s, int status);
static void serverTest2Complete(Socket *s, int status);
static void serverTest3Complete(Socket *s, int status);
static void serverTest5Complete(Socket *s, int status);
static void serverTest5Part2(Socket *s, int status);
static void serverTest6Complete(Socket *s, int status);
static void serverTest7Complete(Socket *s, int status);

static void 
testServer(int sock)
{
  Socket *s = (Socket*)xmalloc(sizeof(*s));

  s->sock = sock;
  s->data = NULL;
  registerSocket(s);

  /* Test 1 - fixed-length read */

  readData(s, sizeof(test1Text), serverTest1Complete);

  /* Kick it all off */

  ioLoop();
  exit(0);
}

static void 
serverTest1Complete(Socket *s, int status)
{
  unsigned char *b;

  printf("[server] Test 1 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);
 
  if (memcmp(s->transferData.readBuffer.b.buffer, test1Text, sizeof(test1Text)))
    {
      printf("[server] Test 1 text mismatch!\n");
      exit(1);
    }

  /* Test 2 */

  b = setupForWrite(s, sizeof(test2Text), 1);
  memcpy(b, test2Text, sizeof(test2Text));
  sendData(s, serverTest2Complete);
}

static void 
serverTest2Complete(Socket *s, int status)
{
  printf("[server] Test 2 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  /* Test 3 - Partial read. */

  readPartialData(s, 1024, serverTest3Complete);
}

static void 
serverTest3Complete(Socket *s, int status)
{
  printf("[server] Test 3 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  if (s->transferData.readBuffer.totalLength != sizeof(test3Text) ||
      memcmp(s->transferData.readBuffer.b.buffer, test3Text, sizeof(test3Text)))
    {
      printf("[server] Test 3 text mismatch!\n");
      exit(1);
    }

  /* Test 5 - cancel timeout */

  setTimeout(s, 7, serverTest5Complete);
  readData(s, -1, serverTest5Part2);
}

static void 
serverTest5Part2(Socket *s, int status)
{
  printf("[server] Test 5 (part 1) %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  if (s->transferData.readBuffer.totalLength != sizeof(test5Text) ||
      memcmp(s->transferData.readBuffer.b.buffer, test5Text, sizeof(test5Text)))
    {
      printf("[server] Test 5 text mismatch!\n");
      exit(1);
    }

  cancelTimeout(s);
  readData(s, -1, serverTest5Complete);
}

static void 
serverTest5Complete(Socket *s, int status)
{
  unsigned char *b;

  printf("[server] Test 5 (part 2) %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  if (s->transferData.readBuffer.totalLength != sizeof(test5Text2) ||
      memcmp(s->transferData.readBuffer.b.buffer, test5Text2, sizeof(test5Text2)))
    {
      printf("[server] Test 5 (part 2) text mismatch!\n");
      exit(1);
    }

  /* Test 6 */

  b = setupForWrite(s, sizeof(test6Text), 1);
  memcpy(b, test6Text, sizeof(test6Text));
  sendData(s, serverTest6Complete);
}

static void 
serverTest6Complete(Socket *s, int status)
{
  printf("[server] Test 6 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  /* Set up encryption. */

  setupEncryption(s);

  readDecryptData(s, -1, serverTest7Complete);
}

static void 
serverTest7Complete(Socket *s, int status)
{
  printf("[server] Test 7 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  if (s->transferData.readBuffer.totalLength != sizeof(test7Text) ||
      memcmp(s->transferData.readBuffer.b.buffer, test7Text, sizeof(test7Text)))
    {
      printf("[server] Test 7 text mismatch!\n");
      exit(1);
    }

  closeSocket(s);
}

static void clientTest1Complete(Socket *s, int status);
static void clientTest2Complete(Socket *s, int status);
static void clientTest3Complete(Socket *s, int status);
static void clientTest4Complete(Socket *s, int status);
static void clientTest4Failed(Socket *s, int status);
static void clientTest5Part2(Socket *s, int status);
static void clientTest5Complete(Socket *s, int status);
static void clientTest6Failed(Socket *s, int status);
static void clientTest6Complete(Socket *s, int status);
static void clientTest7(Socket *s, int status);
static void clientTest7Complete(Socket *s, int status);

static void
testClient(int sock)
{
  unsigned char *b;
  Socket *s = (Socket*)xmalloc(sizeof(*s));

  s->sock = sock;
  s->data = NULL;
  registerSocket(s);

  /* Test 1 - write */

  b = setupForWrite(s, sizeof(test1Text), 0);
  memcpy(b, test1Text, sizeof(test1Text));
  sendData(s, clientTest1Complete);

  /* Kick it all off */

  ioLoop();
}

static void 
clientTest1Complete(Socket *s, int status)
{
  printf("[client] Test 1 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  /* Test 2 - variable length read */

  readData(s, -1, clientTest2Complete);
}

static void 
clientTest2Complete(Socket *s, int status)
{
  unsigned char *b;

  printf("[client] Test 2 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  if (s->transferData.readBuffer.totalLength != sizeof(test2Text) ||
      memcmp(s->transferData.readBuffer.b.buffer, test2Text, sizeof(test2Text)))
    {
      printf("[client] Test 2 text mismatch!\n");
      exit(1);
    }

  /* Test 3 */

  b = setupForWrite(s, sizeof(test3Text), 0);
  memcpy(b, test3Text, sizeof(test3Text));
  sendData(s, clientTest3Complete);
}

static void 
clientTest3Complete(Socket *s, int status)
{
  printf("[client] Test 3 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  /* Test 4 - Timeout on read */

  setTimeout(s, 4, clientTest4Complete);
  readData(s, -1, clientTest4Failed);
}

static void 
clientTest4Failed(Socket *s, int status)
{
  printf("[client] Test 4 failed\n");
  exit(1);
}

static void 
clientTest4Complete(Socket *s, int status)
{
  unsigned char *b;

  printf("[client] Test 4 passed\n");
 
  /* Test 5 */
 
  b = setupForWrite(s, sizeof(test5Text), 1);
  memcpy(b, test5Text, sizeof(test5Text));
  sendData(s, clientTest5Part2);
}

static void 
clientTest5Part2(Socket *s, int status)
{
  unsigned char *b;

  printf("[client] Test 5 (part 1) %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  b = setupForWrite(s, sizeof(test5Text2), 1);
  memcpy(b, test5Text2, sizeof(test5Text2));
  sleep(4);
  sendData(s, clientTest5Complete);
}

static void 
clientTest5Complete(Socket *s, int status)
{
  printf("[client] Test 5 (part 2) %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  /* Test 6 - Timed out before read. */

  setTimeout(s, 2, clientTest6Complete);
  sleep(5);
  readData(s, -1, clientTest6Failed);
}

static void 
clientTest6Failed(Socket *s, int status)
{
  printf("[client] Test 6 failed\n");
  exit(1);
}

static void 
clientTest6Complete(Socket *s, int status)
{
  printf("[client] Test 6 %s\n", status ? "Passed" : "Failed");
  fflush(stdout);

  if (!status)
    exit(1);

  /* Clear outstanding data. */
  readPartialData(s, 1024, clientTest7);
}

static void 
clientTest7(Socket *s, int status)
{
  unsigned char *b;

  printf("[client] Test 6 clean-up %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  /* Set up encryption. */

  setupEncryption(s);

  b = setupForWrite(s, sizeof(test7Text), 1);
  memcpy(b, test7Text, sizeof(test7Text));
  encryptSendData(s, clientTest7Complete);
}

static void 
clientTest7Complete(Socket *s, int status)
{
  printf("[client] Test 7 %s\n", status ? "Failed" : "Passed");
  fflush(stdout);

  if (status)
    exit(1);

  closeSocket(s);
}

int
main(int argc, char **argv)
{
  int fds[2];

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
    {
      perror("socketpair()");
      exit(1);
    }

  signal(SIGCHLD, childHandler);
  ioSetup();

  switch(fork())
    {
      case -1:
        perror("fork()");
        exit(1);
      case 0:
        close(fds[0]);
        testServer(fds[1]);
        break;
      default:
        close(fds[1]);
        testClient(fds[0]);
        waitForServer();
        break;
    }

  cleanupCrypto();
  exit(0);
}

/* EOF */

