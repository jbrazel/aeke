#ifndef COMMON_H
#define COMMON_H

#include "socket.h"

#define CMDSIZE 1024
#define FILE_SENDSIZE 1024
#define MAX_PROXY_HOPS 6
#define MAX_KNOCKS 10
#define MAX_STACK_DEPTH 5

typedef struct _AekeSocket
{
  Socket *sock;

  int connected;
  int rawMode;

  union 
  {
    struct 
    {
      char *connectionStrings[MAX_PROXY_HOPS+1];
      int hopNo;

      int use_proxy;
      struct sockaddr_in proxy_addr;
      int proxyEorMarker, responseCode;
      const char *proxyAuth;

      struct in_addr ip;
      unsigned short knockSequence[MAX_KNOCKS];
      int currentKnockPtr;
    } connectData;
    
    struct sockaddr_in clientAddress;	/* Listen socket only. */
  } u;

  struct 
  {
    unsigned char sessionKey[MD5_DIGEST_LENGTH];
    unsigned char password[MD5_DIGEST_LENGTH];
    DH *key;
    
    union {
      struct {	
	unsigned char clientVerifier[2048]; 
      } serverSide;
      
      struct {
	char cleartextPassword[256];
	unsigned char verifier[MD5_DIGEST_LENGTH];
      } clientSide;
    } authenticationData;
  } cryptoData;
  
  char *commandData, *tmpFile;
  int portknockTimeout;

  int proxyHop;

  void (*read_routine)(Socket*, int, completion_handler);
  void (*write_routine)(Socket*, completion_handler);

  Socket *peer;

  completion_handler stack[MAX_STACK_DEPTH];
  unsigned int stackPtr;

  MD5_CTX fileHash;
  int fileFd;
} AekeSocket;

extern inline void pushReturn(Socket *s, completion_handler h);
extern inline void popReturn(Socket *s, int status);


extern Socket *createSocket();

extern void connectSocket(Socket *s, char *connectString, int timeout,
			   completion_handler onConnected);
extern void authenticateToServer(Socket *s, const char *password, 
				 completion_handler onAuthenticated);
extern void authenticateToClient(Socket *s, const unsigned char *password, 
				 completion_handler onAuthenticated);
extern void disableEncryption(Socket *s);

extern void sendFile(Socket *s, int fileFd, 
		     completion_handler completionRoutine);
extern void recvFile(Socket *s, int outFile, 
		     completion_handler completionRoutine);
extern void connectToFile(Socket *s, const char *filename, 
			  int mode, completion_handler transferComplete);

extern Socket *openTty(const char *execString);
extern Socket *openClientTty(const char *ttyName);

extern void joinSockets(Socket *s, Socket *newPeer, 
			completion_handler closeRoutine);

extern void closeSocket(Socket *s);
extern void closeSocketPair(Socket *s, int status);

#if defined( __OpenBSD__) || defined(__linux__)
extern char * mkxtemp(char *template);
#endif
#endif /* COMMON_H */
