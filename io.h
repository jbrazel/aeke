#ifndef IO_H
#define IO_H

#include "socket.h"

#define DEFAULT_XFER_BLKSIZE 1024

/* Low-level I/O routines. */

extern void ioSetup(void);
extern void ioLoop();
extern void ioShutdown();

extern void registerSocket(Socket *s);

extern void onRead(Socket *s, handler readRoutine);
extern void onWrite(Socket *s, handler writeRoutine);
extern void onAccept(Socket *s, handler acceptRoutine);

extern void ioConnect(Socket *s, struct sockaddr_in *addr,
		      completion_handler completionRoutine);

extern int enableEncryption(Socket *s, const EVP_CIPHER *cipher, 
			    const unsigned char *sessionKey);

extern unsigned char *setupForWrite(Socket *s, int totalLength, 
				    int prependLength);
extern void sendData(Socket *s, completion_handler completionRoutine);
extern void encryptSendData(Socket *s, completion_handler completionRoutine);


extern void readData(Socket *s, int totalLength, 
		     completion_handler completionRoutine);
extern void readPartialData(Socket *s, int maxBytes, 
			    completion_handler completionRoutine);
extern void readDecryptData(Socket *s, int totalLength, 
			    completion_handler completionRoutine);

extern void setTimeout(Socket *s, int seconds, 
		       completion_handler timeoutHandler);
extern void cancelTimeout(Socket *s);

extern void shutdownSocket(Socket *s);
extern void cleanupSocket(Socket *s);

#endif /* IO_H */

