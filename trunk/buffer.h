#ifndef BUFFER_H
#define BUFFER_H

#include "utils.h"

typedef struct {
  struct {
    unsigned char *buffer;
    unsigned short len;
  } b;
  unsigned char *ptr;
  int length, totalLength;
} buffer;

extern unsigned char *setupBuffer(buffer *b, int size);
extern int readBuffer(int fd, buffer *b);
extern int writeBuffer(int fd, buffer *b);
extern void clearBuffer(buffer *b);
extern void cleanupBuffer(buffer *b);

#endif /* BUFFER_H */
