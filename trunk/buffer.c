#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "buffer.h"

/* Set up a buffer for reading or writing: make sure the buffer
 * has enough space. If doing a variable length read (size < 0), 
 * set up the buffer to read the initial 2-byte length prefix only.
 *
 * If the buffer is already big enough, just clear it.
 */

unsigned char*
setupBuffer(buffer *b, int size)
{
  if (size == b->totalLength)
    {
      clearBuffer(b);
      return b->b.buffer;
    }

  cleanupBuffer(b);

  if (size < 0)
    {
      /* Read a 2-byte length field first, then remaining data. */
      b->ptr = (unsigned char*)&b->b.len;
      b->length = sizeof(b->b.len);
      b->totalLength = -1;
    }
  else
    {
      if (size > 0)
	b->b.buffer = b->ptr = xmalloc(size);
      b->totalLength = b->length = size;
    }

  return b->b.buffer;
}

/* Read data from the file descriptor provided into the 
 * buffer struct. If doing a variable length read, resize
 * the buffer once we know how big the following data is
 * (i.e. once we've read the 2-byte length prefix.
 */

int
readBuffer(int fd, buffer *b)
{
  int len = read(fd, b->ptr, b->length);

  if (len <= 0)
    return len;

  b->ptr += len;
  b->length -= len;

  if (b->length == 0 && b->totalLength == -1)
    {
      /* First chunk read was a length field. */

      b->totalLength = (int) ntohs(b->b.len);

      /* The length field counts itself in the total number of bytes in the
       * message, so we always subtract 2 to get the total length of any
       * following data.
       * A length field of 0 or 1 is technically a protocol error, so we just
       * return the original length field unaltered (otherwise we wind up with
       * a negative length field, which gets passed to the read system call
       * furthur up the chain, and causes all sorts of problems).
       */
       
      if (b->totalLength >= 2)
        b->totalLength -= 2;
      b->length = b->totalLength;

      if (b->length > 0)
	b->b.buffer = b->ptr = xmalloc(b->totalLength);
    }

  return 1;
}

/* Write data to the file descriptor provided, and update the 
 * internal pointers.
 */

int
writeBuffer(int fd, buffer *b)
{
  int len = write(fd, b->ptr, b->length);

  if (len < 0)
    return -1;

  b->ptr += len;
  b->length -= len;

  return 0;
}

/* 'Empties' a buffer by resetting the points back to their start values. */

void
clearBuffer(buffer *b)
{
  if ((b->length = b->totalLength) < 0)
    {
      b->ptr = (unsigned char*)&b->b.len;
      b->length = sizeof(b->b.len);
    }
  else
    b->ptr = b->b.buffer;
}

/* Clean up a buffer - zero out the memory before freeing it. */

void
cleanupBuffer(buffer *b)
{
  if (b->totalLength > 0)
    {
      memset(b->b.buffer, 0, b->totalLength);
      xfree(b->b.buffer);
    }

  b->b.buffer = b->ptr = NULL;
  b->length = b->totalLength = 0;
}

/* EOF */
