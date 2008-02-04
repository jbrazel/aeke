#ifndef UTILS_H
#define UTILS_H

extern void *xmalloc(unsigned int size);
extern void xfree(void *ptr);
extern char *xstrdup(const char *str);
extern void xmemoryStats(void);

#endif /* UTILS_H */
