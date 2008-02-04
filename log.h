#ifndef LOG_H
#define LOG_H

/* Debug log levels:
 * 1 - Errors (not printed by server normally).
 * 2 - Protocol information (state changes, etc).
 * 3 - Information messages.
 */

extern int show_error_messages;

extern void setLogPrefix(const char *prefixString);

extern void logMsg(const char *format, ...);
extern void dbgMsg(int dbg_level, const char *format, ...);
extern void dbgHexDump(int dbgLevel, const char *blurb, unsigned char *data, int length);
extern void errMsg(const char *format, ...);

#endif /* LOG_H */
