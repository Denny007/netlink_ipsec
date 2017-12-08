/*	
 * Description: print the log to log file or terminal
 * Auther: Denny
 */

#ifndef _PLOG_H
#define _PLOG_H

#include <stdarg.h>
/*
 * INFO: begin negotiation, SA establishment/deletion/expiration.
 * NOTIFY: just notifiable.
 * WARNING: not error strictly.
 * ERROR: system call error. also invalid parameter/format.
 * DEBUG1: debugging informatioin.
 * DEBUG2: too more verbose. e.g. parsing config.
 */
#define LLV_ERROR	1
#define LLV_WARNING	2
#define LLV_NOTIFY	3
#define LLV_INFO	4
#define LLV_DEBUG	5
#define LLV_DEBUG2	6
 
#define LLV_BASE	LLV_INFO /* by default log less than this value. */

extern char *pname; //存储运行程序的名称
extern u_int32_t loglevel;
extern int f_foreground;
extern int print_location;

struct sockaddr;
//#define plog

#define LOCATION  debug_location(__FILE__, __LINE__, __func__) //使用宏定义LOCATION来定义回调函数debug_location

#define plog(pri, ...) \
	do { \
		if ((pri) <= loglevel) \
			_plog((pri), __VA_ARGS__); \
	} while (0)

//#define plog(pri, ...) 
extern void _plog __P((int, const char *, struct sockaddr *, const char *, ...))
	__attribute__ ((__format__ (__printf__, 4, 5)));
extern void plogv __P((int, const char *, struct sockaddr *,
	const char *, va_list));
extern void plogdump __P((int, void *, size_t));
extern void ploginit __P((void));
extern void plogset __P((char *));
extern void plogfinal __P((void));

extern const char *debug_location(const char *file; int line; const char *func;);


#endif /* _PLOG_H */
