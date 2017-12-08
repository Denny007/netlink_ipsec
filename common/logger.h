/*	
 * Description: print the log to log file or terminal
 * Auther: Denny
 */

#ifndef _LOGGER_H
#define _LOGGER_H

struct log {
	
	char *fname;
};

extern struct log *log_open __P((size_t, char *));
extern void log_add __P((struct log *, char *));
extern int log_print __P((struct log *, char *));
extern int log_vprint __P((struct log *, const char *, ...));
extern int log_vaprint __P((struct log *, const char *, va_list));
extern int log_close __P((struct log *));
extern void log_free __P((struct log *));

#endif /* _LOGGER_H */
