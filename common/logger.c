/*	
 * Description: print the log to log file or terminal
 * Auther: Denny
 */

#include <sys/types.h>
#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <stdarg.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "logger.h"

struct log *
log_open(siz, fname)
	size_t siz;
	char *fname;
{
	struct log *p;

	p = (struct log *)malloc(sizeof(*p));
	if (p == NULL)
		return NULL;
	memset(p, 0, sizeof(*p));

	if (fname)
		p->fname = strdup(fname);

	return p;
}


/*
 * write out string to the log file, as is.
 * \n-termination is up to the caller.  if you don't add \n, the file
 * format may be broken.
 */
int
log_print(p, str)
	struct log *p;
	char *str;
{
	FILE *fp;

	if (p->fname == NULL)
		return -1;	/*XXX syslog?*/
	fp = fopen(p->fname, "a");
	if (fp == NULL)
		return -1;
	fprintf(fp, "%s", str);
	fclose(fp);

	return 0;
}

int
log_vprint(struct log *p, const char *fmt, ...)
{
	va_list ap;

	FILE *fp;

	if (p->fname == NULL)
		return -1;	/*XXX syslog?*/
	fp = fopen(p->fname, "a");
	if (fp == NULL)
		return -1;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);

	fclose(fp);

	return 0;
}

int
log_vaprint(struct log *p, const char *fmt, va_list ap)
{
	FILE *fp;

	if (p->fname == NULL)
		return -1;	/*XXX syslog?*/
	fp = fopen(p->fname, "a");
	if (fp == NULL)
		return -1;
	vfprintf(fp, fmt, ap);
	fclose(fp);

	return 0;
}

void
log_free(p)
	struct log *p;
{
	if (p->fname)
		free(p->fname);
	free(p);
	p = NULL;
}


