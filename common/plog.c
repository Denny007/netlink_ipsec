/*	
 * Description: print the log to log file or terminal
 * Auther: Denny
 */

#include <sys/types.h>
#include <sys/param.h>

#include <arpa/inet.h>
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
#include <ctype.h>
#include <err.h>

#include "plog.h"
#include "logger.h"

#define ARRAYLEN(a)	(sizeof(a)/sizeof(a[0]))

#ifndef VA_COPY
#define VA_COPY(dst,src) memcpy(&(dst), &(src), sizeof(va_list))
#endif

char *pname = NULL;
u_int32_t loglevel = LLV_BASE;

int print_location = 1;

static struct log *logp = NULL;
char *logfile = NULL;
//char *logfile = "/tmp/lis_xfrm.log";

static char *plog_common __P((int, const char *, const char *, struct sockaddr *));

static struct plogtags {
	char *name;
	int priority;
} ptab[] = {
	{ "(not defined)",	0, },
	{ "ERROR",		LLV_ERROR, },
	{ "WARNING",		LLV_WARNING, },
	{ "NOTIFY",		LLV_NOTIFY, },
	{ "INFO",			LLV_INFO, },
	{ "DEBUG",		LLV_DEBUG, },
	{ "DEBUG2",		LLV_DEBUG2, },
};

//获取日志输出的位置（文件以及文件中的函数）
const char *
debug_location(file, line, func)
	const char *file;
	int line;
	const char *func;
{
	static char buf[1024];
	const char *p;

	/* truncate pathname */
	p = strrchr(file, '/');
	if (p)
		p++;
	else
		p = file;

	if (func)
		snprintf(buf, sizeof(buf), "%s:%d:%s()", p, line, func);
	else
		snprintf(buf, sizeof(buf), "%s:%d", p, line);

	return buf;
}

static char *
plog_common(pri, fmt, func, sa)
	int pri;
	const char *fmt, *func;
	struct sockaddr *sa;
{
	static char buf[800];	/* XXX shoule be allocated every time ? */
	char *p;
	int reslen; //剩余长度
	int len;

	p = buf;
	reslen = sizeof(buf);

	time_t t;
	struct tm *tm;

	t = time(0);
	tm = localtime(&t);
	len = strftime(p, reslen, "%Y-%m-%d %T: ", tm);
	p += len;
	reslen -= len;

	/*if (sa && reslen > 3) {
		addr = NULL;
		switch (sa->sa_family) {
		case AF_INET:
			addr = &((struct sockaddr_in*)sa)->sin_addr;
			break;
		case AF_INET6:
			addr = &((struct sockaddr_in6*)sa)->sin6_addr;
			break;
		}
		if (inet_ntop(sa->sa_family, addr, p + 1, reslen - 3) != NULL) {
			*p++ = '[';
			len = strlen(p);
			p += len;
			*p++ = ']';
			*p++ = ' ';
			reslen -= len + 3;
		}
	}*/

	if (pri < ARRAYLEN(ptab)) { //ARRAYLEN(ptab) = 7
		len = snprintf(p, reslen, "%s: ", ptab[pri].name); //日志级别(LLV_INFO,LLV_DEBUG)
		p += len;
		reslen -= len;
	}

	if (print_location)
		len = snprintf(p, reslen, "%s: %s", func, fmt);
	else
		len = snprintf(p, reslen, "%s", fmt);
	p += len;
	reslen -= len;

	/* Force nul termination */
	if (reslen == 0)
		p[-1] = 0;

	return buf;
}

void
_plog(int pri, const char *func, struct sockaddr *sa, const char *fmt, ...)
{
	va_list ap;  //va_list用于获取不确定个数的参数

	va_start(ap, fmt);
	plogv(pri, func, sa, fmt, ap);
	va_end(ap);
}

void
plogv(int pri, const char *func, struct sockaddr *sa,
	const char *fmt, va_list ap)
{
	char *newfmt;
	//va_list ap_bak;

	if (pri > loglevel)
		return;

	newfmt = plog_common(pri, fmt, func, sa);

	//VA_COPY(ap_bak, ap);
		
	if (logfile) //如果指定了文件，则输出日志到这个文件中
		log_vaprint(logp, newfmt, ap);
	else {
		vprintf(newfmt, ap); //没有的话，直接输出打印消息
	}
}

void
plogdump(pri, data, len)
	int pri;
	void *data;
	size_t len;
{
	caddr_t buf;
	size_t buflen;
	int i, j;

	if (pri > loglevel)
		return;

	/*
	 * 2 words a bytes + 1 space 4 bytes + 1 newline 32 bytes
	 * + 2 newline + '\0'
	 */
	buflen = (len * 2) + (len / 4) + (len / 32) + 3;
	buf = (void *)malloc(buflen);
	memset(buf, '\0', buflen);

	i = 0;
	j = 0;
	while (j < len) {
		if (j % 32 == 0)
			buf[i++] = '\n';
		else
		if (j % 4 == 0)
			buf[i++] = ' ';
		snprintf(&buf[i], buflen - i, "%02x",
			((unsigned char *)data)[j] & 0xff);
		i += 2;
		j++;
	}
	if (buflen - i >= 2) {
		buf[i++] = '\n';
		buf[i] = '\0';
	}
	plog(pri, LOCATION, NULL, "%s", buf);

	free(buf);
}

void
ploginit()
{
	if (logfile) {
		logp = log_open(250, logfile);  //初始化struct log这个结构体，为里面数据分配内存
		if (logp == NULL)
			errx(1, "ERROR: failed to open log file %s.", logfile);
		return;
	}
}

void plogset(file)
	char *file;
{
	if (logfile != NULL)
		free(logfile);
	if (file)
		logfile = strdup(file);
}

void plogfinal(void)
{
	if(logp){
		log_free(logp);
	}

}
