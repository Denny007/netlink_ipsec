/*
 ***************************************************************
 *	Description: socket miscellaneous functions
 *  Author:		 Denny
 *  Date:		 2017-11-30
 ***************************************************************
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "sockmisc.h"
#include "plog.h"
#include "logger.h"

#define SOCKUNLEN sizeof(struct sockaddr_un)
#define SOCKUNPATH(sa) (((struct sockaddr_un*)(sa))->sun_path)
#define SCOKUNPATHLEN sizeof(SOCKUNPATH(0))


/* set socket option */
void setsock(int sockfd, int flags, int bufsize, char *sockname)
{
	int optval;
	socklen_t optlen;

	/* Set flags */
	if (flags && (fcntl(sockfd, F_SETFL, flags) < 0))
	{
		if (sockname)
		{
			plog(LLV_ERROR, LOCATION, NULL, "Could not set %s socket flags to %08x: %s\n", sockname, flags, strerror(errno));
		}
	}
	plog(LLV_DEBUG, LOCATION, NULL, "%s socket flags: %d\n", sockname, fcntl (sockfd, F_GETFL));

	optval = bufsize;
	optlen = sizeof(optval);

	/* set send buffer size */
	if (bufsize && (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &optval, optlen) < 0))
	{
		if (sockname){
			plog(LLV_ERROR, LOCATION, NULL, "Could not set %s socket send buffer size to %d: %s\n", 
				sockname, bufsize, strerror(errno));
		}
	}
	else
	{
		/* 判断是否设置了发送缓冲区大小 */
		if (sockname) {
			if (getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &optval, &optlen)){
				plog(LLV_ERROR, LOCATION, NULL, "Could not set %s socket send buffer size to %d: %s\n", 
					sockname, bufsize, strerror(errno));
			}
			else{
				plog(LLV_DEBUG, LOCATION, NULL, "%s socket send buffer size=%d\n", sockname, optval);
			}
		}
	}

	/* set recv buffer size */
	if (bufsize && (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &optval, optlen) < 0 ))
	{
		if (sockname){
			plog(LLV_ERROR, LOCATION, NULL, "Could not set %s socket recv buffer size to %d: %s\n", 
				sockname, bufsize, strerror(errno));
		}
	}
	else
	{
		/* 判断是否设置了接收缓冲区大小 */
		if (sockname) {
			if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &optval, &optlen)){
				plog(LLV_ERROR, LOCATION, NULL, "Could not set %s socket recv buffer size to %d: %s\n", 
					sockname, bufsize, strerror(errno));
			}
			else{
				plog(LLV_DEBUG, LOCATION, NULL, "%s socket recv buffer size=%d\n", sockname, optval);
			}
		}
	}
}

/* create new socket */
int newsock(int family, int type, int proto, int flags, int bufsize, char *sockname)
{
	int sock;

	/* Create socket */
	sock = socket(family, type, proto);
	if (sock < 0)
	{
		plog(LLV_ERROR, LOCATION, NULL, "Could not open socket %s \n", strerror(errno));
		return sock;
	}
	/* set socket option */
	setsock(sock, flags, bufsize, sockname);

	return sock;
}

/* set unix domain socket */
int set_sockaddr_unix(struct sockaddr *sa, const char *servpath)
{
	size_t path_len;
	
	path_len = strlen(servpath) + 1;
	if (path_len > SCOKUNPATHLEN) {
		plog(LLV_ERROR, LOCATION, NULL, "socket path too long\n");
		return -1;
	}
	memset(sa, 0, sizeof(struct sockaddr));
	sa->sa_family = AF_UNIX;
	snprintf(SOCKUNPATH(sa), path_len, "%s", servpath);

	return 0;

}

/* get sockaddr_len according different sa_family */
int sockaddr_len(struct sockaddr *sa)
{
	int len = 0;

	switch(sa->sa_family) {
	case AF_INET6:
		len = sizeof(struct sockaddr_in6);
		break;
	case AF_INET:
		len = sizeof(struct sockaddr_in);
		break;
	case AF_LOCAL:
		len = sizeof(struct sockaddr_un);
		break;
	default:
		break;
	}

	return len;
}