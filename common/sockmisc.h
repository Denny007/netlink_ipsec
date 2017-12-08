

#ifndef __SOCKMISC_H__
#define __SOCKMISC_H__ 1


void setsock(int sockfd, int flags, int bufsize, char *sockname);
int newsock(int family, int type, int proto, int flags, int bufsize, char *sockname);
int set_sockaddr_unix(struct sockaddr *sa, const char *servpath);
int sockaddr_len(struct sockaddr *sa);



#endif


