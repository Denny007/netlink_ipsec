#ifndef __NL_CON__
#define __NL_CON__

#include <arpa/inet.h>
#include <stdio.h>
#include <event.h>

#define PFUNC()  printf("[+%s]\n", __FUNCTION__)
#define NLMSG_TYPE(type)    printf(#type " : %d\n", type)

struct nl_sock_user
{
	struct sockaddr_nl	s_local;
	struct sockaddr_nl	s_peer;
	int			s_fd;
};


struct nl_handle
{
	struct nl_sock_user  sk;
	char               *name;
	struct event        ev;
	int (*recv)(struct sockaddr_nl *,struct nlmsghdr *, void *);
};

/* 使用typedef声明函数指针的类型 */
typedef int handler_t(struct sockaddr_nl *,struct nlmsghdr *, void *);


void cm_netlink_xfrm_init(void);
int netlink_connect(struct nl_sock_user *sk, int protocol, int groups);
int nl_recv_msg(struct nl_sock_user *sk, handler_t *handler, void *data);
void nl_recv_event(int fd, short event, void *data);


#endif