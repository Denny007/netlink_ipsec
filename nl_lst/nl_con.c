

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>


#include "nl_con.h"
#include "nl_xfrm.h"
#include "plog.h"
#include "logger.h"

static int nl_xfrm_recv(struct sockaddr_nl *who, struct nlmsghdr *h, void *data);

static struct nl_handle xfrm_handle = {
	.name = "netlink_xfrm",
	.recv = nl_xfrm_recv,
};


/*
 *打开netlink socket，并绑定地址
 * 
 */
int netlink_connect(struct nl_sock_user *sk, int protocol, int groups)
{
	int err;
	socklen_t addrlen;
	struct sockaddr_nl local = { 0 };

	sk->s_fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (sk->s_fd < 0) {
		perror("open socket failed:");
		return 0;
	}
	memset(&sk->s_local, 0, sizeof(struct sockaddr_nl));
	sk->s_local.nl_groups |= groups;
	sk->s_local.nl_family = AF_NETLINK;

	err = bind(sk->s_fd, (struct sockaddr*) &sk->s_local,
				   sizeof(sk->s_local));
	 if (err < 0)
   		return -1;

	addrlen = sizeof(local);
	err = getsockname(sk->s_fd, (struct sockaddr*)&local, &addrlen);
	if (err < 0)
		return -1;
	if (addrlen != sizeof(local)) {
		errno = EINVAL;
		return -1;
	}

	if (local.nl_family != AF_NETLINK) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static int nl_xfrm_recv(struct sockaddr_nl *who, struct nlmsghdr *h, void *data)
{
	plog(LLV_INFO, LOCATION, NULL, "nlmsg_type=(%d) seq=#%u len=%hu pid=%u\n",
				h->nlmsg_type, h->nlmsg_seq,
				h->nlmsg_len, h->nlmsg_pid);
	parse_xfrm_nlmsg(h);

	return 0;
}

/* 监听内核多播的信息 */
int nl_recv_msg(struct nl_sock_user *sk, handler_t *handler, void *data)
{
	int err;
	ssize_t msglen;
	int flags = 0;
	unsigned char buffer[8192];
	struct sockaddr_nl nladdr = {0};
	struct nlmsghdr *nlmhdr;

	struct iovec iov;
	struct msghdr msg = {
		.msg_name = (void *)&nladdr,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	iov.iov_len = sizeof(buffer);;
	iov.iov_base = buffer;

 	
	msglen = recvmsg(sk->s_fd, &msg, flags);

	if (msglen < 0)
    	return 0;
  	else if (msglen == 0)
    	return -1;
  	else if (msg.msg_namelen != sizeof(nladdr))
   	 	return -1;
   	/* netlink头部指针指向数据报文 */
   	nlmhdr = (struct nlmsghdr*)buffer;
   	/* 当一次接收多个netlink报文时，逐一分析*/
   	while((size_t)msglen >= sizeof(*nlmhdr))
   	{
   		/* 数据长度 */
    	int datalen = nlmhdr->nlmsg_len - sizeof(*nlmhdr);

    	/* 总长度 > 接收长度 或者 数据长度 < 0 */
    	if (datalen < 0 || nlmhdr->nlmsg_len > msglen)
     		return -1;

   		err = handler(&nladdr, nlmhdr, data);
   		if (err < 0)
      		return err;

      	/* 接收长度减去已分析的netlink报文 */
      	msglen = msglen - NLMSG_ALIGN(nlmhdr->nlmsg_len);
      	/* netlink头部指针指向下一个报文头 */
    	nlmhdr = (struct nlmsghdr*)((char*)nlmhdr + NLMSG_ALIGN(nlmhdr->nlmsg_len));
   	}

   	if (msg.msg_flags & MSG_TRUNC)
    	return 0;
  	if (msglen)
    	return -1;
  	return err;
}


/* 接收事件，在event事件列表中监听fd对应的消息*/
void nl_recv_event(int fd, short event, void *data)
{
	struct nl_handle *nh = (struct nl_handle *)data;
	nl_recv_msg(&(nh->sk), nh->recv, NULL);
}

/* 初始化netlink(xfrm) */
void cm_netlink_xfrm_init(void)
{
	/* init the socket of netlink*/
	netlink_connect(&xfrm_handle.sk, NETLINK_XFRM, XFRMGRP_SA | XFRMGRP_POLICY | XFRMGRP_EXPIRE);

	event_set(&xfrm_handle.ev, xfrm_handle.sk.s_fd, EV_READ | EV_PERSIST, nl_recv_event, &xfrm_handle);

	event_add(&xfrm_handle.ev, NULL);
}

