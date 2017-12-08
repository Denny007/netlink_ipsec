/*
 *	Description: 通过socket发送获取到的SAD和SPD数据
 *	Author: Denny
 *  Date: 2017-11-29
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <event.h>

#include "ipsec_common.h"
#include "nl_priv.h"
#include "nl_xfrm.h"
#include "nl_sa.h"
#include "nl_sp.h"
#include "nl_msg.h"
#include "sockmisc.h"

#include "plog.h"
#include "logger.h"


TAILQ_HEAD(fpmmsg, fpm_msg);

struct fpm_ctx {
	int                   fpm_sock; 
	u_int32_t             fpm_ev_set;
	struct event          fpm_ev_send;
	struct event          fpm_ev_recv;

	u_int32_t             fpm_sn;
	u_int32_t             fpm_wait_ack;

	struct fpmmsg         fpm_msg_head;
	u_int32_t             fpm_msg;
	struct fpmmsg         fpm_sent_head;
	u_int32_t             fpm_sent;
	struct fpmmsg         fpm_svg_head;
	u_int32_t             fpm_svg;
};

//#define  LIS_UNIX_PATH       "/tmp/.lis_xfrm"
#define LIS_UNIX_PATH "/var/run/test.sock"
#define NL_DEFAULT_SOCKBUFSIZ 131070
//int nl_sockbufsiz = NL_DEFAULT_SOCKBUFSIZ;
int   srv_conn_maxtry = 5;

/*
 * In case of single FPM, let's have it STATIC
 */
struct fpm_ctx FPM_CTX;

/*
 *========================================================
 *   LOCAL TOOLS
 *========================================================
 */
/* 清空fpmmsg队列 */
static void purge_msgQ(struct fpmmsg *head)
{
	struct fpm_msg *msg;
	/* point to the first entry */
	msg = TAILQ_FIRST(head);
	while(msg)
	{
		TAILQ_REMOVE(head, msg, msg_link);
		free (msg->msg_pkt);
		free (msg);
		msg = TAILQ_FIRST(head); 
	}
}

static void nl_msg_destroy(struct fpm_ctx *fpm)
{
	/*
	 * First, remove any event, and close socket
	 */
	event_del(&fpm->fpm_ev_recv);
	if (fpm->fpm_ev_set)
	{
		event_del(&fpm->fpm_ev_send);
	}
	close(fpm->fpm_sock);
	fpm->fpm_sock = -1;

	/*
	 * Then free  fpmmsg Queue s
	 */
	purge_msgQ (&fpm->fpm_msg_head);
	purge_msgQ (&fpm->fpm_sent_head);
	purge_msgQ (&fpm->fpm_svg_head);


}

/* 初始化消息，在启动程序的时候发送netlink消息到内核主动获取SA和SP */
static void nl_initial_messages (struct fpm_ctx *fpm)
{
	plog(LLV_INFO, LOCATION, NULL, "init the messages \n");

}

/*
 * Determines if sending conditions are met
 * and if needed set associated libevent event
 */
static void nl_check_activate (struct fpm_ctx *fpm)
{
	/*
	 * If there are still one remaining , re-arm (if needed) 
	 * the evt to allow future sending when socket is ready
	 * else, wait for something to be posted
	 * This evt re-activation is postponed when a blocking
	 * condition is set
	 */
	if ((fpm->fpm_sock != (-1)) &&
	    (!(TAILQ_EMPTY(&fpm->fpm_msg_head))) &&
		(fpm->fpm_ev_set == 0)) 
	{
			fpm->fpm_ev_set = 1;
			if (event_add (&fpm->fpm_ev_send, NULL))
				perror("event_add fpm_ev_send");
	} 
}
/* 处理接收消息 */
static void nl_msg_recv(int fd, short event, void *data)
{

}


/*
 * Called from the lis_xfrm internal process (netlink translation)
 * Manages a list, and update sending evt 
 * 将数据写入fpm_msg_head队列
 */
void nl_msg_enqueue(struct cp_hdr *m, void *data)
{
	struct fpm_ctx *fpm = (struct fpm_ctx *)data;
	struct fpm_msg *msg;

	if (fpm == NULL)
		fpm = &FPM_CTX;

	/* 填充msg结构体 */
	msg = calloc(1, sizeof(struct fpm_msg));
	msg->msg_len = htonl(m->cphdr_length) + sizeof(struct cp_hdr);
	msg->msg_sn = fpm->fpm_sn++;
	msg->msg_pkt = m;
	plog(LLV_DEBUG, LOCATION, NULL, "the msg->msg_len=%d, msg->msg_sn=%d \n", msg->msg_len, msg->msg_sn);

	m->cphdr_sn = htonl(msg->msg_sn);

	/* insert the msg to msg_link queue*/
	TAILQ_INSERT_TAIL(&fpm->fpm_msg_head, msg, msg_link);
	/* add the number of fpm_msg in the tailq queue*/
	fpm->fpm_msg++;

	/*
	 * After any operation on msg queue, perform evt management
	 */
	nl_check_activate (fpm);
}

/* traverse the tailq queue fpmmsg and send the msg */
void nl_msg_dequeue(int fd, short event, void *data)
{
	struct fpm_ctx *fpm = (struct fpm_ctx *)data;
	struct fpm_msg *msg = NULL;

	fpm->fpm_ev_set = 0;
	/*
	 * try to send as many msg as possible,
	 * without being blocked
	 */
	while ((msg = TAILQ_FIRST(&fpm->fpm_msg_head))) 
	{
		int send_len;
		send_len = send(fpm->fpm_sock, (caddr_t)msg->msg_pkt + msg->msg_off, msg->msg_len - msg->msg_off, 0);
		if (send_len <= 0)
		{
			/* nothing to read */
			if (errno == EAGAIN)
				return;
			/* real error */
			else
			{
				plog(LLV_ERROR, LOCATION, NULL, "Connection to FPM is lost.\n");
				nl_msg_destroy(fpm);
				nl_msg_init();
				return;
			}
		}
		/* 已发送message的偏移量  */
		msg->msg_off += send_len; 
		/* message全部发送完毕 */
		if (msg->msg_len == msg->msg_off) 
		{
			msg->msg_off= 0; //清空偏移量
			/* 从链表中清除这个msg节点*/
			TAILQ_REMOVE (&fpm->fpm_msg_head, msg, msg_link);
			fpm->fpm_msg--;
			fpm->fpm_sent++;
			plog(LLV_DEBUG, LOCATION, NULL, "Message send finished.\n");
		}
		else
		{
			plog(LLV_DEBUG, LOCATION, NULL, "socket is full (%d bytes not sent), "
				       "waiting for room\n", msg->msg_len - msg->msg_off);
			break;
		}
	}

	/*
	 * After any operation on msg queue, perform evt management
	 */
	nl_check_activate (fpm);
}

int nl_msg_init(void)
{
	struct fpm_ctx *fpm = &FPM_CTX;;
	int try = 0;
 	struct sockaddr_un addr;

	memset (fpm, 0, sizeof(struct fpm_ctx));
	memset(&addr, 0, sizeof(addr));
	/* init msg,sent,svg queue */
	TAILQ_INIT(&fpm->fpm_msg_head);
	TAILQ_INIT(&fpm->fpm_sent_head);
	TAILQ_INIT(&fpm->fpm_svg_head);

	fpm->fpm_sock = newsock(AF_LOCAL, SOCK_STREAM, 0, O_NONBLOCK, NL_DEFAULT_SOCKBUFSIZ, "xfrm_sock");
	if (fpm->fpm_sock < 0) {
	    plog(LLV_ERROR, LOCATION, NULL, "cannot open socket \n");
	    exit (-1);
	}

	set_sockaddr_unix((struct sockaddr *)&addr, LIS_UNIX_PATH);

	/* try to connect up to srv_conn_maxtry times (0=forever) */
	while(1)
	{
		if (connect(fpm->fpm_sock, (struct sockaddr *)&addr, sockaddr_len((struct sockaddr *)&addr)) < 0)
		{
			plog(LLV_ERROR, LOCATION, NULL, "cannot connect to server socket \n");
			if (srv_conn_maxtry && (++try >= srv_conn_maxtry))
				exit(-1);
		}
		else
		{
			 plog(LLV_INFO, LOCATION, NULL, "Connected to server socket \n");
			 break;
		}
	}

	nl_initial_messages(fpm);

	event_set(&fpm->fpm_ev_recv, fpm->fpm_sock, EV_READ | EV_PERSIST, nl_msg_recv, fpm);
	if (event_add(&fpm->fpm_ev_recv, NULL))
	{
		perror("event_add fpm_ev_rcv");
	}
	/* 设置发送事件到event */
	event_set(&fpm->fpm_ev_send, fpm->fpm_sock, EV_WRITE, nl_msg_dequeue, fpm);

	/* 发送nl_initial_messages中的消息 */
	nl_msg_dequeue(fpm->fpm_sock, EV_WRITE, fpm);

	return 0;
}
