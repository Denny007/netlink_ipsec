/*
 * Description: Unix server for CM.
 * Author: Denny
 * Date: 2017-12-4
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> 
#include <fcntl.h>
#include <stdarg.h>
#include <event.h>
#include <stdio.h>
#include <syslog.h>
#include <err.h>
#include <sys/un.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "cm_msg.h"
#include "ipsec_common.h"
#include "sockmisc.h"
#include "serv_ipsec.h"
#include "plog.h"
#include "logger.h"

static char *pidfilename = "/var/run/serv_lst.pid";
static char *progname;


/*
 * UNIX socket server variables
 */
#define DEFAULT_CM_PATH "/var/run/test.sock"
static char             *srv_path = DEFAULT_CM_PATH;
#define NL_DEFAULT_SOCKBUFSIZ	131070
int sockbufsiz = NL_DEFAULT_SOCKBUFSIZ;


/* used for socket*/
static int               sock_conn;
static struct event      event_conn;

/* used for accept */
static int sock_cli;
static struct event      event_recv;

int serv_received;
int serv_expected = sizeof(struct cp_hdr);
static unsigned char serv_recv_buf[4096];

static void show_usage()
{
	fprintf (stderr, "	-F foreground mode\n"
		"	-V (Version) show program version\n"
		"	-d (debug)   debug level\n"
		"   -l (log_file_path) set the path of log file \n"
		);
	exit(1);
}

static int serv_dispatch(struct cp_hdr *hdr, unsigned char *data)
{
	switch(ntohl(hdr->cphdr_type)){
	case CMD_IPSEC_SA_CREATE:
		return serv_ipsec_sa_create((struct cp_ipsec_sa_add *)data);
		
	case CMD_IPSEC_SA_DELETE:
		return serv_ipsec_sa_delete((struct cp_ipsec_sa_del *)data);
		
	case CMD_IPSEC_SA_FLUSH:
		return serv_ipsec_sa_flush();
		
	case CMD_IPSEC_SP_CREATE:
		return serv_ipsec_sp_create((struct cp_ipsec_sp_add *)data);
		
	case CMD_IPSEC_SP_DELETE:
		return serv_ipsec_sp_delete((struct cp_ipsec_sp_del *)data);
		
	case CMD_IPSEC_SP_FLUSH:
		return serv_ipsec_sp_flush();
	default:
		plog(LLV_DEBUG, LOCATION, NULL, "command type %08X not implemented yet\n", ntohl(hdr->cphdr_type));
		break;	
	}
	return -1;
}

static void serv_get(int fd, short event, void *data)
{
	struct fpm_msg msg;
	struct cp_hdr *hdr;
	int recv_length;
	unsigned char *req;

	/* malloc staitc global variable serv_recv_buf */
	hdr = (struct cp_hdr *)serv_recv_buf;

	recv_length = recv(fd, serv_recv_buf, sizeof(serv_recv_buf), 0);
	if (recv_length < 0)
	{
		plog(LLV_ERROR, LOCATION, NULL, "accept: %s \n", strerror(errno));
		event_del (&event_recv);
		return;
	}
	plog(LLV_DEBUG, LOCATION, NULL, "recv_length is %d\n", recv_length);

	// += recv_length; /* 已接收数据递增 */
	//serv_expected -= recv_length; /* 预计接收数据递减 */

	msg.msg_len = recv_length;
	msg.msg_sn  = ntohl(hdr->cphdr_sn);
	msg.msg_pkt = hdr;

	req = (unsigned char *)(hdr + 1);/* 去掉hdr头部的实际数据 */

	serv_dispatch(hdr, req);

}

static void serv_accept(int fd, short event, void *data)
{
	struct sockaddr_un remote;
	socklen_t remote_len = sizeof(remote);

	int cli_sock_fd;

	if ((cli_sock_fd = accept(fd, (struct sockaddr *)&remote, &remote_len)) < 0)
	{
		plog(LLV_ERROR, LOCATION, NULL, "accept: %s \n", strerror(errno));
		return;
	}

	plog(LLV_INFO, LOCATION, NULL, "nl_lst Connected:\n");

	setsock(cli_sock_fd, O_NONBLOCK, sockbufsiz, "stub client");

	sock_cli = cli_sock_fd;

	/*
	 * Now we do have a registered Client, it is time
	 * to set up events for cli_sock_fd :
	 *  - receive event 
	 *  - send event, so that no sending will ever be blocking
	 */
	event_set(&event_recv, sock_cli, EV_READ | EV_PERSIST, serv_get, NULL);
	if(event_add(&event_recv, NULL))
	{
		plog(LLV_ERROR, LOCATION, NULL, "event_add event_recv \n");
		return;
	}

}

/* new socket for nl_lst*/
static int serv_socket(struct sockaddr *sa)
{
	int sockfd;
	struct linger linger;

	sockfd = newsock(sa->sa_family, SOCK_STREAM, 0, 0, sockbufsiz, "server connect");
	if (sockfd < 0) {
		perror("cannot open socket");
		return -1;
	}

	/* set reuse addr option, to avoid bind error when re-starting */
	int on = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		perror("setsockopt SO_REUSEADDR");
		goto error;
	}

	/* immediately send a TCP RST when closing socket */
	linger.l_onoff  = 1;
	linger.l_linger = 0;	
	if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0) {
		perror("setsockopt SO_LINGER");
		goto error;
	}

	if (bind(sockfd, sa, sockaddr_len(sa)) < 0)
	{
		perror("cannot bind socket");
		goto error;
	}

	if (listen (sockfd, 1)) {
		perror("listen");
		goto error;
	}

	event_set (&event_conn, sockfd,
			EV_READ | EV_PERSIST,
			serv_accept, NULL);
	event_add (&event_conn, NULL);

	sock_conn = sockfd;

	return 0;

error:
	close(sockfd);
	return -1;
}

int main(int argc, char *argv[])
{
	int ch;
	int f_foreground = 0;
	struct sockaddr_un addr_un;
	int srv_family = AF_LOCAL;

	progname = strrchr(argv[0], '/');
	if (progname)
		progname++;
	else
		progname = argv[0];

	/*
	 * set stdout and stderr line buffered, so that user can read messages
	 * as soon as line is complete
	 */
	setlinebuf(stdout);
	setlinebuf(stderr);

	while((ch = getopt(argc, argv, "FVdl:")) != -1)
	{
		switch(ch){
		case 'F':
			f_foreground = 1;
			break;
		case 'V':
			printf("version is 1.0\n");
			break;
		case 'd':
			loglevel++;
			break;
		case 'l':
			plogset(optarg);	//设置日志文件路径
			break;
		default:
			show_usage();
			break;
		}
	}

	/*
	 * Daemon stuff : 
	 *  - detach terminal
	 *  - keep current working directory
	 *  - keep std outputs opened 
	 */	
	if (!f_foreground) {
		FILE *fp;
		if (daemon(1, 1) < 0)
			err(1, "daemon");
		if ((fp = fopen(pidfilename, "w")) != NULL) {
			fprintf(fp, "%d\n", (int) getpid());
			fclose(fp);
		}
	}

	event_init();

	/* 设置unix域套接字 */
	memset(&addr_un, 0, sizeof(addr_un));
	if(srv_family == AF_LOCAL)
	{
		if(set_sockaddr_unix((struct sockaddr *)&addr_un, srv_path))
		{
			plog(LLV_ERROR, LOCATION, NULL, "set unix domain socket failed! \n");
			exit(-1);
		}
		unlink(srv_path);
	}

	if(serv_socket((struct sockaddr *)&addr_un) < 0)
	{
		return -1;
	}

	/* Infinite loop */
	event_dispatch();

	return 0;
}
