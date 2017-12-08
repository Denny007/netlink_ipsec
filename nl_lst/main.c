/*
 *   监听内核中ipsec（SA、 SP）消息
 *	 
 */

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

#include <event.h>
#include "ipsec_common.h"
#include "nl_con.h"
#include "nl_priv.h"
#include "nl_msg.h"
#include "plog.h"
#include "logger.h"


/*
 * Default file names, access names ...
 */
static char  pidfilename[256] = DEFAULT_CM_PIDFILE;
static char *program;


static void show_usage()
{
	fprintf (stderr, "	-F foreground mode\n"
		"	-V (Version) show program version\n"
		"	-d (debug)   debug level\n"
		"   -l (log_file_path) set the path of log file \n"
		);
	exit(1);
}


/*
 * Signal management
 *    - SIGUSR1 : dump of all tables
 *    - SIGHUP  : reload config
 *    - ...
 */
static struct event sigusr1;
static struct event sighup;
static struct event sigterm;
/* 调用函数cm_sig的地方 最后一个参数传进来的是一个整形而不是整形的指针 */
static void cm_sig (int fd, short event, void *data)
{
	/* 64为机器上指针长度是8字节 */
	if ((int_cast)data == SIGUSR1)
		printf("SIGUSR1 received:\n");
		//fpm_dump();
	else if ((int_cast)data == SIGHUP)
		printf("SIGHUP received:\n");
		//cm_config (configfile);
	else if ((int_cast)data == SIGTERM) {
		/* TBD some cleaning */
		printf ("SIGTERM received: exiting\n");
		exit (1);
	}
	return;
}


int main(int argc, char *argv[])
{
	int f_foreground = 0;
	int ch;

	if (argc < 2)
	{
		show_usage();
	}

	program = strrchr(argv[0], '/');
	if (program){
		program++;
	}
	else{
		program = argv[0];
	}

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
		if(daemon(1, 1) < 0){
			perror("daemon error");
		}
		/* write the pid to the pid file */
		if ((fp = fopen(pidfilename, "w")) != NULL) {
			fprintf(fp, "%d\n", (int) getpid());
			fclose(fp);
		}
	}
 
	ploginit();

	event_init();
	
	/* Now add the various Sigs, and timers */
	signal_set (&sigusr1, SIGUSR1, cm_sig, (void *)SIGUSR1);
	signal_add (&sigusr1, NULL);
	signal_set (&sighup, SIGHUP, cm_sig, (void *)SIGHUP);
	signal_add (&sighup, NULL);
	signal_set (&sigterm, SIGTERM, cm_sig, (void *)SIGTERM);
	signal_add (&sigterm, NULL);

	/* Netlink Init (XFRM) */
	cm_netlink_xfrm_init();

	nl_msg_init();

	event_dispatch();

	return 0;
}