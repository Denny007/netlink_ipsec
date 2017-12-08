/*
 * Description：处理接收的ipsec消息
 * Author：		Denny
 * Date：		2017-12-5
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/syslog.h>
#include <net/if.h>
#include <event.h>

#include "ipsec_common.h"
#include "cm_msg.h"
#include "serv_ipsec.h"
#include "plog.h"
#include "logger.h"


int serv_ipsec_sa_create(struct cp_ipsec_sa_add *sa)
{
	plog(LLV_INFO, LOCATION, NULL, "serv_ipsec_sa_create: \n");
	if (sa->family == AF_INET) {
		plog(LLV_DEBUG, LOCATION, NULL,"\tproto=%s spi=0x%08x\n"
		 	   "\tdst=%u.%u.%u.%u src=%u.%u.%u.%u sport=%d dport=%d reqid=%u\n"
		       "\tekeylen=%d ealgo=%d akeylen=%d aalgo=%d\n",
				sa->proto == IPPROTO_AH ? "ah" : "esp",
				sa->spi,
				FP_NIPQUAD(sa->daddr),
				FP_NIPQUAD(sa->saddr),
				ntohs(sa->sport),
				ntohs(sa->dport),
				ntohl(sa->reqid),
				ntohs(sa->ekeylen),
				sa->ealgo,
				ntohs(sa->akeylen),
				sa->aalgo);
	}
	return 0;
}
int serv_ipsec_sa_delete(struct cp_ipsec_sa_del *sa)
{
	plog(LLV_INFO, LOCATION, NULL, "serv_ipsec_sa_delete:\n");
	if (sa->family == AF_INET) {
		plog(LLV_DEBUG, LOCATION, NULL,"\tproto=%s spi=0x%08x dst=%u.%u.%u.%u state=%d\n",
					sa->proto == IPPROTO_AH ? "ah" : "esp",
					sa->spi, 
					FP_NIPQUAD(sa->daddr), 
					sa->state);
	}

	return 0;
}


int serv_ipsec_sa_flush()
{
	plog(LLV_INFO, LOCATION, NULL, "serv_ipsec_sa_flush:\n");
	return 0;
}

int serv_ipsec_sp_create(struct cp_ipsec_sp_add *sp)
{
	plog(LLV_INFO, LOCATION, NULL, "serv_ipsec_sp_create:\n");
	if (sp->family == AF_INET) {
		plog(LLV_DEBUG, LOCATION, NULL,"\tdir=%u index=%u proto=%d "
					"src=%u.%u.%u.%u/%d dst=%u.%u.%u.%u/%d action=%d \n"
					" xfrm=%d\n",
					sp->dir,
					ntohl(sp->index),
					sp->proto,
					FP_NIPQUAD(sp->saddr), sp->spfxlen,
					FP_NIPQUAD(sp->daddr), sp->dpfxlen,
					sp->action,
					sp->xfrm_count);
	}
	return 0;
}
int serv_ipsec_sp_delete(struct cp_ipsec_sp_del *sp)
{
	plog(LLV_INFO, LOCATION, NULL, "serv_ipsec_sp_delete:\n");
	if (sp->family == AF_INET) {
		plog(LLV_DEBUG, LOCATION, NULL,"\tindex=%u proto=%d src=%u.%u.%u.%u/%d"
					" dst=%u.%u.%u.%u/%d\n ",
					ntohl(sp->index), 
					sp->proto,
					FP_NIPQUAD(sp->saddr), sp->spfxlen, 
					FP_NIPQUAD(sp->daddr), sp->dpfxlen);
	}
	return 0;
}
int serv_ipsec_sp_flush()
{
	plog(LLV_INFO, LOCATION, NULL, "serv_ipsec_sp_flush:\n");
	return 0;
}