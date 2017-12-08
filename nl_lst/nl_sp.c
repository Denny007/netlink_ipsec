/*
 * Description：对SP的创建、删除以及清空操作
 * Author: 		denny 
 * Date: 		2017-11-29 
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <net/if.h>
#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <linux/ipsec.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ipsec_common.h"
#include "nl_priv.h"
#include "nl_parse.h"
#include "nl_xfrm.h"
#include "nl_sa.h"
#include "nl_sp.h"
#include "nl_msg.h"

#include "plog.h"
#include "logger.h"


/*
 * Convert a NETLINK SP to a cache manager SP
 *
 */
static struct nl_ipsec_sp *sp_nl2cm(struct xfrm_userpolicy_info *p, struct nlattr **xfrma)
{
	struct nl_ipsec_sp *sp = NULL;
	int xfrm_count = 0;
	u_int16_t sport, dport;
	int i;

	struct nlattr *rt = xfrma[XFRMA_TMPL];
	struct xfrm_user_tmpl *ut;

	if (rt){
		xfrm_count = (rt->nla_len - sizeof(*rt)) / sizeof(*ut);
	}

	sp = (struct nl_ipsec_sp *)calloc(1, sizeof(*sp) +
		xfrm_count * sizeof(struct cp_ipsec_xfrm));

	if (!sp){
		plog(LLV_ERROR, LOCATION, NULL, "can not malloc memory for sp\n");
		goto bad;
	}

	/* family */
	sp->family = p->sel.family;

	/* destination address */
	memcpy(&sp->daddr, &p->sel.daddr,
				sizeof(sp->daddr));
	dport = p->sel.dport;

	/* source address */
	memcpy(&sp->saddr, &p->sel.saddr,
				sizeof(sp->saddr));
	sport = p->sel.sport;

	sp->spfxlen = p->sel.prefixlen_s;
	sp->dpfxlen = p->sel.prefixlen_d;

	/* source and destination port or type/code */
	switch(p->sel.proto){
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			/* sport and dport specify the TCP/UDP source port and dest port */
			if (sport)
				sp->sportmask = htons(0xffff);
			if (dport)
				sp->dportmask = htons(0xffff);
			break;
		case IPPROTO_ICMP:
			/* sport and dport specify the ICMP type and code */
			if (sport)
				sp->sportmask = htons(0x00ff);
			if (dport)
				sp->dportmask = htons(0x00ff);
			break;
		default:
			break;
	}


	sp->sport = sport & sp->sportmask;
	sp->dport = dport & sp->dportmask;

	/* layer 4 protocol */
	if(p->sel.proto)
		sp->proto = p->sel.proto;
	else
		sp->proto = 0xFF;

	/* rule index (unique ID) */
	sp->index = p->index;

	/* rule priority (order in table) */
	sp->priority = p->priority;

	/* flow direction 数据包方向，in/out/fwd*/
	switch(p->dir){
		case XFRM_POLICY_IN:
			sp->dir = NL_IPSEC_DIR_INBOUND;
			break;
		case XFRM_POLICY_OUT:
			sp->dir = NL_IPSEC_DIR_OUTBOUND;
			break;
		case XFRM_POLICY_FWD:
			sp->dir = NL_IPSEC_DIR_FWDBOUND;
			break;
		default:
			plog(LLV_ERROR, LOCATION, NULL, "invalid policy direction %d\n", p->dir);
			goto bad;
			break;
	}

	/* action */
	switch (p->action) {
		case XFRM_POLICY_BLOCK:
			sp->action = CM_IPSEC_ACTION_DISCARD;
			break;
		case XFRM_POLICY_ALLOW:
			if (xfrm_count)
				sp->action = CM_IPSEC_ACTION_IPSEC;
			else
				sp->action = CM_IPSEC_ACTION_CLEAR;
			break;
		default:
			plog(LLV_ERROR, LOCATION, NULL, "invalid policy action %d\n", p->action);
			goto bad;
			break;
	}

	/* transformations */
	ut = nla_data(rt);
	sp->xfrm_count = xfrm_count;
	for (i=0; i < xfrm_count; i++, ut++) {
		struct cp_ipsec_xfrm *xfrm = &sp->xfrm[i];

		/* protocol (AH or ESP) */
		xfrm->proto = ut->id.proto;

		xfrm->family = ut->family;
		/* optional "outer" destination address */
		memcpy(&xfrm->daddr, &ut->id.daddr,
				sizeof(xfrm->daddr));

		/* "inner" source address */
		memcpy(&xfrm->saddr, &ut->saddr,
				sizeof(xfrm->saddr));

		/* transformation mode (transport/tunnel) */
		xfrm->mode = ut->mode ? CM_IPSEC_MODE_TUNNEL : CM_IPSEC_MODE_TRANSPORT;
		xfrm->reqid = ut->reqid;
	}
	return sp;
bad:
	if (sp){
		free(sp);
	}

	return NULL;

}

/*
 * Convert a simple NETLINK SP info to an cache manager SP
 * Used for cm2cp_ipsec_sp_delete()
 */
static struct nl_ipsec_sp *sp_nlid2cm(struct xfrm_userpolicy_info *p, struct nlattr **xfrma)
{
	struct nl_ipsec_sp *sp = NULL;
	//int xfrm_count = 0;
	u_int16_t sport, dport;

	//struct nlattr *rt = xfrma[XFRMA_TMPL];
	//struct xfrm_user_tmpl *ut;

	sp = (struct nl_ipsec_sp *)calloc(1, sizeof(*sp));

	if (!sp)
		goto bad;

	/* family */
	sp->family = p->sel.family;

	/* destination address */
	memcpy(&sp->daddr, &p->sel.daddr,
			sizeof(sp->daddr));
	dport = p->sel.dport;

	/* source address */
	memcpy(&sp->saddr, &p->sel.saddr,
			sizeof(sp->saddr));
	sport = p->sel.sport;

	sp->spfxlen = p->sel.prefixlen_s;
	sp->dpfxlen = p->sel.prefixlen_d;

	/* source and destination port or type/code */
	switch (p->sel.proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		/* sport and dport specify the TCP/UDP source port and dest port */
		if (sport)
			sp->sportmask = htons(0xffff);
		if (dport)
			sp->dportmask = htons(0xffff);
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		/* sport and dport specify the ICMP type and code */
		if (sport)
			sp->sportmask = htons(0x00ff);
		if (dport)
			sp->dportmask = htons(0x00ff);
		break;
	default:
		break;
	}

	sp->sport = sport & sp->sportmask;
	sp->dport = dport & sp->dportmask;

	/* layer 4 protocol */
	if(p->sel.proto)
		sp->proto = p->sel.proto;
	else
		sp->proto = 0xFF;

	/* rule index (unique ID) */
	sp->index = p->index;

	/* flow direction */
	switch (p->dir) {
	case XFRM_POLICY_IN:
		sp->dir = NL_IPSEC_DIR_INBOUND;
		break;
	case XFRM_POLICY_OUT:
		sp->dir = NL_IPSEC_DIR_OUTBOUND;
		break;
	case XFRM_POLICY_FWD:
			sp->dir = NL_IPSEC_DIR_FWDBOUND;
			break;
	default:
		plog(LLV_ERROR, LOCATION, NULL, "invalid policy direction %d\n", p->dir);
		goto bad;
		break;
	}

	return sp;

bad:
	if (sp){
		free(sp);
	}
	return NULL;
}


/*
 * Send a CMD_IPSEC_SA_CREATE/CMD_IPSEC_SA_DELETE message to FPM
 */
void cm2cp_ipsec_sp_create (struct nl_ipsec_sp *sp)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sp_add *sp_add;
	int len;
	int i;

	plog(LLV_DEBUG, LOCATION, NULL, "Create a new Security Policy !!!\n");

	/* the length of the message */
	len = sizeof(*sp_add) + sp->xfrm_count * sizeof(struct cp_ipsec_xfrm);
	hdr = calloc (1, len + sizeof(*hdr));
	hdr->cphdr_report = 0;
	hdr->cphdr_sn = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SP_CREATE);

	sp_add = (struct cp_ipsec_sp_add *)(hdr + 1);

	sp_add->index      = htonl(sp->index);
	sp_add->priority   = htonl(sp->priority);
	sp_add->family     = sp->family;
	sp_add->dir        = sp->dir;
	sp_add->proto      = sp->proto;
	sp_add->saddr      = sp->saddr;
	sp_add->daddr      = sp->daddr;
	sp_add->sport      = sp->sport;
	sp_add->dport      = sp->dport;
	sp_add->sportmask  = sp->sportmask;
	sp_add->dportmask  = sp->dportmask;
	sp_add->spfxlen    = sp->spfxlen;
	sp_add->dpfxlen    = sp->dpfxlen;
	sp_add->flags      = htonl(sp->flags);
	sp_add->fpid       = sp->fpid;
	sp_add->action     = sp->action;
	sp_add->xfrm_count = sp->xfrm_count;

	for (i=0; i < sp->xfrm_count; i++) {
		sp_add->xfrm[i].family = sp->xfrm[i].family;
		sp_add->xfrm[i].proto = sp->xfrm[i].proto;
		sp_add->xfrm[i].flags = sp->xfrm[i].flags;
		sp_add->xfrm[i].saddr = sp->xfrm[i].saddr;
		sp_add->xfrm[i].daddr = sp->xfrm[i].daddr;
		sp_add->xfrm[i].spi   = sp->xfrm[i].spi;
		sp_add->xfrm[i].reqid = htonl(sp->xfrm[i].reqid);
		sp_add->xfrm[i].mode  = sp->xfrm[i].mode;
	}

	/* inset the msg to the tailq queue */
	nl_msg_enqueue(hdr, NULL);

}

void cm2cp_ipsec_sp_delete(struct nl_ipsec_sp *sp)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sp_del *sp_del;
	int len;

	plog(LLV_DEBUG, LOCATION, NULL, "Delete Security Policy !!!\n");

	len = sizeof(*sp_del);
	hdr = calloc (1, len + sizeof (*hdr));
	hdr->cphdr_report = 0;
	hdr->cphdr_sn = 0;
	hdr->cphdr_length = htonl (len);
	hdr->cphdr_type = htonl (CMD_IPSEC_SP_DELETE);

	sp_del = (struct cp_ipsec_sp_del *)(hdr + 1);

	sp_del->index      = htonl(sp->index);
	sp_del->priority   = htonl(sp->priority);
	sp_del->family     = sp->family;
	sp_del->dir        = sp->dir;
	sp_del->proto      = sp->proto;
	sp_del->saddr      = sp->saddr;
	sp_del->daddr      = sp->daddr;
	sp_del->sport      = sp->sport;
	sp_del->dport      = sp->dport;
	sp_del->sportmask  = sp->sportmask;
	sp_del->dportmask  = sp->dportmask;
	sp_del->spfxlen    = sp->spfxlen;
	sp_del->dpfxlen    = sp->dpfxlen;
	sp_del->action     = sp->action;

	/* inset the msg to the tailq queue */
	nl_msg_enqueue(hdr, NULL);

}

void cm2cp_ipsec_sp_flush()
{
	struct cp_hdr *hdr;

	plog(LLV_DEBUG, LOCATION, NULL, "Flush Security Policy !!!\n");

	hdr = calloc (1, sizeof (*hdr));
	hdr->cphdr_report = 0;
	hdr->cphdr_sn = 0;
	hdr->cphdr_length = 0;
	hdr->cphdr_type = htonl (CMD_IPSEC_SP_FLUSH);

	/* inset the msg to the tailq queue */
	nl_msg_enqueue(hdr, NULL);
}


/* create a new security policy */
void nl_xfrm_newsp(struct nlmsghdr *nlh)
{
	struct xfrm_userpolicy_info *p = NLMSG_DATA(nlh);
	struct nlattr *tb[XFRMA_MAX + 1];
	struct nlattr *attr = (void *) nlh + NLMSG_SPACE (sizeof(struct xfrm_userpolicy_info));
	struct nl_ipsec_sp *sp;
	int len;

	/* get the length of netlink security policy message*/
	len = nlh->nlmsg_len - NLMSG_SPACE(sizeof(struct xfrm_userpolicy_info));
	if(len < 0)
	{
		plog(LLV_ERROR, LOCATION, NULL, "bad length recived \n");
		return;
	}

	/*  */
	if ((p->index & 0x7) >= XFRM_POLICY_MAX) {
		plog(LLV_ERROR, LOCATION, NULL, "ignoring socket policy\n");
		return;
	}

	memset(tb, 0, sizeof(tb));
	nl_parse_nlattr(tb, XFRMA_MAX, attr, len);

	sp = sp_nl2cm(p, tb);
	if (sp) {
		cm2cp_ipsec_sp_create(sp);
		free(sp);
	}	



}


#define XFRM_NLA(x) ((struct nlattr*)(((char*)(x)) + NLMSG_ALIGN(sizeof(*(x)))))
void nl_xfrm_delsp(struct nlmsghdr *nlh)
{
	struct xfrm_userpolicy_info *xpinfo = NULL;
	struct xfrm_userpolicy_id *xpid;
	struct nlattr *tb[XFRMA_MAX + 1];
	struct nlattr *attrs;
	struct nl_ipsec_sp *sp;
	int len = nlh->nlmsg_len;

	/* only handle delete messages */
	if (nlh->nlmsg_type != XFRM_MSG_DELPOLICY) {
		return;
	}

	xpid = NLMSG_DATA(nlh);
	len = len - NLMSG_SPACE(sizeof(*xpid));
	attrs = XFRM_NLA(xpid);

	/* in delpolicy messages, xfrm_usersp_info is stored in 1st attribute */
	if(nla_ok(attrs, len) && attrs->nla_type == XFRMA_POLICY)
	{
		xpinfo = nla_data(attrs);
		attrs = nla_next(attrs, &len);
	}
	else
	{
		plog(LLV_ERROR, LOCATION, NULL, "netlink XFRM_MSG_DELPOLICY: missing XFRMA_POLICY attribute\n");
		return ;
	}

	memset(tb, 0, sizeof(tb));
	nl_parse_nlattr(tb, XFRMA_MAX, attrs, len);
	sp = sp_nlid2cm(xpinfo, tb);
	if (sp) {
		cm2cp_ipsec_sp_delete(sp);
		free(sp);
	}
}

void nl_xfrm_expiresp(struct nlmsghdr *nlh)
{
	struct xfrm_user_polexpire *xpexp = NLMSG_DATA(nlh);
	struct xfrm_userpolicy_info *xpinfo = &xpexp->pol;
	
	struct nlattr *tb[XFRMA_MAX + 1];
	struct nlattr *attrs = (void *)nlh + NLMSG_SPACE(sizeof(struct xfrm_user_polexpire));;

	struct nl_ipsec_sp *sp;

	int len = nlh->nlmsg_len;
	if (len < 0) {
		plog(LLV_ERROR, LOCATION, NULL, "bad length recived \n");
		return;
	}

	/* ignore soft expire */
	if (xpexp->hard == 0)
		return;

	memset(tb, 0, sizeof tb);
	nl_parse_nlattr(tb, XFRMA_MAX, attrs, len);
	sp = sp_nlid2cm(xpinfo, tb);
	if (sp) {
		cm2cp_ipsec_sp_delete(sp);
		free(sp);
	}
}

void nl_xfrm_flushsp(struct nlmsghdr *nlh)
{

	cm2cp_ipsec_sp_flush();

}