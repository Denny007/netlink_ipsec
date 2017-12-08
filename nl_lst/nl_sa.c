/*
 * Description：对SA的创建、删除以及清空操作
 * Author:  	denny 
 * Date: 		2017-11-24 
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
 * Send a CMD_IPSEC_SA_CREATE/CMD_IPSEC_SA_DELETE message to FPM
 */
void cm2cp_ipsec_sa_create (struct nl_ipsec_sa *sa)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sa_add *add_sa;
	int len;
	uint16_t keyoffset;
	plog(LLV_DEBUG, LOCATION, NULL, "Create a new Security Association !!!\n");

	len = sizeof(struct cp_ipsec_sa_add) + sa->ekeylen + sa->akeylen; //发送的数据长度

	hdr = calloc(1, len + sizeof(struct cp_hdr));
	hdr->cphdr_report = 0;
	hdr->cphdr_sn = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_type = htonl(CMD_IPSEC_SA_CREATE);

	add_sa = (struct cp_ipsec_sa_add *)(hdr + 1); //指针所指的类型+1，即指向cp_hdr结构体之后的数据

	add_sa->family   = sa->family;
	add_sa->proto    = sa->proto;
	add_sa->spi      = sa->spi;
	add_sa->daddr    = sa->daddr;
	add_sa->saddr    = sa->saddr;
	add_sa->dport    = sa->dport;
	add_sa->sport    = sa->sport;

	add_sa->reqid    = htonl(sa->reqid);
	add_sa->mode     = sa->mode;
	add_sa->ealgo    = sa->ealgo;
	add_sa->aalgo    = sa->aalgo;
	add_sa->ekeylen  = htons(sa->ekeylen);
	add_sa->akeylen  = htons(sa->akeylen);
	add_sa->replay   = sa->replay;
	add_sa->flags    = htonl(sa->flags);

	keyoffset = 0;

	if (sa->ekeylen)
	{
		memcpy(add_sa->keys, sa->keys, sa->ekeylen);
		keyoffset += sa->ekeylen;
	}
	if (sa->akeylen) {
		memcpy(add_sa->keys + keyoffset, sa->keys + keyoffset, sa->akeylen);
	}
	/* inset the msg to the tailq queue */
	nl_msg_enqueue(hdr, NULL);

}

void cm2cp_ipsec_sa_delete(struct nl_ipsec_sa *sa)
{
	struct cp_hdr *hdr;
	struct cp_ipsec_sa_del *del_sa;
	int len;

	plog(LLV_DEBUG, LOCATION, NULL, "Delete the SA !!!\n");

	len = sizeof(struct cp_ipsec_sa_del);
	hdr = calloc(1, len + sizeof (*hdr));
	/* fill up the hdr head */
	hdr->cphdr_report = 0;
	hdr->cphdr_sn = 0;
	hdr->cphdr_length = htonl(len);
	hdr->cphdr_type = htonl(CMD_IPSEC_SA_DELETE);

	del_sa = (struct cp_ipsec_sa_del *)(hdr + 1);
	del_sa->family   = sa->family;
	del_sa->proto    = sa->proto;
	del_sa->spi      = sa->spi;
	del_sa->daddr    = sa->daddr;
	del_sa->state    = sa->state;

	/* inset the msg to the tailq queue */
	nl_msg_enqueue(hdr, NULL);

}

void cm2cp_ipsec_sa_flush()
{
	struct cp_hdr *hdr;

	plog(LLV_DEBUG, LOCATION, NULL, "Flush the SA !!!\n");
	
	hdr = calloc (1,  sizeof (*hdr));
	hdr->cphdr_report = 0;
	hdr->cphdr_sn = 0;
	hdr->cphdr_length = 0;
	hdr->cphdr_type = htonl (CMD_IPSEC_SA_FLUSH);

	nl_msg_enqueue(hdr, NULL);
}


/*
 * 使用自定义的SA结构体存储从内核获取的SA
 */
static struct nl_ipsec_sa *sa_nl2cm(struct xfrm_usersa_info *p, struct nlattr **xfrma)
{
	struct xfrm_algo *auth_algp = NULL;
	struct xfrm_algo *crypt_algp = NULL;
	struct xfrm_encap_tmpl *encap = NULL;

	struct nl_ipsec_sa *sa = NULL;

	uint16_t keybytes = 0;
	uint16_t keyoff = 0;

	plog(LLV_DEBUG, LOCATION, NULL, "sa_nl2cm here !\n");
	if (xfrma)
	{
		/* 消息认证(sha1,md5)的属性 */
		if (xfrma[XFRMA_ALG_AUTH])
		{
			auth_algp = nla_data(xfrma[XFRMA_ALG_AUTH]);
			plog(LLV_DEBUG, LOCATION, NULL, "auth_algp is %s \n", auth_algp->alg_name);
		}

		/* 加密算法(aes,3des)的属性 */
		if (xfrma[XFRMA_ALG_CRYPT]){
			crypt_algp = nla_data(xfrma[XFRMA_ALG_CRYPT]);
			plog(LLV_DEBUG, LOCATION, NULL, "crypt_algp is %s \n", crypt_algp->alg_name);
		}

		if (xfrma[XFRMA_ENCAP]){
			encap = nla_data(xfrma[XFRMA_ENCAP]);
			plog(LLV_DEBUG, LOCATION, NULL, "encap type is %d \n", encap->encap_type);
		}

		/* key的长度 */
		if (auth_algp)
			keybytes += (auth_algp->alg_key_len + 7) / 8;
		if (crypt_algp)
			keybytes += (crypt_algp->alg_key_len + 7) / 8;
	}

	sa = (struct nl_ipsec_sa *)calloc(1, sizeof(*sa) + keybytes);
	if (!sa)
		goto bad;

	/* family */
	sa->family = p->family;

	/* SA protocol */
	sa->proto = p->id.proto;

	/* SPI */
	sa->spi = p->id.spi;

	/* destination address */
	memcpy(&sa->daddr, &p->id.daddr,
				sizeof(sa->daddr));
	/* source address */
	memcpy(&sa->saddr, &p->saddr,
				sizeof(sa->saddr));

	/* IPsec mode */
	sa->mode = p->mode;

	/* request ID */
	sa->reqid = p->reqid;

	/* replay window size */
	sa->replay = p->replay_window;

	/* SA flags */
	sa->flags = p->flags;

	/* encryption algorithm */
	if (crypt_algp) {
		//sa->ealgo = CM_IPSEC_EALG_3DESCBC;
		sa->ealgo = ealg_nl2cm(crypt_algp->alg_name);
		if (sa->ealgo == CM_IPSEC_ALG_UNKNOWN) {
			fprintf(stderr, "%s: unknown encryption algorithm\n", __FUNCTION__);
			goto bad;
		}
	
		sa->ekeylen = NL_ALIGNUNIT8(crypt_algp->alg_key_len);
		memcpy(sa->keys, crypt_algp->alg_key, sa->ekeylen);
		keyoff += sa->ekeylen;
	}
	else
	{
		sa->ealgo = CM_IPSEC_AALG_NONE;
	}

	/* authentication algorithm */	
	if (auth_algp) {
		sa->aalgo = aalg_nl2cm(auth_algp->alg_name);
		if (sa->aalgo == CM_IPSEC_ALG_UNKNOWN) {
			fprintf(stderr, "%s: unknown authentication algorithm\n", __FUNCTION__);
			goto bad;
		}
		sa->akeylen = NL_ALIGNUNIT8(auth_algp->alg_key_len);
		memcpy(sa->keys + keyoff, auth_algp->alg_key, sa->akeylen);
	}
	else
	{
		sa->aalgo = CM_IPSEC_AALG_NONE;
	}

	/* NAT Traversal */
	if (encap) {
		sa->sport = encap->encap_sport;
		sa->dport = encap->encap_dport;
	} else {
		sa->sport = 0;
		sa->dport = 0;
	}

	return sa;

bad:
	if (sa)
	{
		free(sa);
		sa = NULL;	
	}
	return NULL;

}

/*
 * Convert a NETLINK simple SA info to a cache manager SA
 */
static struct nl_ipsec_sa *sa_nlid2cm(struct xfrm_usersa_id *p)
{
	struct nl_ipsec_sa *sa = NULL;

	sa = (struct nl_ipsec_sa *)calloc(1, sizeof(*sa));

	if (!sa)
		goto bad;

	/* Family*/
	sa->family = p->family;
		
	/* SA protocol */
	sa->proto = p->proto;
	
	/* SPI */
	sa->spi = p->spi;

	/* destination address */
	memcpy(&sa->daddr, &p->daddr,
				sizeof(sa->daddr));

	/* source address */
	//memcpy(&sa->saddr, &p->saddr,	sizeof(sa->saddr));

	return sa;

bad:
	if (sa)
		free(sa);
	return NULL;
}

void nl_xfrm_newsa(struct nlmsghdr *nlh)
{
	struct nlattr *tb[XFRMA_MAX + 1];	//存储netlink消息属性数组,XFRMA_MAX定义在内核的xfrm.h头文件中
	struct nlattr *attr = (void *) nlh + NLMSG_SPACE (sizeof(struct xfrm_usersa_info));  //指向netlink消息属性
	struct xfrm_usersa_info *p = NLMSG_DATA(nlh);
	struct nl_ipsec_sa *sa;
	int len;

	/* 实际消息长度 = 数据总长度 - xfrm_usersa_info头部大小 */
	len = nlh->nlmsg_len - NLMSG_SPACE (sizeof(struct xfrm_usersa_info)); 

	if (len < 0)
	{
		plog(LLV_ERROR, LOCATION, NULL, "bad length recived \n");
		return;
	}

	memset(tb, 0, sizeof(tb));
	nl_parse_nlattr (tb, XFRMA_MAX, attr, len);

	sa = sa_nl2cm(p, tb);
	xfrm_dump(sa);
	if (sa) {
		cm2cp_ipsec_sa_create(sa);
		free(sa);
	}

}

void nl_xfrm_delsa(struct nlmsghdr *nlh)
{
	struct nlattr *tb[XFRMA_MAX + 1];
	struct nlattr *attr = (void *)nlh + NLMSG_SPACE(sizeof(struct xfrm_usersa_id));
	struct xfrm_usersa_id *p = NLMSG_DATA(nlh);
	struct nl_ipsec_sa *sa;
	int len;

	len = nlh->nlmsg_len - NLMSG_SPACE (sizeof(struct xfrm_usersa_id));

	if (len < 0) {
		plog(LLV_ERROR, LOCATION, NULL, "bad length recived \n");
		return;
	}

	memset(tb, 0, sizeof(tb));
	nl_parse_nlattr (tb, XFRMA_MAX, attr, len);

	sa = sa_nlid2cm(p);

	if (sa) {
		cm2cp_ipsec_sa_delete(sa);
		free(sa);
	}
}

void nl_xfrm_expiresa(struct nlmsghdr *nlh)
{
	struct nlattr *tb[XFRMA_MAX + 1];
	struct nlattr *attr = (void *)nlh + NLMSG_SPACE(sizeof(struct xfrm_user_expire));
	struct xfrm_user_expire *exp = NLMSG_DATA(nlh);
	struct xfrm_usersa_info *p = &exp->state;
	struct nl_ipsec_sa *sa;
	int len;

	len = nlh->nlmsg_len - NLMSG_SPACE (sizeof(struct xfrm_user_expire));
	if (len < 0) {
		plog(LLV_ERROR, LOCATION, NULL, "bad length recived \n");
		return;
	}

	/* ignore soft expire */
	if (exp->hard == 0)
		return;

	memset(tb, 0, sizeof tb);
	nl_parse_nlattr (tb, XFRMA_MAX, attr, len);

	sa = sa_nl2cm(p, tb);
	if (sa) {
		cm2cp_ipsec_sa_delete(sa);
		free(sa);
	}
}

void nl_xfrm_flushsa(struct nlmsghdr *nlh)
{
	cm2cp_ipsec_sa_flush();
}