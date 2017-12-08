
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
#include "nl_xfrm.h"
#include "nl_parse.h"
#include "nl_priv.h"
#include "nl_sa.h"
#include "nl_sp.h"


#include "plog.h"
#include "logger.h"

u_int8_t ealg_nl2cm(char *alg_name)
{
	u_int8_t alg;
	if(!strcmp(alg_name, "cipher_null"))
	{
		/*SADB_EALG_NULL*/
		alg = CM_IPSEC_EALG_NONE;			
	}
	else if(!strcmp(alg_name, "cbc(des)"))
	{
		/*SADB_EALG_DESCBC*/
		alg = CM_IPSEC_EALG_DESCBC;
	}
	else if(!strcmp(alg_name, "cbc(des3_ede)"))
	{
		/*SADB_EALG_3DESCBC*/
		
		alg = CM_IPSEC_EALG_3DESCBC;
	}
	else if(!strcmp(alg_name, "cbc(cast128)"))
	{
		/*SADB_X_EALG_CASTCBC*/
		alg = CM_IPSEC_EALG_CASTCBC;
	}
	else if(!strcmp(alg_name, "cbc(blowfish)"))
	{
		/*SADB_X_EALG_BLOWFISHCBC*/
		alg = CM_IPSEC_EALG_BLOWFISHCBC;
	}
	else if(!strcmp(alg_name, "cbc(aes)"))
	{
		/*SADB_X_EALG_AESCBC*/
		alg = CM_IPSEC_EALG_AESCBC;
	}
	else if(!strcmp(alg_name, "cbc(serpent)"))
	{
		/*SADB_X_EALG_SERPENTCBC*/
		alg = CM_IPSEC_EALG_SERPENTCBC;
	}
	else if(!strcmp(alg_name, "cbc(twofish)"))
	{
		/*SADB_X_EALG_TWOFISHCBC*/
		alg = CM_IPSEC_EALG_TWOFISHCBC;
	}
	else
	{
		alg = CM_IPSEC_ALG_UNKNOWN;
	}

	return alg;
}

u_int8_t aalg_nl2cm(char *alg_name)
{
	u_int8_t alg;
	if(!strcmp(alg_name, "digest_null"))
	{
		/*SADB_X_AALG_NULL*/
		alg = CM_IPSEC_AALG_NONE;	
	}
	else if(!strcmp(alg_name, "hmac(md5)"))
	{
		/*SADB_AALG_MD5HMAC*/
		alg = CM_IPSEC_AALG_MD5HMAC;
	}
	else if(!strcmp(alg_name, "hmac(sha1)"))
	{
		/*SADB_AALG_SHA1HMAC*/
		alg = CM_IPSEC_AALG_SHA1HMAC;
	}
	else if(!strcmp(alg_name, "hmac(sha256)"))
	{
		/*SADB_X_AALG_SHA2_256HMAC*/
		alg = CM_IPSEC_AALG_SHA2_256HMAC;
	}
	else if(!strcmp(alg_name, "hmac(ripemd160)"))
	{
		/*SADB_X_AALG_RIPEMD160HMAC*/
		alg = CM_IPSEC_AALG_RIPEMD160HMAC;
	}
#ifdef SADB_X_AALG_AES_XCBC_MAC	
	else if(!strcmp(alg_name, "aes"))
	{
		/*SADB_X_AALG_AES_XCBC_MAC*/
		alg = CM_IPSEC_AALG_AES_XCBC_MAC;
	}
#endif	
	else
	{
		alg = CM_IPSEC_ALG_UNKNOWN;
	}
	
	return alg;
}


void xfrm_dump(struct nl_ipsec_sa *sa)
{
	char daddr[INET6_ADDRSTRLEN];
	char saddr[INET6_ADDRSTRLEN];

	saddr[0] = daddr[0] = 0;
	inet_ntop(sa->family, &sa->daddr, daddr, sizeof(daddr));
	inet_ntop(sa->family, &sa->saddr, saddr, sizeof(saddr));

	printf (SPACES "proto=%s spi=0x%08x dst=%s\n", 
				sa->proto == IPPROTO_AH ? "ah" : "esp",
				(unsigned int)ntohl(sa->spi), daddr);

	printf (SPACES "src=%s\n", saddr);

	printf(SPACES "reqid=%u mode=%s replay=%d flags=%08x\n",
		(unsigned int)ntohl(sa->reqid),
		sa->mode ? "tunnel" : "transport", sa->replay,
		sa->flags);

	if (sa->fpid || sa->output_blade) {
		printf(SPACES "fpid=0x%08x output_blade=%u\n",
			(unsigned int)ntohl(sa->fpid),
			(unsigned int)sa->output_blade);
	}

	printf(SPACES "ealg=%s(%u) aalg=%s(%u)\n",
		nl_ipsec_ealg2str(sa->ealgo), sa->ealgo,
		nl_ipsec_aalg2str(sa->aalgo), sa->aalgo);

}


/* 解析收到的信息 */
void parse_xfrm_nlmsg(struct nlmsghdr *nlh)
{
		switch (nlh->nlmsg_type) {
		case XFRM_MSG_NEWSA:
		case XFRM_MSG_UPDSA:
			nl_xfrm_newsa(nlh);
			break;
			
		case XFRM_MSG_DELSA:
			nl_xfrm_delsa(nlh);
			break;

		case XFRM_MSG_EXPIRE:
			nl_xfrm_expiresa(nlh);
			break;

		case XFRM_MSG_FLUSHSA:
			nl_xfrm_flushsa(nlh);
			break;	
				
		case XFRM_MSG_NEWPOLICY:
		case XFRM_MSG_UPDPOLICY:
			nl_xfrm_newsp(nlh);
			break;

		case XFRM_MSG_DELPOLICY:
			nl_xfrm_delsp(nlh);
			break;

		case XFRM_MSG_POLEXPIRE:
			nl_xfrm_expiresp(nlh);
			break;

		case XFRM_MSG_FLUSHPOLICY:
			nl_xfrm_flushsp(nlh);
			break;
		default:
			printf("other nlmsg_type(%d). \nexit\n",
				   nlh->nlmsg_type);
			break;
		}

}


const char *nl_ipsec_aalg2str(u_int8_t alg)
{
	static char unknown[] = "CM_IPSEC_AALG_[DDD]";
	char * str;

	switch(alg) {
	_PF(CM_IPSEC_AALG_NONE)
	_PF(CM_IPSEC_AALG_MD5HMAC)
	_PF(CM_IPSEC_AALG_SHA1HMAC)
	_PF(CM_IPSEC_AALG_SHA2_256HMAC)
	_PF(CM_IPSEC_AALG_SHA2_384HMAC)
	_PF(CM_IPSEC_AALG_SHA2_512HMAC)
	_PF(CM_IPSEC_AALG_RIPEMD160HMAC)
	_PF(CM_IPSEC_AALG_AES_XCBC_MAC)

	default:
		sprintf(unknown, "CM_IPSEC_AALG_[%u]", alg);
		str = unknown;
		break;
	}

	return str;
}

const char *nl_ipsec_ealg2str(u_int8_t alg)
{
	static char unknown[] = "CM_IPSEC_EALG_[DDD]";
	char * str;

	switch(alg) {
	_PF(CM_IPSEC_EALG_NONE)
	_PF(CM_IPSEC_EALG_DESCBC)
	_PF(CM_IPSEC_EALG_3DESCBC)
	_PF(CM_IPSEC_EALG_CASTCBC)
	_PF(CM_IPSEC_EALG_BLOWFISHCBC)
	_PF(CM_IPSEC_EALG_AESCBC)
	_PF(CM_IPSEC_EALG_SERPENTCBC)
	_PF(CM_IPSEC_EALG_TWOFISHCBC)

	default:
		sprintf(unknown, "CM_IPSEC_EALG_[%u]", alg);
		str = unknown;
		break;
	}

	return str;
}

