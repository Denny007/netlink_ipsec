#ifndef __NL_XFRM_H__
#define __NL_XFRM_H__ 1


#include "ipsec_common.h"

/*
 * IPsec SA structure (internal to CM)
 * CM allocates size of this struct + size for crypto keys
 */
struct nl_ipsec_sa
{
	u_int8_t          family;   /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int8_t          state;   /* e.g. dying or dead */
	u_int8_t          mode;    /* tunnel if set, transport if 0 */

	u_int32_t         spi;     /* IPsec SPI */
	cp_ipsec_addr_t   daddr;   /* destination address */
	cp_ipsec_addr_t   saddr;   /* source address */
	u_int32_t         reqid;   /* request ID */

	u_int32_t         svti_ifindex; /* SVTI interface ifindex */

	u_int16_t         sport;   /* (optional), used in NAT-traversal mode */
	u_int16_t         dport;   /* (optional), used in NAT-traversal mode */

	u_int32_t         oseq;    /* highest sent sequence number */
	u_int32_t         seq;     /* highest received sequence number */
	u_int32_t         bitmap;  /* replay window bitmap */

	u_int8_t          replay;  /* optional replay window size */
	u_int8_t          ealgo;   /* encryption algorithm */
	u_int8_t          aalgo;   /* authentication algorithm */
	u_int8_t          calgo;   /* compression algorithm (not yet) */

	u_int16_t         ekeylen; /* encryption key length in bytes */
	u_int16_t         akeylen; /* authentication key length in bytes */
	u_int32_t         flags;

	u_int32_t         gap;      /* GAP in output sequence number, for SA Migration purpose */

	u_int32_t         fpid;     /* fast path unique id */
	u_int8_t          output_blade; /* fast path output blade */

	u_int8_t          keys[0];   /* cryptographic keys */
};


/*
 * IPsec SP structure (internal to CM)
 */
struct nl_ipsec_sp
{
	u_int32_t         index;    /* rule unique ID */
	u_int32_t         priority; /* rule priority (order in SPD) */

	u_int8_t          family;   /* AF_INET or AF_INET6 */
	u_int8_t          dir;      /* flow direction */
	u_int8_t          proto;     /* L4 protocol */
	u_int8_t          action;   /* destination address prefix length */

	cp_ipsec_addr_t   saddr;   /* source address */
	cp_ipsec_addr_t   daddr;   /* destination address */

	u_int16_t         sport;   /* source port */
	u_int16_t         dport;   /* destination port */
	u_int16_t         sportmask;   /* source port mask */
	u_int16_t         dportmask;   /* destination mask */

	u_int32_t         svti_ifindex; /* SVTI interface ifindex */

	u_int8_t          spfxlen;   /* source address prefix length */
	u_int8_t          dpfxlen;   /* destination address prefix length */
	u_int8_t          xfrm_count;  /* nb of transformations in bundle */
	u_int8_t          reserved2;

	u_int32_t         flags;

	u_int32_t         fpid;      /* fast path unique id */
	
	struct cp_ipsec_xfrm xfrm[0];  /* transformations (SA templates) */
};


/*
 * total structure size (including keys) is rounded to next 32 bit boundary
 */

#define CM_IPSEC_ALG_UNKNOWN      255

#define CM_IPSEC_AALG_NONE          0
#define CM_IPSEC_AALG_MD5HMAC       2
#define CM_IPSEC_AALG_SHA1HMAC      3
#define CM_IPSEC_AALG_SHA2_256HMAC  5
#define CM_IPSEC_AALG_SHA2_384HMAC  6
#define CM_IPSEC_AALG_SHA2_512HMAC  7
#define CM_IPSEC_AALG_RIPEMD160HMAC 8
#define CM_IPSEC_AALG_AES_XCBC_MAC  9

#define CM_IPSEC_EALG_NONE          0
#define CM_IPSEC_EALG_DESCBC        2
#define CM_IPSEC_EALG_3DESCBC       3
#define CM_IPSEC_EALG_CASTCBC       6
#define CM_IPSEC_EALG_BLOWFISHCBC   7
#define CM_IPSEC_EALG_AESCBC       12
#define CM_IPSEC_EALG_SERPENTCBC  252
#define CM_IPSEC_EALG_TWOFISHCBC  253

#define CM_IPSEC_F_NOECN        0x00000001
#define CM_IPSEC_F_DECAP_DSCP   0x00000002
#define CM_IPSEC_F_NOPMTUDISC   0x00000004

#define CM_IPSEC_STATE_NONE     0
#define CM_IPSEC_STATE_DYING    1


#define _PF(f) case f: str = #f ; break;

u_int8_t aalg_nl2cm(char *alg_name);
u_int8_t ealg_nl2cm(char *alg_name);
void parse_xfrm_nlmsg(struct nlmsghdr *nlh);
void xfrm_dump(struct nl_ipsec_sa *sa);
const char *nl_ipsec_aalg2str(u_int8_t alg);
const char *nl_ipsec_ealg2str(u_int8_t alg);


#endif