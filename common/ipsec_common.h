#ifndef __IPSEC_COMMON_H__
#define __IPSEC_COMMON_H__ 1


#include <sys/queue.h>

/*
 *==============================================================
 * Common header for messages sent from the nl_listen
 * to another program on the UNIX socket
 *==============================================================
 */
struct cp_hdr {
	u_int32_t cphdr_type;    /* Message type                              */
	u_int32_t cphdr_sn;      /* Sequence Number                           */
	u_int32_t cphdr_report;  /* Desired report                            */
	u_int32_t cphdr_length;  /* This length does NOT include common header*/
};



/*
 * FPM internal
 */
struct fpm_msg {
	TAILQ_ENTRY(fpm_msg)   msg_link;     /* chaining stuff       */
	u_int32_t              msg_sn;       /* sequence number      */
	u_int32_t              msg_len;      /* total message length */
	u_int32_t              msg_off;      /* sending start offset */
	u_int32_t              msg_replay_scheduled:1;
	                       /* replay was requested while this packet was
	                        * partially sent. This packet replay is already
	                        * scheduled. once sent, do not archive it and
	                        * do not free msg_pkt */
	struct cp_hdr        * msg_pkt;      /* message itself       */
};


typedef union {
	struct in_addr addr4;
	struct in6_addr addr6;
} cp_ipsec_addr_t;



/*
 *==============================================================

 * IPsec SA  messages
 *==============================================================
 */

#define CMD_IPSEC_BASE       0x070000

/*
 *--------------------------------------------------------------
 * Parameters For SAs (Security Associations)
 *--------------------------------------------------------------
 */
#define CMD_IPSEC_SA_BASE          CMD_IPSEC_BASE  +  0x100

#define CMD_IPSEC_SA_CREATE       (CMD_IPSEC_SA_BASE + 1)
#define CMD_IPSEC_SA_DELETE       (CMD_IPSEC_SA_BASE + 2)
#define CMD_IPSEC_SA_FLUSH        (CMD_IPSEC_SA_BASE + 3)
#define CMD_IPSEC_SA_REPLAYWIN    (CMD_IPSEC_SA_BASE + 4)
#define CMD_IPSEC_SA_MIGRATE      (CMD_IPSEC_SA_BASE + 5)
#define CMD_IPSEC_SA_BULK_MIGRATE (CMD_IPSEC_SA_BASE + 6)


/* For fpm graceful restart simplifications, cp_ipsec_sa_add must be castable to cp_ipsec_sa_del */
struct cp_ipsec_sa_add {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int8_t          mode;    /* tunnel if set, transport if 0 */
	u_int8_t          reserved;

	u_int32_t         spi;     /* IPsec SPI */
	cp_ipsec_addr_t   daddr;   /* destination address */
	cp_ipsec_addr_t   saddr;   /* source address */

	u_int32_t         reqid;   /* request ID */

	u_int32_t         svti_ifindex; /* SVTI interface ifindex */

	u_int16_t         sport;   /* (optional), used in NAT-traversal mode */
	u_int16_t         dport;   /* (optional), used in NAT-traversal mode */

	u_int16_t         ekeylen; /* encryption key length */
	u_int16_t         akeylen; /* authentication key length */
	u_int32_t         flags;

	u_int8_t          ealgo;   /* encryption algorithm */
	u_int8_t          aalgo;   /* authentication algorithm */
	u_int8_t          calgo;   /* compression algorithm (not yet) */
	u_int8_t          replay;  /* optional replay window size */

	u_int32_t         fpid;    /* Fast Path unique ID */
	u_int8_t          output_blade; /* Fast Path output blade */
	u_int8_t          pad1;
	u_int8_t          pad2;
	u_int8_t          pad3;

	u_int8_t          keys[0]; /* cryptographic keys */
};


/* For fpm graceful restart simplifications, cp_ipsec_sa_add must be castable to cp_ipsec_sa_del */
struct cp_ipsec_sa_del {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;  
	u_int8_t          state;
	u_int8_t          reserved;
	u_int32_t         spi;     /* IPsec SPI */
	cp_ipsec_addr_t   daddr;   /* destination address */
	cp_ipsec_addr_t   saddr;   /* source address */
};


/*
 *--------------------------------------------------------------
 * Parameters For SPs (Security Policies)
 *--------------------------------------------------------------
 */
#define CMD_IPSEC_SP_BASE       CMD_IPSEC_BASE  +  0x200

#define CMD_IPSEC_SP_CREATE    (CMD_IPSEC_SP_BASE + 1)
#define CMD_IPSEC_SP_DELETE    (CMD_IPSEC_SP_BASE + 2)
#define CMD_IPSEC_SP_FLUSH     (CMD_IPSEC_SP_BASE + 3)

/*
 * IPsec transformation (SA template)
 */
struct cp_ipsec_xfrm {
	u_int8_t          family;  /* AF_INET or AF_INET6 */
	u_int8_t          proto;   /* IPPROTO_AH or IPPROTO_ESP */
	u_int8_t          mode;    /* tunnel if set, transport if 0 */
	u_int8_t          flags;

	cp_ipsec_addr_t   saddr;   /* source address. ignored in transport mode */
	cp_ipsec_addr_t   daddr;   /* destination address. mandatory if tunnel
	                            * mode or if SPI is specified */
	u_int32_t         spi;     /* (optional) */
	u_int32_t         reqid;   /* (optional) request id */
};

/* For fpm graceful restart simplifications, cp_ipsec_sp_add must be castable to cp_ipsec_sp_del */
struct cp_ipsec_sp_add {
	u_int32_t         index;    /* rule unique ID */
	u_int32_t         priority; /* rule priority (order in SPD) */

	/* selector */
	u_int8_t          reserved;
	u_int8_t          family;   /* AF_INET or AF_INET6 */
	u_int8_t          dir;      /* flow direction */
	u_int8_t          proto;    /* L4 protocol */

	cp_ipsec_addr_t   saddr;   /* source address */
	cp_ipsec_addr_t   daddr;   /* destination address */

	u_int16_t         sport;   /* source port */
	u_int16_t         dport;   /* destination port */
	u_int16_t         sportmask;   /* source port mask */
	u_int16_t         dportmask;   /* destination mask */


	u_int8_t          spfxlen;   /* source address prefix length */
	u_int8_t          dpfxlen;   /* destination address prefix length */
	u_int8_t          action;      /* clear/discard/ipsec */
	u_int8_t          xfrm_count;  /* nb of transformations in bundle */

	u_int32_t         flags;
	u_int32_t         fpid;    /* Fast Path unique ID */

	struct cp_ipsec_xfrm xfrm[0];  /* transformations (SA templates) */
};

/*
 * Note: In CMD_IPSEC_SP_DELETE message, the CM sends both the packet selector
 * and the SP index. One of the 2 would be enough.
 * Therefore, the FPM is free to use the selector or the index to identify
 * the SP to delete.
 */
/* For fpm graceful restart simplifications, cp_ipsec_sp_add must be castable to cp_ipsec_sp_del */
struct cp_ipsec_sp_del {

	u_int32_t         index;    /* rule unique ID */
	u_int32_t         priority; /* rule priority (order in SPD) */

	/* selector */
	u_int8_t          reserved;
	u_int8_t          family;   /* AF_INET or AF_INET6 */
	u_int8_t          dir;      /* flow direction */
	u_int8_t          proto;    /* L4 protocol */

	cp_ipsec_addr_t   saddr;   /* source address */
	cp_ipsec_addr_t   daddr;   /* destination address */

	u_int16_t         sport;   /* source port or icmp type */
	u_int16_t         dport;   /* destination port or icmp code */
	u_int16_t         sportmask;   /* source port mask or icmp type mask */
	u_int16_t         dportmask;   /* destination mask or icmp code mask */

	u_int8_t          spfxlen;   /* source address prefix length */
	u_int8_t          dpfxlen;   /* destination address prefix length */
	u_int8_t          action;    /* clear/discard/ipsec */
	u_int8_t          xfrm_count;  /* nb of transformations in bundle */
};

#define NL_IPSEC_DIR_INBOUND  1
#define NL_IPSEC_DIR_OUTBOUND 2
#define NL_IPSEC_DIR_FWDBOUND 3

#define CM_IPSEC_ACTION_CLEAR   0
#define CM_IPSEC_ACTION_DISCARD 1
#define CM_IPSEC_ACTION_IPSEC   2

#define CM_IPSEC_MODE_TRANSPORT 0
#define CM_IPSEC_MODE_TUNNEL    1


#endif