#ifndef __NL_PRIV_H__
#define __NL_PRIV_H__ 1


/*
 *  Files for the main()
 */ 
#define  DEFAULT_CM_PIDFILE  "/var/run/lis_xfrm.pid"
#define  DEFAULT_CM_CFGFILE  "/var/tmp/lis_xfrm.conf"

/* 64位系统和32位系统的指针长度不一致 */
#ifdef linux_x64
#define int_cast long
#else
#define int_cast int
#endif

/* message family (for XXX2str functions) */
#define MSG_FAMILY_RTM  		1
#define MSG_FAMILY_ADM  		2
#define MSG_FAMILY_DSTM 		3
#define MSG_FAMILY_RTM_MULTICAST 	4
#define MSG_FAMILY_NAT 			5
#define MSG_FAMILY_IFACE        6
#define MSG_FAMILY_ADDR         7
#define MSG_FAMILY_NEIGH        8
#define MSG_FAMILY_SNOOPING     9
#define MSG_FAMILY_VNB		10
#define MSG_FAMILY_XFRM		11

#define SPACES "        "


#define NL_ALIGN32(a) (1 + (((a) - 1) | (32 - 1)))
#define NL_ALIGNUNIT8(a) ((a + 7) >> 3)


#endif