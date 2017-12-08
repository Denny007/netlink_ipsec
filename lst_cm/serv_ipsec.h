#ifndef __SERV_IPSEC_H__
#define __SERV_IPSEC_H__ 1


#define FP_NIPQUAD_FMT "%u.%u.%u.%u"
#define FP_NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]



extern int serv_ipsec_sa_create(struct cp_ipsec_sa_add *sa);
extern int serv_ipsec_sa_delete(struct cp_ipsec_sa_del *sa);
extern int serv_ipsec_sa_flush();

extern int serv_ipsec_sp_create(struct cp_ipsec_sp_add *sp);
extern int serv_ipsec_sp_delete(struct cp_ipsec_sp_del *sp);
extern int serv_ipsec_sp_flush();


#endif