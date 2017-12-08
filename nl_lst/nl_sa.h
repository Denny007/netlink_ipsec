#ifndef __NL_SA_H__
#define __NL_SA_H__ 1


void nl_xfrm_newsa(struct nlmsghdr *nlh);
void nl_xfrm_delsa(struct nlmsghdr *nlh);
void nl_xfrm_expiresa(struct nlmsghdr *nlh);
void nl_xfrm_flushsa(struct nlmsghdr *nlh);




#endif