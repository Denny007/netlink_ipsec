#ifndef __NL_SP_H__
#define __NL_SP_H__ 1



void nl_xfrm_newsp(struct nlmsghdr *nlh);
void nl_xfrm_delsp(struct nlmsghdr *nlh);
void nl_xfrm_expiresp(struct nlmsghdr *nlh);
void nl_xfrm_flushsp(struct nlmsghdr *nlh);


#endif