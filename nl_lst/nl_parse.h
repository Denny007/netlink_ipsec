#ifndef __NL_PARSE_H__
#define __NL_PARSE_H__ 1




int nla_ok(const struct nlattr *nla, int remaining);
struct nlattr *nla_next(const struct nlattr *nla, int *remaining);
int nla_type(const struct nlattr *nla);
void *nla_data(const struct nlattr *nla);


void nl_parse_nlattr (struct nlattr **tb, int maxtype, struct nlattr *head, int len);

#endif