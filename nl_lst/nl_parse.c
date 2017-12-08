/**
 *	Description:parse the netlink message or arrtibution
 *
**/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <linux/netlink.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "plog.h"
#include "logger.h"

/**
 * Check if the attribute header and payload can be accessed safely.
 * @arg nla		Attribute of any kind.
 * @arg remaining	Number of bytes remaining in attribute stream.
 *
 * Verifies that the header and payload do not exceed the number of
 * bytes left in the attribute stream. This function must be called
 * before access the attribute header or payload when iterating over
 * the attribute stream using nla_next().
 *
 * @return True if the attribute can be accessed safely, false otherwise.
 */
int nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= sizeof(*nla) &&
	       nla->nla_len >= sizeof(*nla) &&
	       nla->nla_len <= remaining;
}

/**
 * Return next attribute in a stream of attributes.
 * @arg nla		Attribute of any kind.
 * @arg remaining	Variable to count remaining bytes in stream.
 *
 * Calculates the offset to the next attribute based on the attribute
 * given. The attribute provided is assumed to be accessible, the
 * caller is responsible to use nla_ok() beforehand. The offset (length
 * of specified attribute including padding) is then subtracted from
 * the remaining bytes variable and a pointer to the next attribute is
 * returned.
 *
 * nla_next() can be called as long as remainig is >0.
 *
 * @return Pointer to next attribute.
 */
struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
	int totlen = NLA_ALIGN(nla->nla_len);

	*remaining -= totlen;
	return (struct nlattr *) ((char *) nla + totlen);
}

/**
 * Return type of the attribute.
 * @arg nla		Attribute.
 *
 * @return Type of attribute.
 */
int nla_type(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}

/**
 * Return pointer to the payload section.
 * @arg nla		Attribute.
 *
 * @return Pointer to start of payload section.
 */
void *nla_data(const struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}

void nl_parse_nlattr (struct nlattr **tb, int maxtype, struct nlattr *head, int len)
{
	struct nlattr *nla;
	nla = head;

	while(nla_ok(nla, len))
	{
		int type = nla_type(nla);
		printf(" nla->nla_type is %d\n", type);
		if (type > maxtype)
			continue;
		tb[type] = nla;

		/* get the next attr */
		nla = nla_next(nla, &(len));
	}
}
