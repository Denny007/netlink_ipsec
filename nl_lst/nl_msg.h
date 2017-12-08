#ifndef __NL_MSG_H__
#define __NL_MSG_H__ 1


int nl_msg_init();
void nl_msg_enqueue(struct cp_hdr *m, void *data);
void nl_msg_dequeue(int fd, short event, void *data);


#endif


