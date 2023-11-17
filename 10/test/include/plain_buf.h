#ifndef ppp
#define ppp

#include "tcp_sock.h"

struct buffer{
    char *buff;
    int head;
    int tail;
    int size;
};

void init_buff(struct buffer *buf, int len);
int buff_used(struct buffer *buf);
int buff_free(struct buffer *buf);
int read_buff(struct buffer *buf, char *rbuf, int len);
int write_buff(struct buffer *buf, char *wbuf, int len);
int buff_empty(struct buffer *buf);
int buff_full(struct buffer *buf);

#endif