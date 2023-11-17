#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <plain_buf.h>

void init_buff(struct buffer *buf, int len){
    buf->buff = (char *)malloc(len);
    buf->head = buf->tail = 0;
    buf->size = len;
}

int buff_used(struct buffer *buf){
    return (buf->tail - buf->head);
}

int buff_free(struct buffer *buf){
    return (buf->size - buf->tail);
}

int read_buff(struct buffer *buf, char *rbuf, int len){
    if(len <= 0) return len;
    memcpy(rbuf, buf->buff + buf->head, len);
    buf->head += len;
    return len;
}

int write_buff(struct buffer *buf, char *wbuf, int len){
    if(len <= 0) return len;
    memcpy(buf->buff + buf->tail, wbuf, len);
    buf->tail += len;
    return len;
}

int buff_empty(struct buffer *buf){
    if(buf->tail - buf->head > 0) return 0;
    return 1;
}

int buff_full(struct buffer *buf){
    if(buf->tail == buf->size) return 1;
    return 0;
}