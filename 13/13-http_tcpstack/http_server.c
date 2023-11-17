#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <pthread.h>
#include "tcp_sock.h"
#include "log.h"

#define NUM_THREAD 3

struct info_for_http{
    int which;
    struct tcp_sock *csock;
} info_http[NUM_THREAD];

int http_tid[NUM_THREAD];

int http_busy[NUM_THREAD];

/*void* handle_http_req(void* arg){
    struct info_for_http thisinfo = *(struct info_for_http*)arg;
    struct tcp_sock *csock = thisinfo.csock;
    pthread_detach(pthread_self());
    
    char readbuf[1024] = {0};
    int reqsize = tcp_sock_read(csock, readbuf, 1024);
    if(reqsize < 0){
        log(DEBUG, "recv failed");
        http_busy[thisinfo.which] = 0;
        return NULL;
    }
    
    char method[10];
    char url[50];
    char ver[10];
    sscanf(readbuf, "%s %s %s", method, url, ver);
    
    assert(strcmp(method, "GET") == 0);
    
    //printf("url is: %s -- http\n", url);
    
    char segname[50];
    char ip[30];
    int ii = 0;
    while(readbuf[ii] != '\r' || readbuf[ii + 1] != '\n'){
        while(readbuf[ii] != '\n') ii++;
        sscanf(readbuf + ii + 1, "%[^:]", segname);
        if(strcmp(segname, "Host") == 0){
            sscanf(readbuf + ii + 1, "%*s%s", ip);
            break;
        }
        ii++;
    }
    
    char sendbuf[1024];
    int used = 0;
    used += sprintf(sendbuf, "%s 301 Moved Permanently\r\n", ver);
    used += sprintf(sendbuf + used, "Server: lgy\r\n");
    used += sprintf(sendbuf + used, "Content-Length: 0\r\n");
    used += sprintf(sendbuf + used, "Location: https://%s%s\r\n", ip, url);
    used += sprintf(sendbuf + used, "\r\n");
    sendbuf[used] = '\0';
    
    if(send(csock, sendbuf, strlen(sendbuf), 0) < 0){
        perror("send failed");
        http_busy[thisinfo.which] = 0;
        return NULL;
    }
    
    http_busy[thisinfo.which] = 0;
    return NULL;
}*/

void* handle_http_req(void* arg){
    struct info_for_http thisinfo = *(struct info_for_http*)arg;
    struct tcp_sock *csock = thisinfo.csock;
    pthread_detach(pthread_self());
    char readbuf[1024] = {0};
    int reqsize = tcp_sock_read(csock, readbuf, sizeof(readbuf));
    if(reqsize < 0){
        log(DEBUG, "read failed");
        http_busy[thisinfo.which] = 0;
        return NULL;
    }
    
    char method[10];
    char url[50];
    char ver[10];
    sscanf(readbuf, "%s %s %s", method, url, ver);
    
    if(strcmp(method, "GET") != 0){
        perror("method not supported");
        http_busy[thisinfo.which] = 0;
        return NULL;
    }
    
    //printf("url received is %s\n", url);

    int st_code;
    char st_message[30];
    FILE* file = fopen(url + 1, "r");
    
    char* sendbuf = malloc(1024*1024*100);
    
    int fsize = 0;
    if(!file){
        st_code = 404;
        strcpy(st_message, "Not Found");
        int used = 0;
        used += sprintf(sendbuf, "%s %d %s\r\n", ver, st_code, st_message);
        used += sprintf(sendbuf + used, "Server: lgy\r\n");
        used += sprintf(sendbuf + used, "Content-Length: 0\r\n");
        used += sprintf(sendbuf + used, "\r\n");
        sendbuf[used] = '\0';
        fsize += used;
    }
    else{
        char* fbuf = malloc(1024*1024*100);
        char c = 0;
        while((c = fgetc(file)) != EOF && fsize < 1024*1024*100){
            fbuf[fsize] = c;
            fsize++;
        }
        if(fsize >= 1024*1024*100){
            log(DEBUG, "file too big");
        }
        fbuf[fsize] = '\0';
        //printf("file read\n");
        //printf("fsize: %d\n", fsize);
        
        char segname[50];
        char range[30];
        int ii = 0;
        int is_part = 0;
        while(readbuf[ii] != '\r' || readbuf[ii + 1] != '\n'){
            while(readbuf[ii] != '\n') ii++;
            sscanf(readbuf + ii + 1, "%[^:]", segname);
            //printf("%s\n", segname);
            if(strcmp(segname, "Range") == 0){
                is_part = 1;
                sscanf(readbuf + ii + 1, "%*s%s", range);
                break;
            }
            ii++;
        }
        //printf("check done\n");
        if(is_part){
            st_code = 206;
            strcpy(st_message, "Partial Content");
            
            assert(strncmp(range, "bytes=", 6) == 0);
            int start = -1, end = -1;
            int howmany = sscanf(range, "bytes=%d-%d", &start, &end);
            assert(howmany >= 1);
            int reqlen = 0;
            if(end != -1) reqlen = end - start + 1;
            else reqlen = fsize - start;
            if(end == -1) end = fsize - 1;
            
            int used = 0;
            used += sprintf(sendbuf, "%s %d %s\r\n", ver, st_code, st_message);
            used += sprintf(sendbuf + used, "Server: lgy\r\n");
            used += sprintf(sendbuf + used, "Accept-Range: bytes\r\n");
            used += sprintf(sendbuf + used, "Content-Length: %d\r\n", reqlen);
            used += sprintf(sendbuf + used, "Content-Range: bytes %d-%d/%d\r\n", start, end, fsize);
            used += sprintf(sendbuf + used, "Content-Type: text/html\r\n");
            used += sprintf(sendbuf + used, "\r\n");
            fsize += used;
            
            int j;
            for(j = start; j <= end; j++)
                sendbuf[used + j - start] = fbuf[j];
            sendbuf[used + j - start] = '\0';
        }
        else{
            st_code = 200;
            strcpy(st_message, "OK");
            
            int used = 0;
            used += sprintf(sendbuf, "%s %d %s\r\n", ver, st_code, st_message);
            used += sprintf(sendbuf + used, "Server: lgy\r\n");
            used += sprintf(sendbuf + used, "Content-Length: %d\r\n", fsize);
            used += sprintf(sendbuf + used, "Content-Type: text/html\r\n");
            used += sprintf(sendbuf + used, "\r\n");
            fsize += used;
            
            int j;
            for(j = 0; j < fsize; j++)
                sendbuf[used + j] = fbuf[j];
        }
        free(fbuf);
    }
    
    //printf("st_code is: %d\n", st_code);
    if(tcp_sock_write(csock, sendbuf, fsize) < 0){
        perror("SSL_write failed");
        http_busy[thisinfo.which] = 0;
        return NULL;
    }
    tcp_sock_close(csock);
    
    free(sendbuf);
    
    http_busy[thisinfo.which] = 0;
    return NULL;
}

void* server(void *arg){
    u16 port = htons(80);
	  struct tcp_sock *sock = alloc_tcp_sock();

	  struct sock_addr addr;
	  bzero(&addr, sizeof(addr));
	  addr.ip = htonl(0);
    addr.port = port;
    
    if (tcp_sock_bind(sock, &addr) < 0) {
		    perror("Bind failed -- http");
		    exit(1);
	  }
	  
    if(tcp_sock_listen(sock, 3) < 0){
        perror("Listen failed -- http");
        exit(1);
    }
    
    while(1){
        for(int i = 0; i < NUM_THREAD; i++){
            if(!http_busy[i]){
                http_busy[i] = 1;
                struct sockaddr_in caddr;
                struct tcp_sock *csock = tcp_sock_accept(sock);
                info_http[i].which = i;
                info_http[i].csock = csock;
                pthread_create(http_tid + i, NULL, handle_http_req, info_http + i);
            }
        }
    }
}