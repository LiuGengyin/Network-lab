#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <pthread.h>

#define NUM_THREAD 3

struct info_for_https{
    int which;
    SSL* ssl;
} info_https[NUM_THREAD];

int https_tid[NUM_THREAD];

int https_busy[NUM_THREAD];

struct info_for_http{
    int which;
    int csock;
} info_http[NUM_THREAD];

int http_tid[NUM_THREAD];

int http_busy[NUM_THREAD];

void* handle_http_req(void* arg){
    struct info_for_http thisinfo = *(struct info_for_http*)arg;
    int csock = thisinfo.csock;
    pthread_detach(pthread_self());
    
    char readbuf[1024] = {0};
    int reqsize = recv(csock, readbuf, 1024, 0);
    if(reqsize < 0){
        perror("recv failed");
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
}

void* handle_https_req(void* arg){
    struct info_for_https thisinfo = *(struct info_for_https*)arg;
    SSL* ssl = thisinfo.ssl;
    pthread_detach(pthread_self());
    if(SSL_accept(ssl) == -1){
        perror("SSL_accept failed");
        https_busy[thisinfo.which] = 0;
        return NULL;
    }
    char readbuf[1024] = {0};
    int reqsize = SSL_read(ssl, readbuf, sizeof(readbuf));
    if(reqsize < 0){
        perror("SSL_read failed");
        https_busy[thisinfo.which] = 0;
        return NULL;
    }
    
    char method[10];
    char url[50];
    char ver[10];
    sscanf(readbuf, "%s %s %s", method, url, ver);
    
    if(strcmp(method, "GET") != 0){
        perror("method not supported");
        https_busy[thisinfo.which] = 0;
        return NULL;
    }
    
    //printf("url received is %s\n", url);

    int st_code;
    char st_message[30];
    FILE* file = fopen(url + 1, "r");
    
    char* sendbuf = malloc(8192*30);
    
    if(!file){
        st_code = 404;
        strcpy(st_message, "Not Found");
        int used = 0;
        used += sprintf(sendbuf, "%s %d %s\r\n", ver, st_code, st_message);
        used += sprintf(sendbuf + used, "Server: lgy\r\n");
        used += sprintf(sendbuf + used, "Content-Length: 0\r\n");
        used += sprintf(sendbuf + used, "\r\n");
        sendbuf[used] = '\0';
    }
    else{
        char* fbuf = malloc(8192*30);
        char c = 0;
        int fsize = 0;
        while((c = fgetc(file)) != EOF && fsize < 8192*30){
            fbuf[fsize] = c;
            fsize++;
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
            
            int j;
            for(j = 0; j < fsize; j++)
                sendbuf[used + j] = fbuf[j];
        }
        free(fbuf);
    }
    
    //printf("st_code is: %d\n", st_code);
    
    if(SSL_write(ssl, sendbuf, strlen(sendbuf)) < 0){
        perror("SSL_write failed");
        https_busy[thisinfo.which] = 0;
        return NULL;
    }
    
    free(sendbuf);
    
    https_busy[thisinfo.which] = 0;
    return NULL;
}

void* case_http(void* arg){
    int port = 80;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        perror("Opening socket failed -- http");
        exit(1);
    }
    
    int enable = 1;
	  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		    perror("Setsockopt(SO_REUSEADDR) failed -- http");
		    exit(1);
	  }
    
    struct sockaddr_in addr;
	  bzero(&addr, sizeof(addr));
	  addr.sin_family = AF_INET;
	  addr.sin_addr.s_addr = INADDR_ANY;
	  addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		    perror("Bind failed -- http");
		    exit(1);
	  }
	  listen(sock, 10);
    
    while(1){
        for(int i = 0; i < NUM_THREAD; i++){
            if(!http_busy[i]){
                http_busy[i] = 1;
                struct sockaddr_in caddr;
                socklen_t len;
                int csock = accept(sock, (struct sockaddr*)&caddr, &len);
                if(csock < 0){
                    perror("Accept failed -- http");
                    exit(1);
                }
                info_http[i].csock = csock;
                info_http[i].which = i;
                pthread_create(http_tid + i, NULL, handle_http_req, info_http + i);
            }
        }
    }
    
    return NULL;
}

int main(){
    int port = 443;
    
    // init SSL Library
	  SSL_library_init();
	  OpenSSL_add_all_algorithms();
	  SSL_load_error_strings();
     
    // enable TLS method
	  const SSL_METHOD *method = TLS_server_method();
	  SSL_CTX *ctx = SSL_CTX_new(method);
    
    // load certificate and private key
	  if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		    perror("load cert failed");
		    exit(1);
	  }
	  if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		    perror("load prikey failed");
		    exit(1);
	  }
     
    // init socket, listening to port 443
	  int sock = socket(AF_INET, SOCK_STREAM, 0);
	  if (sock < 0) {
		    perror("Opening socket failed -- https");
		    exit(1);
	  }
	  int enable = 1;
	  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		    perror("Setsockopt(SO_REUSEADDR) failed -- https");
		    exit(1);
	  }

	  struct sockaddr_in addr;
	  bzero(&addr, sizeof(addr));
	  addr.sin_family = AF_INET;
	  addr.sin_addr.s_addr = INADDR_ANY;
	  addr.sin_port = htons(port);
    
    //detect http requests
    int http_case_tid;
    pthread_create(&http_case_tid, NULL, case_http, NULL);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		    perror("Bind failed -- https");
		    exit(1);
	  }
	  listen(sock, 10);
    
    while(1){
        for(int i = 0; i < NUM_THREAD; i++){
            if(!https_busy[i]){
                https_busy[i] = 1;
                struct sockaddr_in caddr;
                socklen_t len;
                int csock = accept(sock, (struct sockaddr*)&caddr, &len);
                if(csock < 0){
                    perror("Accept failed -- https");
                    exit(1);
                }
                info_https[i].ssl = SSL_new(ctx);
                SSL_set_fd(info_https[i].ssl, csock);
                info_https[i].which = i;
                pthread_create(https_tid + i, NULL, handle_https_req, info_https + i);
            }
        }
    }
    
    return 0;
}