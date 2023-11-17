#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
#include <string.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");
 
  char *readbuf = (char *)malloc(1024);
  char *sendbuf = (char *)malloc(1024);
  while(1){
      int rlen = tcp_sock_read(csk, readbuf, 1000);
      if(rlen > 0){
          strncpy(sendbuf, "server echoes: ", 15);
          strncpy(sendbuf + 15, readbuf, rlen);
          sendbuf[15+rlen] = '\0';
          int wlen = tcp_sock_write(csk, sendbuf, strlen(sendbuf));
          if(wlen < 0){
              log(DEBUG, "wlen < 0");
              return NULL;
          }
      }
      
      else if(rlen == 0){
          log(DEBUG, "client closed link");
          break;
      }
      else{
          log(DEBUG, "rlen < 0");
          return NULL;
      }
  }
 
  free(readbuf);
  free(sendbuf);

	sleep(5);

	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}
 
  char data[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  char *readbuf = (char *)malloc(1024);
  char *sendbuf = (char *)malloc(1024);
  
  for(int i = 0; i < 10; i++){
      memcpy(sendbuf, data + i, strlen(data) - i);
      memcpy(sendbuf + strlen(data) - i, data, i+1);
      
      
      int wlen = tcp_sock_write(tsk, sendbuf, strlen(data)+1);
      if(wlen < 0){
          log(DEBUG, "wlen < 0");
          return NULL;
      }
      int rlen = tcp_sock_read(tsk, readbuf, 1000);
      if(rlen > 0){
          readbuf[rlen] = '\0';
          printf("%s\n", readbuf);
      }
      else if(rlen == 0){
          break;
      }
      else{
          log(DEBUG, "rlen < 0");
          return NULL;          
      }
      
      sleep(1);
  }
  
  free(readbuf);
  free(sendbuf);

	tcp_sock_close(tsk);

	return NULL;
}
