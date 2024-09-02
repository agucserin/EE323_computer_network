#define _XOPEN_SOURCE 200
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>

#define BUF_SIZE 9999993
#define BUF_LINE 100

//#define BUF_SIZE 50
void error_handling(char *message, int sock, int zero);
void* request_handler(void* arg);
void send_data(FILE* fp, char* ct, char* file_name);
char* content_type(char* file);
void send_error(FILE* fp);
void* thread_black();

char * idx(char * str, char a){
	int i = 0;
	while(*(str + i) != '\0'){
		if (*(str + i) == a){
			return str + i;
		}
		i++;
	}
	return NULL;
}

char *connection_hdr = "Connection: close\r\n";
char *proxy_connection_hdr = "Proxy-Connection: close\r\n";
char * uahdr =
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 "
    "Firefox/10.0.3\r\n";

char * b404 = "HTTP/1.0 400 Bad Request\r\n";

typedef struct Node{
	char stri[BUF_LINE];
	struct Node * next;
    struct Node * pre;
}node;

int check = 0;
int end = 0;
node * blin;

int main(int argc, char *argv[])
{
	pthread_t t_id0;
	blin = (node *)malloc(sizeof(node));

	if(argc != 2){
		error_handling("argument error", 0,0);
	}

	if(pthread_create(&t_id0, NULL, thread_black, NULL)!=0)
	{
		puts("pthread_create() error");
		return -1;};
    

	int servsock, clntsock;
	struct sockaddr_in seraddr, clnaddr;
	
	pthread_t t_id;
	socklen_t addrsz;
	servsock=socket(PF_INET, SOCK_STREAM, 0);
	int option = 1;
	setsockopt( servsock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option) );
	memset(&seraddr, 0, sizeof(seraddr));
	seraddr.sin_family=AF_INET;
	seraddr.sin_addr.s_addr=htonl(INADDR_ANY);
	seraddr.sin_port=htons(atoi(argv[1]));
	
	if(bind(servsock, (struct sockaddr*) &seraddr, sizeof(seraddr))==-1)
		error_handling("bind() error", 0,0);
	if(listen(servsock, 5)==-1)
		error_handling("listen() error", 0,0);
	
	while(1){
		addrsz=sizeof(clnaddr);
		clntsock=accept(servsock, (struct sockaddr*)&clnaddr, &addrsz);
		pthread_create(&t_id, NULL, request_handler, &clntsock);
		pthread_detach(t_id);
    }

	close(servsock);
	return 0;
}

void* thread_black() 
{
	char message[BUF_LINE];
	node * tmp1 = blin;
	char * http = "http://";
	while(fgets(message,BUF_LINE,stdin) != NULL){
		check = 1;
		node * tmp2 = (node *)malloc(sizeof(node));
		char * tmp4 = strstr(message,http);
		char * tmp3;
		if (tmp4 != NULL){
			tmp3 = tmp4 + strlen(http);
		}
		else{
			tmp3 = message;
		}
		strcpy(tmp2->stri,tmp3);
		tmp1 -> next = tmp2;
		tmp2 -> pre = tmp1;
		tmp1 = tmp2;
	}
	end = 1;
	return NULL;
}

void * request_handler(void *arg){
	int clntsock=*((int*)arg);

	char reqline[BUF_LINE];
	FILE* clntread;
	
	char method[BUF_LINE];
	char target[BUF_LINE];
	char version[BUF_LINE];

	clntread=fdopen(clntsock, "r");
	fgets(reqline, BUF_LINE,clntread);

	sscanf(reqline, "%s %s %s", method, target, version);

	char * get = "GET";
	if (strncmp(get,method,strlen(get)) != 0){
		write(clntsock, b404, strlen(b404));
		fclose(clntread);
		close(clntsock);
		return NULL;
	}

	char *http10 = "HTTP/1.0";
	if (strncasecmp(http10,version,strlen(http10)) != 0){
		write(clntsock, b404, strlen(b404));
		fclose(clntread);
		close(clntsock);
		return NULL;
	}

	int port = 80;
	char hostname[BUF_LINE];
	char path[BUF_LINE];

	//pasing 시작
	char *http = "http://";
	char *addr = strstr(target, http);
	if (addr == NULL){
		addr = target;
	}
	else{
		addr += strlen(http);
	}

	char *addr2;
	addr2 = idx(addr, ':');
	if (addr2 == NULL){					// hostname/path
		addr2 = idx(addr, '/');
		if(addr2 == NULL){
			strcpy(hostname,addr);
			char * tmp = "/";
			strcpy(path,tmp);
		}
		else{
			*addr2 = '\0';
			strcpy(hostname,addr);
			*addr2 = '/';
			strcpy(path,addr2);
		}
	}
	else{								// hostname:port/path
		*addr2 = '\0';
		strcpy(hostname,addr);
		char *ps = addr2 + 1;
		char *addr2 = idx(ps, '/');
		if(addr2 == NULL){
			port = atoi(ps);
			char * tmp = "/";
			strcpy(path,tmp);
		}
		else{
			*addr2 = '\0';
			port = atoi(ps);
			*addr2 = '/';
			strcpy(path,addr2);
		}
	}

	//HTTP 헤더 생성(request 용)
	char * sl = "GET %s HTTP/1.0\r\n";
	char startline[BUF_LINE];
	char hosthdr[BUF_LINE];
	char *EOL = "\r\n";
	sprintf(startline, sl, path);

	char * message = (char *)malloc(sizeof(char) * BUF_SIZE);
	char * HOST = "Host: ";
	char * UA = "User-Agent:";
	char * CONN = "Connection:";
	char * PRCO = "Proxy-Connection: ";

	node * init = (node *)malloc(sizeof(node));
	node * tmp1 = init;
	char * result;

	int ua = 0;
	int conn = 0;
	int prco = 0;
	int hostt = 0;
	while((result=fgets(message, BUF_LINE,clntread))!=0){
		if(strncasecmp(message,EOL,strlen(EOL)) == 0){
			break;
		}
		else if(strlen(message) == 0){
			break;
		}
		if(strncasecmp(message, HOST, strlen(HOST)) == 0){
			hostt = 1;
			strcpy(hosthdr, message);
			if (strlen(hostname) == 0){
				strcpy(hostname,strtok(message,HOST));
			}
			else{
				char * host2 = strstr(message,HOST) + strlen(HOST);
				if(strncasecmp(hostname,host2,strlen(hostname)) != 0){
					write(clntsock, b404, strlen(b404));
					fclose(clntread);
					close(clntsock);
					return NULL;
				}
			}
		}
		else if(strncasecmp(message, UA, strlen(UA)) != 0 \
		&& strncasecmp(message, CONN, strlen(CONN)) != 0 \
		&& strncasecmp(message, PRCO, strlen(PRCO)) != 0){
			node * tmp2 = (node *)malloc(sizeof(node));
			strcpy(tmp2->stri,message);
			tmp1 -> next = tmp2;
			tmp2 -> pre = tmp1;
			tmp1 = tmp2;
		}
		else{
			if(strncasecmp(message, UA, strlen(UA)) == 0){
				ua = 1;
			}
			else if(strncasecmp(message, CONN, strlen(CONN)) == 0){
				conn = 1;
			}
			else if(strncasecmp(message, PRCO, strlen(PRCO)) == 0){
				prco = 1;
			}
		}
	}

	
	if (hostt == 0){
		//clienterror(clntsock, "400", "Bad Request", "Uri not start with 'http'");
		write(clntsock, b404, strlen(b404));
		fclose(clntread);
		close(clntsock);
		return NULL;
	}

	int bl = 0;
	if (check == 1){
		while(end == 0){

		}
		node * tm = blin;
		while(tm->next != NULL){
			tm = tm->next;
			if (strlen(tm->stri) != 0){
				if (strncasecmp(tm->stri,hostname,strlen(hostname)) == 0){
					bl = 1;
					break;
				}
			}
		}
	}

	int servfd = socket(PF_INET, SOCK_STREAM, 0);
	if (servfd == -1){
		error_handling("socket() error",clntsock,1);
	}

	struct sockaddr_in servaddr;
	struct hostent *servv;

	if (bl == 0){
		servv = gethostbyname(hostname);
		if (servv == NULL){
			write(clntsock, b404, strlen(b404));
			fclose(clntread);
			close(clntsock);
			return NULL;
		}
		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family=AF_INET;
		servaddr.sin_addr.s_addr=inet_addr(inet_ntoa(*(struct in_addr*)servv -> h_addr_list[0]));
		servaddr.sin_port=htons(port);

		if(connect(servfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1){
			error_handling("connect() error!",clntsock,1);
		}

		//printf("start : %s",startline);
		//printf("hosthdr : %s",hosthdr);
		//printf("%s\n",inet_ntoa(*(struct in_addr*)servv -> h_addr_list[0]));

		write(servfd, startline, strlen(startline));
		write(servfd, hosthdr, strlen(hosthdr));
		if (conn == 1) write(servfd, connection_hdr, strlen(connection_hdr));
		if (prco == 1) write(servfd, proxy_connection_hdr, strlen(proxy_connection_hdr));
		if (ua == 1) write(servfd, uahdr, strlen(uahdr));
		node * tmpp = init;
		while(tmpp->next != NULL){
			tmpp = tmpp->next;
			if (strlen(tmpp->stri) != 0){
				write(servfd, tmpp->stri, strlen(tmpp->stri));
			}
			
		}
		write(servfd, EOL, strlen(EOL));
	}
	else{
		char * warn = "www.warning.or.kr";
		servv = gethostbyname(warn);
		char * wast = "GET / HTTP/1.0\r\n";
		char * waho = "Host: warning.or.kr\r\n";

		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family=AF_INET;
		servaddr.sin_addr.s_addr=inet_addr(inet_ntoa(*(struct in_addr*)servv -> h_addr_list[0]));
		servaddr.sin_port=htons(80);

		if(connect(servfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1){
			error_handling("connect() error!",clntsock,1);
		}

		write(servfd, wast, strlen(wast));
		write(servfd, waho, strlen(waho));
		write(servfd, EOL, strlen(EOL));
	}

	int recbyte;
	char tmp[BUF_LINE];
	while((recbyte = read(servfd, &tmp, BUF_LINE)) > 0){
		if(recbyte == -1){
		perror("error");
		}
		if(recbyte == 0){
			break;
		}
		write(clntsock, tmp, recbyte);
	}
	close(servfd);
	fclose(clntread);
	close(clntsock);
	return NULL;
}

void error_handling(char *message,int sock,int zero)
{
	if (zero == 1){
		write(sock, b404, strlen(b404));
		close(sock);
	}
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}