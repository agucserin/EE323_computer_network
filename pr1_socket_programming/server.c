#define _XOPEN_SOURCE 200
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUF_SIZE 9999993

//#define BUF_SIZE 50
void error_handling(char *message);
void read_childproc();

char caesar(char A, unsigned short nn, unsigned opp){
    if (opp == 0){ //해독
        if (A + nn > 'z'){
            return A + nn - 26;
        }
        else{
            return A + nn;
        }
    }
    else{ //암호화
        if (A - nn < 'a'){
            return 26 + (A - nn);
        }
        else{
            return A - nn;
        }
    }
}

int main(int argc, char *argv[])
{
	int servsock, clntsock;
	struct sockaddr_in seraddr, clnaddr;
	
	pid_t pid;
	struct sigaction act;
	socklen_t addrsz;
	int lenstr;
	char * message = (char *)malloc(sizeof(char) * BUF_SIZE);
	if(argc!=3) {
		error_handling("Wrong input format");
	}

	act.sa_handler=read_childproc;
	sigemptyset(&act.sa_mask);
	act.sa_flags=0;
	servsock=socket(PF_INET, SOCK_STREAM, 0);
	memset(&seraddr, 0, sizeof(seraddr));
	seraddr.sin_family=AF_INET;
	seraddr.sin_addr.s_addr=htonl(INADDR_ANY);
	seraddr.sin_port=htons(atoi(argv[2]));
	
	if(bind(servsock, (struct sockaddr*) &seraddr, sizeof(seraddr))==-1)
		error_handling("bind() error");
	if(listen(servsock, 5)==-1)
		error_handling("listen() error");
	
	while(1)
	{
		addrsz=sizeof(clnaddr);
		clntsock=accept(servsock, (struct sockaddr*)&clnaddr, &addrsz);
		if(clntsock==-1)
			continue;
		pid=fork();
		if(pid==-1)
		{
			close(clntsock);
			continue;
		}
		else if(pid==0)
		{
			close(servsock);
            unsigned short n,op;
            //unsigned int len;
            int first = 0;
			while((lenstr=read(clntsock, message, BUF_SIZE))!=0){
                if (first == 0){
                    first = 1;
                    char strn[2];
                    char strop[2];
                    //char strlen[4];

                    for (int i = 0; i < 2; i++)
                        strop[i] = message[i];
                    for (int i = 2; i < 4; i++)
                        strn[i - 2] = message[i];
                    /*
                    for (int i = 4; i < 8; i++)
                        strlen[i - 4] = message[i];*/

                    op = ntohs(*(unsigned short *)strop);
                    n = ntohs(*(unsigned short *)strn) % 26;
                    //len = ntohl(*(unsigned int *)strlen);

                    for (int i = 8; i < lenstr; i++){
                        char tmp = message[i];
                        int isalpha = 0;
                        if (tmp >= 65 && tmp <= 90){
                            isalpha = 1;
                            tmp = tmp + 32;
                        }
                        if (tmp >= 97 && tmp <= 122){
                            isalpha = 1;
                        }
                        if (isalpha == 1){
                            message[i] = caesar(tmp,n,op);
                        }
                    }
                    
                }
                else{
                    for (int i = 0; i < lenstr; i++){
                        char tmp = message[i];
                        int isalpha = 0;
                        if (tmp >= 65 && tmp <= 90){
                            isalpha = 1;
                            tmp += 32;
                        }
                        if (tmp >= 97 && tmp <= 122){
                            isalpha = 1;
                        }
                        if (isalpha == 1){
                            message[i] = caesar(tmp,n,op);
                        }
                    }
                }
                write(clntsock, message, lenstr);
            }
			close(clntsock);
			return 0;
		}
		else
			close(clntsock);
	}
	close(servsock);
	return 0;
}

void read_childproc()
{
	int status;
	waitpid(-1, &status, WNOHANG);
}
void error_handling(char *message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}