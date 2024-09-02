#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#define BUF_SIZE 9999993

//#define BUF_SIZE 50
void error_handling(char * message);

void error_handling(char * message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

int main(int argc, char *argv[]){
    int sock;
    char * message = (char *)malloc(sizeof(char) * BUF_SIZE);
    int lenstr, totalrecv, recvbyte;
    struct sockaddr_in servaddr;
    unsigned short n,op;
    unsigned int len;

    if (argc != 9){
        error_handling("socket() error");
    }
    char * ipadr = "-h";
    char * port = "-p";
    char * cipher = "-o";
    char * howmany = "-s";

    char strip[20];
    char strport[10];
    char strcipher[3];
    char strhow[10];

    int checklis[4] = {0,};
    for (int i = 0; i < 4; i++){
        int ii = i * 2 + 1;
        if (strcmp(argv[ii],ipadr) == 0){
            if (checklis[0] != 0){
                error_handling("Wrong input format");
            }
            strcpy(strip,argv[ii+1]);
            checklis[0] = 1;
        }
        else if (strcmp(argv[ii],port) == 0){
            if (checklis[1] != 0){
                error_handling("Wrong input format");
            }
            strcpy(strport,argv[ii+1]);
            checklis[1] = 1;
        }
        else if (strcmp(argv[ii],cipher) == 0){
            if (checklis[2] != 0){
                error_handling("Wrong input format");
            }
            strcpy(strcipher,argv[ii+1]);
            checklis[2] = 1;
        }
        else if (strcmp(argv[ii],howmany) == 0){
            if (checklis[3] != 0){
                error_handling("Wrong input format");
            }
            strcpy(strhow,argv[ii+1]);
            checklis[3] = 1;
        }
        else{
            error_handling("Wrong input format");
        }
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1){
        error_handling("socket() error");
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family=AF_INET;
    servaddr.sin_addr.s_addr=inet_addr(strip);
    servaddr.sin_port=htons(atoi(strport));

    if ((atoi(strcipher) != 1) && (atoi(strcipher) != 0)){
        error_handling("Wrong input format");
    }

    char * zero = "0";
    if ((atoi(strhow) == 0) && (strcmp(strhow,zero) != 0)){
        error_handling("Wrong input format");
    }

    op = htons(atoi(strcipher));
    n = htons(atoi(strhow));

    unsigned short * pop;
    unsigned short * pn;

    pop = &op;
    pn = &n;

    char * cpop = (char*)pop;
    char * cpn =  (char*)pn;
    for (int i = 0; i < 2; i++){
        message[i] = *(cpop + i);
    }
    for (int i = 0; i < 2; i++){
        message[i + 2] = *(cpn + i);
    }

    if(connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1){
        error_handling("connect() error!");
    }

    int check = 0;
    char * result;
    while((result = fgets(message + 8, BUF_SIZE, stdin)) != NULL){

        if(message[strlen(message + 8) - 1 + 8] == '\0'){
            if(strlen(message + 8) == 0){ 
                break;
            }
            check = 1;
        }

        len = htonl((unsigned int)strlen(message + 8) + 8);

        unsigned int * plen = &len;
        char * cplen = (char *)plen;
        for (int i = 0; i < 4; i++){
            message[i + 4] = *(cplen + i);
        }

        lenstr = write(sock, message, strlen(message + 8) + 8);

        totalrecv = 0;
        while(totalrecv < lenstr){
            recvbyte = read(sock, &message[totalrecv], BUF_SIZE);
            if(recvbyte == -1){
                //error_handling("read() error!");
                perror("error");
            }
            if(recvbyte == 0){
                break;
            }
            totalrecv += recvbyte;
        }

        char nlis[2];
        char oplis[2];
        char lenlis[4];

        for (int i = 0; i < 2; i++)
            oplis[i] = message[i];
        for (int i = 2; i < 4; i++)
            nlis[i - 2] = message[i];
        for (int i = 4; i < 8; i++)
            lenlis[i - 4] = message[i];

        op = ntohs(*(unsigned short *)oplis);
        n = ntohs(*(unsigned short *)nlis);
        len = ntohl(*(unsigned int *)lenlis);

        printf("%s",message+8);

        if (check == 1){
            break;
        }
    }

    close(sock);
    free(message);
    return 0;
}