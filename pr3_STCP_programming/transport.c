/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <netinet/in.h>
#include <unistd.h>

enum { CSTATE_ESTABLISHED,
       SYN_SENT,
       LISTEN,
       SYN_RCVD,
       FIN_WAIT_1,
       FIN_WAIT_2,
       CLOSED,
       CLOSE_WAIT,
       LAST_ACK,
       CLOSING
 };    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

uint16_t defa = 3072;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define PRIME 5000011
//basic structure unit of each packet
struct pack{
	STCPHeader * realpacket;
	struct pack * next;
	struct pack * prev; //제일 마지막을 가리킴
};

//int idx = 0;

//insert unit into hashtable
void insert(struct pack * list,STCPHeader * packet){
    if(list->next == NULL){
        struct pack *new = (struct pack *)malloc(sizeof(struct pack));
        list->next = new;
        new->prev = list;
        new->realpacket = packet;
        list->prev = new;
        return;
    }
    struct pack *tmp = list->prev;
    struct pack *new = (struct pack *)malloc(sizeof(struct pack));
    tmp->next = new;
    new->prev = list;
    new->realpacket = packet;
    new->next = NULL;

    list->prev = new;
    /*
    while(1){
        //printf("@@\n");
        if (tmp->next == NULL){
            //printf("**\n");
            struct pack *new = (struct pack *)malloc(sizeof(struct pack));
            //printf("!!\n");
            tmp->next = new;
            new->prev = list;
            new->realpacket = packet;
            new->next = NULL;
            return;
        }
        else{
            tmp = tmp->next;
        }
    }*/
}

void delete(struct pack * list){
    //printf("deleting\n");
    if(list->next == NULL){
        return;
    }
    struct pack * tmp = list->next;
    if ((*tmp).next != NULL){
        struct pack * nex = (*tmp).next;
        list->next = nex;
        nex->prev = list;
        free(tmp->realpacket);
        free(tmp);
    }
    else{
        list->next = NULL;
        list->prev = NULL;
        free(tmp->realpacket);
        free(tmp);
    }
}

void insertA(struct pack * list,STCPHeader * packet){
    if(list->next == NULL){
        struct pack *new = (struct pack *)malloc(sizeof(struct pack));
        list->next = new;
        new->prev = list;
        new->realpacket = packet;
        list->prev = new;
        return;
    }
    struct pack *tmp = list->prev;
    struct pack *new = (struct pack *)malloc(sizeof(struct pack));
    tmp->next = new;
    new->prev = list;
    new->realpacket = packet;
    new->next = NULL;

    list->prev = new;
}

int deleteA(struct pack * list){
    //printf("deleting\n");
    if(list->next == NULL){
        return 1;
    }
    struct pack * tmp = list->next;
    if ((*tmp).next != NULL){
        struct pack * nex = (*tmp).next;
        list->next = nex;
        nex->prev = list;
        free(tmp->realpacket);
        free(tmp);
    }
    else{
        list->next = NULL;
        list->prev = NULL;
        free(tmp->realpacket);
        free(tmp);
    }
    return 0;
}

struct pack * linklist;
struct pack * acklist;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active){
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    linklist = (struct pack *)malloc(sizeof(struct pack));
    acklist = (struct pack *)malloc(sizeof(struct pack));

    STCPHeader *ACK_packet;

    ctx->connection_state = CLOSED;
    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  
       after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  
       you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
    */
    if (is_active == 1){ //active open
        //sending SYN_packet
        STCPHeader *SYN_packet = (STCPHeader *)calloc(1,sizeof(STCPHeader));
        SYN_packet->th_flags = TH_SYN;
        SYN_packet->th_seq = htonl(ctx->initial_sequence_num);
        SYN_packet->th_win = htons(defa);
        stcp_network_send(sd,SYN_packet,sizeof(STCPHeader),NULL);
        //;
        ctx->connection_state = SYN_SENT;

        stcp_wait_for_event(sd,NETWORK_DATA, NULL);

        //receiving SYN/ACK_packet
        free(SYN_packet);
        STCPHeader *packet = (STCPHeader *)calloc(1,sizeof(STCPHeader) + STCP_MSS);
        ssize_t numBytes;
        if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)){
            errno = ECONNREFUSED;
            free(SYN_packet);
            free(ctx);
            return;
        }

        //sending ACK_packet
        ACK_packet = (STCPHeader *)calloc(1,sizeof(STCPHeader));
        ACK_packet->th_flags = TH_ACK;
        ACK_packet->th_seq = htonl(ntohl(packet->th_ack));
        ACK_packet->th_ack = htonl(ntohl(packet->th_seq) + 1);
        ACK_packet->th_win = htons(defa);
        stcp_network_send(sd,ACK_packet,sizeof(STCPHeader),NULL);

        free(packet);
        
    }
    else{ //passive open
        ctx->connection_state = LISTEN;
        stcp_wait_for_event(sd,NETWORK_DATA, NULL);

        //receiving SYN_packet
        STCPHeader *packet = (STCPHeader *)calloc(1,sizeof(STCPHeader) + STCP_MSS);
        ssize_t numBytes;
        if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)){
            errno = ECONNREFUSED;
            free(packet);
            free(ctx);
            return;
        }

        ctx->connection_state = SYN_RCVD;

        //sending SYN/ACK_packet
        STCPHeader *SYNACK_packet = (STCPHeader *)calloc(1,sizeof(STCPHeader));
        SYNACK_packet->th_flags = (TH_ACK|TH_SYN);
        SYNACK_packet->th_seq = htonl(ctx->initial_sequence_num);
        SYNACK_packet->th_ack = htonl(ntohl(packet->th_seq) + 1);
        SYNACK_packet->th_win = htons(defa);
        stcp_network_send(sd,SYNACK_packet,sizeof(STCPHeader),NULL);

        //receiving ACK_packet
        stcp_wait_for_event(sd,NETWORK_DATA, NULL);
        packet = (STCPHeader *)calloc(1,sizeof(STCPHeader) + STCP_MSS);
        if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)){
            errno = ECONNREFUSED;
            free(packet);
            free(ctx);
            return;
        }

        free(packet);
        free(SYNACK_packet);
    }
    ctx->connection_state = CSTATE_ESTABLISHED;
    free(ACK_packet);
    stcp_unblock_application(sd);


    //커넥션 수립이후
    control_loop(sd, ctx);

    /* do any cleanup here *///////////////////////////////////////////////////////////////////////free 하기!
    free(acklist);
    free(linklist);
    free(ctx);
}


/* generate initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx){
    assert(ctx);
    ctx->initial_sequence_num = 1;
}




/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx){
    assert(ctx);

    tcp_seq seqnum = 2;
    tcp_seq acknum = 2; 

    tcp_seq last_ack = 2;
    size_t rwnd = 3072;

    //char * buffer = (char *)malloc(STCP_MSS);
    
    while (!ctx->done){
        unsigned int event;
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA){ 
            //printf("APP\n");
            size_t buff_size;
            if (rwnd != 0){
                if (rwnd < STCP_MSS){
                    buff_size = rwnd;
                }
                else{
                    buff_size = STCP_MSS;
                }
                //memset(buffer,'\0',buff_size); //STCP_MSS 넘는경우 대비 while문 만들기
                //char * buffer = (char *)malloc(buff_size);
                char buffer[buff_size];
                //realloc(buffer,buff_size);
                //printf("size : %ld\n",sizeof(buffer));
                size_t size = stcp_app_recv(sd,buffer,buff_size);
                //printf("from app : %ld %ld %ld\n",strlen(buffer),size,buff_size);
                //printf("buffer : %s\n",buffer);
                

                STCPHeader * ACK_packet = (STCPHeader *)malloc(sizeof(STCPHeader) + size);

                
                //printf("@@@\n");
                ACK_packet->th_flags = TH_ACK;
                ACK_packet->th_seq = htonl(seqnum);
                ACK_packet->th_ack = htonl(acknum);
                ACK_packet->th_win = htons(defa);
                
                insert(linklist,ACK_packet);
                seqnum += size;

                //printf("***\n");

                //char * tmpp = (char *)ACK_packet + sizeof(STCPHeader);
                /*
                for (unsigned int i = 0; i < strlen(buffer) ; i++){
                    tmpp[i] = buffer[i];
                }*/
                //strncpy(tmpp,buffer,strlen(buffer));
                //printf("0x%x\n", &ctx->network_state);

                memcpy((char *)ACK_packet + sizeof(STCPHeader),buffer,size);

                //printf("!!!!\n");
                //printf("%s\n",(char *)ACK_packet + sizeof(STCPHeader));
                //printf("len : %ld\n",strlen(buffer));
                stcp_network_send(sd,ACK_packet,sizeof(STCPHeader) + size,NULL);
                //printf("send : %ld %ld %ld\n",rwnd,size,rwnd-size);
                //printf("###\n");
                
                //printf("@@@@\n");
                //free(ACK_packet);
                //free(buffer);
                rwnd -= size;
            }
        }
        if (event & NETWORK_DATA){
            //printf("NETWORK\n");
            STCPHeader * packet = (STCPHeader *)calloc(1,sizeof(STCPHeader) + STCP_MSS);
            ssize_t numBytes;
            //printf("rec!\n");
            if((numBytes = stcp_network_recv(sd, (void *)packet, sizeof(STCPHeader) + STCP_MSS)) < (ssize_t)sizeof(STCPHeader)){
                //printf("@@\n");
                errno = ECONNREFUSED;
                free(packet);
                free(ctx);
                return;
            }
            //다음번에 보내야 할 것
            //printf("numbytes : %ld\n",numBytes - sizeof(STCPHeader));
            acknum = ntohl(packet->th_seq) + numBytes - sizeof(STCPHeader);
            //seqnum = ntohl(packet->th_ack);

            //printf("%d\n",acknum);
            

            if(packet->th_flags == (TH_FIN|TH_ACK)){
                //printf("close requested from cli\n");
                if (ctx->connection_state == CSTATE_ESTABLISHED){
                    //printf("CLOSE_WAIT\n");
                    ctx->connection_state = CLOSE_WAIT;
                }
                else if (ctx->connection_state == FIN_WAIT_2){
                    //printf("CLOSED\n");
                    ctx->connection_state = CLOSED;
                }
                else if (ctx->connection_state == FIN_WAIT_1){ //simultaneous closing
                    //printf("CLOSED\n");
                    ctx->connection_state = CLOSING;
                }
                //sender에게 확인용 ACK 보내기
                stcp_fin_received(sd);
                STCPHeader *ACK_packet = (STCPHeader *)calloc(1,sizeof(STCPHeader));
                ACK_packet->th_flags = TH_ACK;
                ACK_packet->th_seq = htonl(ntohl(packet->th_ack));
                ACK_packet->th_ack = htonl(ntohl(packet->th_seq) + 1);
                ACK_packet->th_win = htons(defa);
                acknum = ntohl(packet->th_seq) + 1;
                stcp_network_send(sd,ACK_packet,sizeof(STCPHeader),NULL);
                //free(ACK_packet);
            }
            else{
                //sender에게 확인용 ACK 보내기
                if (numBytes - sizeof(STCPHeader) > 0){
                    STCPHeader *ACK_packet = (STCPHeader *)calloc(1,sizeof(STCPHeader));
                    ACK_packet->th_flags = TH_ACK;
                    ACK_packet->th_seq = htonl(ntohl(packet->th_ack));
                    ACK_packet->th_ack = htonl(ntohl(packet->th_seq) + numBytes - sizeof(STCPHeader));
                    ACK_packet->th_win = htons(defa);
                    //printf("%ld\n",ntohl(packet->th_seq) + numBytes - sizeof(STCPHeader));
                    stcp_network_send(sd,ACK_packet,sizeof(STCPHeader),NULL);
                    deleteA(acklist);
                    insertA(acklist,ACK_packet);
                    //free(ACK_packet);
                    //delete_hash(hashtable,ntohl(packet->th_ack));
                }
                else{ //확인용 ACK 받음
                    if (ctx->connection_state == FIN_WAIT_1){
                        //printf("FIN_WAIT_2\n");
                        ctx->connection_state = FIN_WAIT_2;
                    }
                    else if (ctx->connection_state == LAST_ACK){
                        //printf("CLOSED\n");
                        ctx->connection_state = CLOSED;
                    }
                    if (ctx->connection_state == CLOSING){
                        //printf("CLOSED\n");
                        ctx->connection_state = CLOSED;
                    }

                    //delete(linklist);
                }
                rwnd += ntohl(packet->th_ack) - last_ack;

                //printf("recv : %ld %d %d 추가된 rwnd값 : %d\n",rwnd,ntohl(packet->th_ack),last_ack,ntohl(packet->th_ack) - last_ack);

                last_ack = ntohl(packet->th_ack);
                //memset(buffer,'\0',STCP_MSS);;
                //char * buffer = (char *)malloc(STCP_MSS);
                char buffer[STCP_MSS];
                memcpy(buffer,(char *)packet + sizeof(STCPHeader),numBytes - sizeof(STCPHeader));
                //printf("received : %s\n",buffer);
                stcp_app_send(sd, buffer, numBytes - sizeof(STCPHeader));
                
                //free(buffer);
            }
            free(packet);
        }
        if (event & APP_CLOSE_REQUESTED){
            //printf("closing\n");
            if (ctx->connection_state == CSTATE_ESTABLISHED){
                //printf("FIN_WAIT_1\n");
                ctx->connection_state = FIN_WAIT_1;
            }
            else if (ctx->connection_state == CLOSE_WAIT){
                //printf("LAST_ACK\n");
                ctx->connection_state = LAST_ACK;
            }
            //printf("close requested\n");
            STCPHeader *FIN_packet = (STCPHeader *)calloc(1,sizeof(STCPHeader));
            FIN_packet->th_flags = (TH_FIN|TH_ACK);
            FIN_packet->th_seq = htonl(seqnum);
            FIN_packet->th_ack = htonl(acknum);
            FIN_packet->th_win = htons(defa);
            stcp_network_send(sd,FIN_packet,sizeof(STCPHeader),NULL);
            //free(FIN_packet);
        }
        if (ctx->connection_state == CLOSED){
            ctx->done = 1;
        }
        /*
        if (ctx->connection_state == CLOSING){
            STCPHeader *ACK_packet = (STCPHeader *)calloc(1,sizeof(STCPHeader));
            ACK_packet->th_flags = TH_ACK;
            ACK_packet->th_seq = htonl(ntohl(packet->th_ack));
            ACK_packet->th_ack = htonl(ntohl(packet->th_seq) + 1);
            stcp_network_send(sd,ACK_packet,sizeof(STCPHeader),NULL);
        }*/
    }
    
    int c = 0;
    while (c == 0){
        c = deleteA(acklist);
    }
    //free(buffer);
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...){
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



