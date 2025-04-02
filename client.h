#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <pthread.h>
#include <net/if.h>

#define MAX_LEN_DATA 255
#define MAX_LEN_USERNAME 10
#define CODE_SIGN_UP 0x1
#define CODE_POST_TICKET 0x2
#define CODE_LAST_N_TICKET 0x3
#define CODE_SUBSCRIBE 0x4
#define CODE_SEND_FILE 0x5
#define CODE_DL_FILE 0x6
#define CODE_ERROR 0x1F
#define MAX_LEN_MULTICAST_ADDRESS 16
#define MAX_SOCK 4009
#define MAX_LEN_PACKET 512
#define PORT_UDP 9000


#define PORT "4010"
#define ADDRESS "localhost"


struct header {
    uint16_t codereq;
    uint16_t id;
};

struct client_sign_up_request {
    uint16_t codereq_id;
    char username[MAX_LEN_USERNAME+1] ;
};

struct client_request{
    uint16_t codereq_id;
    uint16_t numfil;
    uint16_t nb;
    uint8_t datalen;
    char data[MAX_LEN_DATA+1];
};

struct server_response {
    uint16_t codereq_id;
    uint16_t numfil;
    uint16_t nb;
};
struct server_subscribe{
    uint16_t numfil;
    uint16_t nb;
    char address[MAX_LEN_MULTICAST_ADDRESS];
};
struct ticket {
    uint16_t numfil;
    char origine[MAX_LEN_USERNAME+1];
    char author[MAX_LEN_USERNAME+1];
    uint8_t datalen;
    char message[MAX_LEN_DATA+1];
};

typedef struct Packet_send {
    uint16_t codereq;
    uint16_t sequenceNumber;
    char data[MAX_LEN_PACKET];
} Packet_send;

typedef struct Packet_recv {
    uint16_t codereq;
    uint16_t sequenceNumber;
    char data[MAX_LEN_PACKET];
    struct Packet_recv *next;
} Packet_recv;

void* receive_notifications();
int sign_up(int sock, const char * username,struct header *response);
int post_ticket(int sock,uint16_t numfil,const char* data,struct header *response);
int last_n_tickets(int sock,uint16_t id,int numfil,int nb,struct header *response);
int connexion();
void print_header(struct header header);
void subscribe(int sock,uint16_t numfil,struct header *response);
int add_file(int sock,uint16_t id,uint16_t numfil,const char* data,struct header *response);
int dl_file(int sock,uint16_t id,uint16_t numfil,uint16_t nb,const char* data,struct header *response);
int send_file_to_server(const char* filename,int port);

#endif
