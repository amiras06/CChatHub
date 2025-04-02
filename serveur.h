#ifndef SERVEUR_H
#define SERVEUR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/select.h>


#define PORT 4010
#define PORT_UDP 9000
#define ADDRESS "localhost"

#define MAX_LEN_USERNAME 10
#define MAX_LEN_DATA 255
#define CODE_SIGN_UP 0x1
#define CODE_POST_TICKET 0x2
#define CODE_LAST_N_TICKET 0x3
#define CODE_ERROR 0x1F
#define CODE_SUBSCRIBE 0x4
#define CODE_SEND_FILE 0x5
#define CODE_DL_FILE 0x6
#define MULTICAST_BEING_ADDRESS_6 "FF12::"
#define MULTICAST_BEING_ADDRESS_4 "224.0.0."
#define MULTICAST_PORT 4009
#define MAX_LEN_MULTICAST_ADDRESS 16
#define MAX_LEN_PACKET 512
#define NOTIFICATION_TIME_INTERVAL 5

struct client_sign_up_request {
    uint16_t codereq_id;
    char username[MAX_LEN_USERNAME+1] ;
};

struct server_subscribe{
    uint16_t numfil;
    uint16_t nb;
    char address[MAX_LEN_MULTICAST_ADDRESS];
};

struct client_request{
    uint16_t numfil;
    uint16_t nb;
    uint8_t datalen;
    char data[MAX_LEN_DATA+1];
};

struct client {
    char username[MAX_LEN_USERNAME+1];
    uint16_t id;
    int sock;
    struct client *next;
};

struct header {
    uint16_t codereq;
    uint16_t id;
};

struct server_response {
    uint16_t codereq_id;
    uint16_t numfil;
    uint16_t nb;
};

struct post {
    char author[MAX_LEN_USERNAME+1];
    char message[MAX_LEN_DATA+1];
    struct post *next;
};

struct fil {
    char origine[MAX_LEN_USERNAME+1];
    u_int16_t numfil;
    struct post *posts;
    uint16_t nb_posts;
    struct fil *next;
};

struct ticket {
    uint16_t numfil;
    char origine[MAX_LEN_USERNAME+1];
    char author[MAX_LEN_USERNAME+1];
    uint8_t datalen;
    char message[MAX_LEN_DATA+1];
};


struct multi_diffusion{
  u_int16_t port;
  char *address;
  uint16_t numfil;
  struct multi_diffusion *next;
};

typedef struct Packet_recv {
    uint16_t codereq;
    uint16_t sequenceNumber;
    char data[MAX_LEN_PACKET];
    struct Packet_recv *next;
} Packet_recv;

typedef struct Packet_send {
    uint16_t codereq;
    uint16_t sequenceNumber;
    char data[MAX_LEN_PACKET];
} Packet_send;

typedef struct notification_stack {
    uint16_t codereq;
    uint16_t numfil;
    char pseudo_data[32];
    struct notification_stack *next;
} notification_stack;

#endif
