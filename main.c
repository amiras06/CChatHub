#include "client.h"



void help(){
    printf("CHOOSE A NUMBER BETWEEN 1 AND 6 TO EXECUTE THE CORRESPONDING COMMAND \n");
    printf("(1) -> SIGN UP\n");
    printf("(2) -> POST A TICKET\n");
    printf("(3) -> SEE LAST N TICKETS\n");
    printf("(4) -> SUBSCRIBE TO A FIL\n");
    printf("(5) -> SEND A FILE\n");
    printf("(6) -> DOWNLOAD A FILE\n");
}

void handle_signup(int sock_client, struct header* response){
    char username[11];
    printf("Enter your username (10 characters max)\n");
    fgets(username, sizeof(username), stdin);
    int index = strcspn(username, "\n");
    if(index == sizeof(username)-1 && username[index-1] != '\n'){ 
        printf("Error: Username too long.\n");
        return; 
    } else {
        username[index] = '\0'; 
    }
    int r = sign_up(sock_client, username, response);
    if(r == -1){
        printf("Error while signing up\n");
    }
}

void handle_post(int sock_client, struct header* response){
    char data[255];
    char numfil_str[10];
    int numfil;
    printf("Enter the numfil of the ticket\n");
    fgets(numfil_str, 10, stdin);
    printf("Enter the data of the ticket\n");
    fgets(data, 255, stdin);
    sscanf(numfil_str, "%d", &numfil);
    int index = strcspn(data, "\n");
    data[index] = '\0';
    int r = post_ticket(sock_client,(uint16_t) numfil, data, response);
    if(r == -1){
        printf("Error while posting the ticket\n");
    }
}

void handle_last_n_tickets(int sock_client, struct header* response){
    int numfil, nb;
    printf("Enter the numfil of the ticket\n");
    if (scanf("%d", &numfil) != 1 || numfil < 0) {
        printf("Invalid input for numfil\n");
        return;
    }
    printf("Enter the number of tickets you want to display\n");
    if (scanf("%d", &nb) != 1 || nb < 0) {
        printf("Invalid input for nb\n");
        return;
    }
    int r = last_n_tickets(sock_client, 0, numfil, nb, response);
    if(r == -1){
        printf("Error while displaying the tickets\n");
    }
}

void handle_subscribe(int sock_client, struct header* response){
    int numfil;
    printf("Enter the numfil of the ticket\n");
    if (scanf("%d", &numfil) != 1 || numfil < 0) {
        printf("Invalid input for numfil\n");
        return;
    }
    subscribe(sock_client, numfil, response);
}

void handle_add_file(int sock_client, struct header* response){
    int numfil;
    char filename[256];
     printf("Enter the name of the file\n");
    fgets(filename, sizeof(filename), stdin);
    int index = strcspn(filename, "\n");
    if(index == sizeof(filename)-1 && filename[index-1] != '\n'){ 
        printf("Error: filename too long.\n");
        return; 
    } else {
        filename[index] = '\0'; 
    }
    printf("Enter the numfil of the ticket\n");
    if (scanf("%d", &numfil) != 1 || numfil < 0) {
        printf("Invalid input for numfil\n");
        return;
    }
    printf("filename = %s\n", filename);
    add_file(sock_client,0,numfil,filename, response);
}

void handle_dl_file(int sock_client, struct header* response){
    int numfil;
    char filename[256];
    printf("Enter the name of the file\n");
    fgets(filename, sizeof(filename), stdin);
    int index = strcspn(filename, "\n");
    if(index == sizeof(filename)-1 && filename[index-1] != '\n'){ 
        printf("Error: filename too long.\n");
        return; 
    } else {
        filename[index] = '\0'; 
    }
    printf("Enter the numfil of the ticket\n");
    if (scanf("%d", &numfil) != 1 || numfil < 0) {
        printf("Invalid input for numfil\n");
        return;
    }
    dl_file(sock_client,0,numfil,0,filename, response);
}

void handle_input(char* input, int sock_client, struct header* response){
    int req = atoi(input);
    switch(req){
        case 1: handle_signup(sock_client,response);
                print_header(*response);
                break;
        case 2: handle_post(sock_client,response);
                print_header(*response);
                break;
        case 3: handle_last_n_tickets(sock_client,response);
                print_header(*response);
                break;
        case 4: handle_subscribe(sock_client,response);
                print_header(*response);
                break;
        case 5: handle_add_file(sock_client,response);
                print_header(*response);
                break;
        case 6: handle_dl_file(sock_client,response);
                print_header(*response);
                break;
        default:help();
                break;

    }
}

int main(){
    char input[100];
    while(strncmp(input, "c", 1) != 0){
        printf("Type c to connect to the server\n");
        fgets(input, 100, stdin);
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, receive_notifications,NULL)){
    perror("pthread_create");
    exit(1);
    }
    struct header response;
    memset(&response, 0, sizeof(response));
    while(1){
        int sock_client = connexion(); 
        if(sock_client == -1){
            printf("Error while connecting to the server\n");
            return -1;
        }
        printf("Welcome to Megaphone\n");
        printf("press '0' for help\n");
        fgets(input, 100, stdin);
        handle_input(input, sock_client, &response);
        memset(input, 0, 100);
        close(sock_client);
    }
}