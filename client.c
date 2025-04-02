#include "client.h"

uint16_t id_client = 0;
fd_set followed;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int followed_sockets[MAX_SOCK]={0};

struct header decode_header(uint16_t num){ // Fonction qui decode un uint16_t en un header
    struct header header;
    memset(&header, 0, sizeof(struct header));
    uint16_t first_five_bits = num & 0x1F; // extract first 5 bits
    uint16_t rest_bits = (num >> 5) & 0x7FF; // extract rest of the bits
    header.codereq = first_five_bits;
    header.id = rest_bits;
    return header;
}
uint16_t encode_header(struct header header){ // Fonction qui encode le header en un uint16_t
    uint16_t num = (header.id  << 5) | header.codereq;
    return num;
}

void print_header(struct header header){
  printf("HEADER ==> %d   |  %d\n", header.codereq, header.id);
}

void print_ticket(struct ticket ticket){
  printf("NUMFIL ==> %d \n", ntohs(ticket.numfil));
  printf("ORIGINE ==> %s \n", ticket.origine);
  printf("AUTHOR ==> %s \n", ticket.author);
  printf("DATALEN ==> %d \n", (ticket.datalen));
  printf("MESSAGE ==> %s \n", ticket.message);
}

int get_server_reponse(int sock,struct header *response,struct server_response* rp_msg){ // Fonction qui permet de récupérer la réponse du serveur
  char buf_response[sizeof(struct server_response)];
  memset(&buf_response,0,sizeof(struct server_response));
  int r = recv(sock, &buf_response, sizeof(struct server_response), 0); // Récupération de la réponse du serveur
  if (r == -1){
    perror("recv server response");
    return -1;
  }
  memset(rp_msg,0,sizeof(struct server_response));
  memcpy(rp_msg, buf_response, sizeof(struct server_response)); // Copie de la réponse du serveur dans la structure rp_msg
  uint16_t codereq_id = ntohs(rp_msg->codereq_id); // Conversion de la réponse du serveur en un format hôte
  *response = decode_header(codereq_id); // Décodage de la réponse du serveur
  if(response -> codereq == CODE_ERROR){ // Si la réponse du serveur est une erreur
    perror("server response");
    return -1;
  }
  return 0;
}

int sign_up(int sock, const char * username, struct header *response) {
  struct client_sign_up_request msg;   // Structure pour stocker la demande d'inscription du client
  struct header header = {CODE_SIGN_UP, 0x0};   // Structure d'en-tête contenant le code de demande d'inscription
  memset(&msg, 0, sizeof(struct client_sign_up_request));   // Initialisation de la structure msg avec des zéros
  
  // Conversion de l'en-tête en un format réseau et assignation à msg.codereq_id
  msg.codereq_id = htons(encode_header(header));

  memset(&msg.username, '\0', MAX_LEN_USERNAME * sizeof(char) + 1);   // Initialisation de msg.username avec des caractères nuls
  strncpy(msg.username, username, strlen(username));   // Copie du nom d'utilisateur dans msg.username
  
  // Ajout de caractères '#' supplémentaires à msg.username pour remplir jusqu'à 10 caractères
  memset(msg.username + strlen(msg.username), '#', 10 - strlen(msg.username)); 
  
  char buffer[sizeof(struct client_sign_up_request)];   // Tampon pour stocker le message
  memset(&buffer, 0, sizeof(struct client_sign_up_request));   // Initialisation du tampon avec des zéros
  memcpy(buffer, &msg, sizeof(struct client_sign_up_request));   // Copie du contenu de msg dans le tampon

  int s = send(sock, buffer, sizeof(struct client_sign_up_request), 0);   // Envoi du message sur la socket
  if (s == -1) {
    perror("send sign_up request");
    close(sock);
    return -1;
  }
  struct server_response* rp_msg = malloc(sizeof(struct server_response));   // Allocation de mémoire pour stocker la réponse du serveur
  if (get_server_reponse(sock, response, rp_msg) == -1) {   // Appel à une fonction pour obtenir la réponse du serveur
    close(sock);
    return -1;
  }
  id_client = response->id;   // Stockage de l'ID client à partir de la réponse
  close(sock);   // Fermeture de la socket
  return 0;
}


int post_ticket(int sock,uint16_t numfil,const char* data,struct header *response){ // Fonction qui permet de poster un ticket
  if(id_client == 0){ // Si l'ID client est nul (pas encore inscrit)
    printf("YOU MUST SIGN UP FIRST\n");
    close(sock);
    return -1;
  }
  struct client_request msg; // Structure pour stocker la demande de post de ticket du client
  struct header header = {CODE_POST_TICKET, id_client}; // Structure d'en-tête contenant le code de demande de post de ticket et l'ID client
  memset(&msg, 0, sizeof(struct client_request));
  msg.codereq_id = htons(encode_header(header)); // Remplissage de la stucture
  msg.numfil = htons(numfil);
  msg.nb = htons(0x0);
  msg.datalen = htons(strlen(data));
  memset(&msg.data, '\0', MAX_LEN_DATA * sizeof(char)); 
  strncpy(msg.data, data, strlen(data));
  char buffer[sizeof(struct client_request)];
  memset(&buffer, 0, sizeof(struct client_request));
  memcpy(buffer, &msg, sizeof(struct client_request));
  int s = send(sock,buffer,sizeof(struct client_request),0); // Envoi de la demande de post de ticket au serveur
  if (s == -1){
    perror("send post_ticket request");
    close(sock);
    return -1;
  }
  struct server_response* rp_msg = malloc(sizeof(struct server_response)); 
  if(get_server_reponse(sock,response,rp_msg) == -1){ // Appel à une fonction pour obtenir la réponse du serveur
    close(sock);
    return -1;
  }
  close(sock);
  return 0;
}

int last_n_tickets(int sock,uint16_t id,int numfil,int nb,struct header *response){ // Fonction qui permet d'obtenir les n derniers tickets
  if(id_client == -1){ // Si l'ID client est nul (pas encore inscrit)
    printf("YOU MUST SIGN UP FIRST\n");
    close(sock);
    return -1;
  }
  struct client_request msg;
  struct header header = {CODE_LAST_N_TICKET, id_client}; // Structure d'en-tête contenant le code de demande de post de ticket et l'ID client
  memset(&msg, 0, sizeof(struct client_request)); 
  msg.codereq_id = htons(encode_header(header)); // Remplissage de la stucture
  msg.numfil = htons(numfil);
  msg.nb = htons(nb);
  msg.datalen = htons(0);
  memset(&msg.data, '\0', MAX_LEN_DATA * sizeof(char)); 
  char buffer[sizeof(struct client_request)]; // Tampon pour stocker le message
  memset(&buffer, 0, sizeof(struct client_request)); // Initialisation du tampon avec des zéros
  memcpy(buffer, &msg, sizeof(struct client_request)); // Copie du contenu de msg dans le tampon
  int s = send(sock,buffer,sizeof(struct client_request),0); // Envoi de la demande de post de ticket au serveur
  if (s == -1){
    perror("send request last n tickets");
    return -1;
  }
  struct server_response* rp_msg = malloc(sizeof(struct server_response));
  if(get_server_reponse(sock,response,rp_msg) == -1){ // Appel à une fonction pour obtenir la réponse du serveur
    close(sock);
    return -1;
  }
  //recevoir les msgs
  uint16_t nb_msg = ntohs(rp_msg->nb); // Nombre de messages à recevoir
  while(nb_msg > 0){ // Tant qu'il reste des messages à recevoir
    struct ticket ticket; // Structure pour stocker le ticket
    memset(ticket.author, '\0', MAX_LEN_USERNAME * sizeof(char)  + 1);
    memset(ticket.origine, '\0', MAX_LEN_USERNAME * sizeof(char)  + 1);
    memset(ticket.message, '\0', MAX_LEN_DATA * sizeof(char)  + 1);
    char buffer[sizeof(struct ticket)];
    memset(&buffer, 0, sizeof(struct ticket));
    int r = recv(sock, &buffer, sizeof(struct ticket), 0); // Réception du ticket
    if (r == -1){
      perror("recv ticket");
      return -1;
    }
    memcpy(&ticket, buffer, sizeof(struct ticket));
    print_ticket(ticket); // Affichage du ticket
    nb_msg--;
    printf("\n");
  }
  close(sock);
  return 0;
}

// abonnement à une adresse multicast
void sub_to_adresse(struct server_subscribe response){
  //create connection to udp server
  int * sock= malloc(sizeof(int)); 
  *sock= socket(AF_INET6, SOCK_DGRAM, 0);
  if (*sock == -1){
    perror("socket");
    return;
  }
  // initialisation de l'adresse de reception
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(response.nb);
  addr.sin6_addr = in6addr_any;
  // laison de l'adresse à le socket
  int r = bind(*sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_in6));
  if (r == -1){
    perror("bind");
    return;
  }
  // initialisation de l’adresse IP d’abonnement et l’interface locale
  struct ipv6_mreq group;
  memset(&group, 0, sizeof(struct ipv6_mreq));
  inet_pton(AF_INET6, response.address, &group.ipv6mr_multiaddr.s6_addr);
  group.ipv6mr_interface = if_nametoindex("eth0");
  // abonnement à l’adresse de multicast
  if (setsockopt(*sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &group, sizeof(struct ipv6_mreq)) == -1){
    perror("setsockopt");
    return;
  }
  int index= 0;
  // ajoute le socket à la liste des sockets suivies
  while(index < MAX_SOCK){
    if (followed_sockets[index] == 0){
      FD_SET(*sock, &followed);
      followed_sockets[index] = *sock;
      break;
    }
    index++;
  }
}

// Le client envoie une requete d'abonnement à un fil de discussion au serveur
void subscribe(int sock,uint16_t numfil,struct header *response){
  struct client_request msg;
  struct header header = {CODE_SUBSCRIBE, id_client};
  uint16_t buf[1];
  uint16_t data[10];
  memset(&msg, 0, sizeof(10 * sizeof(uint16_t)));
  memset(&msg, 0, sizeof(struct client_request));
  msg.codereq_id = htons(encode_header(header));
  msg.numfil = htons(numfil);
  msg.nb = htons(0x0);
  msg.datalen = htons(0);
  memset(&msg.data, '\0', MAX_LEN_DATA * sizeof(char)); 
  char buffer[sizeof(struct client_request)];
  memset(&buffer, 0, sizeof(struct client_request));
  memcpy(buffer, &msg, sizeof(struct client_request));
  int s = send(sock,buffer,sizeof(struct client_request),0);
  if (s == -1){
    perror("send post_ticket request");
    close(sock);
    return;
  }
  memset(&buf, 0,1* sizeof(uint16_t));
  int r = recv(sock, &buf, 1 *  sizeof( uint16_t), 0);
  if (r == -1){
    perror("recv sign_up response");
    return;
  } 
  uint16_t codereq_id = ntohs(buf[0]);
  *response = decode_header(codereq_id);
  if (response->codereq == CODE_SUBSCRIBE){
    // recevoir la reponse du serveur avec l'adresse et le port
    int r_data = recv(sock, data, sizeof(struct server_subscribe), 0);
    if(r_data == -1){
      perror("recv subscribe response");
      close(sock);
      return;
    }
    struct server_subscribe msg ={0};
    memcpy(&msg, data, sizeof(struct server_subscribe));
    msg.nb = ntohs(msg.nb);
    sub_to_adresse(msg);
    printf("subscribe success\n");
    close(sock);
  }
  else{
    printf("subscribe failed\n");
    close(sock);
  }
}

int send_file_to_server(const char* filename,int port){ // Envoi d'un fichier au serveur
  FILE * file = fopen(filename, "rb"); // Ouverture du fichier
  if (file == NULL) {
      perror("Impossible d'ouvrir le fichier");
      return -1;
  }

  struct sockaddr_in6 serverAddr;
  socklen_t addr_size;

  int sock = socket(AF_INET6, SOCK_DGRAM, 0); // Création de la socket
  if (sock < 0) {
    perror("Erreur lors de la création de la socket");
    return -1;
  }
    // Configuration de l'adresse du serveur
    memset(&serverAddr, 0, sizeof(serverAddr)); 
    serverAddr.sin6_family = AF_INET6;
    serverAddr.sin6_port = htons(port);
    inet_pton(AF_INET6, ADDRESS, &serverAddr.sin6_addr);
    addr_size = sizeof(serverAddr);

    // Lecture et envoi du fichier
    char buffer[MAX_LEN_PACKET];
    size_t bytesRead;
    int sequenceNumber = 0;

    while ((bytesRead = fread(buffer, sizeof(char), MAX_LEN_PACKET, file)) > 0){ // Lecture du fichier
        usleep(300); // Attente de 300 microsecondes afin de permettre au serveur de recevoir les paquets
        printf("Envoi du paquet %d\n", sequenceNumber);
        Packet_send packet; // Création du paquet
        packet.sequenceNumber = htons(sequenceNumber); // Numéro de séquence
        memset(packet.data,'\0',sizeof(packet.data));
        memcpy(packet.data, buffer, bytesRead); // Données
        ssize_t bytesSent = sendto(sock, (void *)&packet, sizeof(Packet_send), 0,(struct sockaddr *)&serverAddr, addr_size); // Envoi du paquet
        if (bytesSent < 0) {
            perror("Erreur lors de l'envoi du fichier");
            return -1;
        }
        sequenceNumber++;
    }
    fclose(file);
    close(sock);
    printf("Le fichier a été envoyé avec succès.\n");
    return 0;
}

int add_file(int sock,uint16_t id,uint16_t numfil,const char* data,struct header *response){ // Fonction qui permet d'ajouter un fichier
  if(id_client == -1){ // Si l'utilisateur n'est pas inscrit
    printf("YOU MUST SIGN UP FIRST\n");
    close(sock);
    return -1;
  }
  struct client_request msg;
  struct header header = {CODE_SEND_FILE, id_client}; // On crée le header
  memset(&msg, 0, sizeof(struct client_request)); // On initialise le message
  msg.codereq_id = htons(encode_header(header));
  msg.numfil = htons(numfil);
  msg.nb = htons(0x0);
  msg.datalen = htons(strlen(data));
  memset(&msg.data, '\0', MAX_LEN_DATA * sizeof(char)); 
  strncpy(msg.data, data, strlen(data));
  char buffer[sizeof(struct client_request)]; // On crée le buffer
  memset(&buffer, 0, sizeof(struct client_request)); // On initialise le buffer
  memcpy(buffer, &msg, sizeof(struct client_request)); // On copie le message dans le buffer
  int s = send(sock,buffer,sizeof(struct client_request),0); // On envoie le message
  if (s == -1){
    perror("send post_ticket request");
    close(sock);
    return -1;
  }
  struct server_response* rp_msg = malloc(sizeof(struct server_response));
  if(get_server_reponse(sock,response,rp_msg) == -1){ // On récupère la réponse du serveur
    close(sock);
    return -1;
  }
  close(sock);
  if(send_file_to_server(data, ntohs(rp_msg->nb)) == -1){// On envoie le fichier au serveur
    close(sock);
    return -1;
  }
  close(sock);
  return 0;
}

void printPackets(Packet_recv *head) { // Fonction qui permet d'afficher les paquets 
    Packet_recv *current = head;
    while (current != NULL) {
        printf("Sequence Number: %d\n", current->sequenceNumber);
        current = current->next;
    }
}

void insertPacket(Packet_recv **head, Packet_recv *packet) { // Fonction qui permet d'insérer un paquet dans la liste tout en la triant l'ordre
    Packet_recv *current = *head;
    Packet_recv *prev = NULL;
    while (current != NULL && current->sequenceNumber < packet->sequenceNumber) {
        prev = current;
        current = current->next;
    }
    if (prev == NULL) {
        packet->next = *head;
        *head = packet;
    } else {
        prev->next = packet;
        packet->next = current;
    }
}
void freePackets(Packet_recv *head) { // Fonction qui permet de libérer la mémoire allouée pour les paquets
    Packet_recv *current = head;
    Packet_recv *next;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
}

//Fonction qui gére la réception d'un fichier
int receive_file(const char* filename, int port){
  FILE *file;
  char file_path[strlen(filename) + 14];
  memset(file_path, 0, sizeof(file_path));
  sprintf(file_path, "files_downloaded/%s", filename); // Créer le chemin du fichier
  int sock = socket(AF_INET6, SOCK_DGRAM, 0); // Créer le socket UDP
  struct sockaddr_in6 serv_addr, client_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin6_family = AF_INET6;
  serv_addr.sin6_port = htons(port);
  serv_addr.sin6_addr = in6addr_any;
  if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) { // Bind le socket
    perror("bind");
    exit(1);
  }
  socklen_t cli_addr_size = sizeof(client_addr);
   file = fopen(file_path, "wb");  // Ouvrir le fichier en mode écriture binaire
    if (file == NULL) {
        perror("Impossible d'ouvrir le fichier");
        return 1;
    }

    Packet_recv *packetsHead = NULL;
    int numPacketsReceived = 0;

    Packet_recv receivedPacket; // Paquet reçu
    ssize_t bytesRead;          // Nombre d'octets lus

    fd_set readSet;             // Ensemble de descripteurs de fichiers en lecture
    struct timeval timeout;     // Temps d'attente pour le select
    while(1){
        FD_ZERO(&readSet);      // Initialiser l'ensemble
        FD_SET(sock, &readSet); // Ajouter le socket au readSet
        timeout.tv_sec = 10;    // Temps d'attente de 10 secondes
        timeout.tv_usec = 0;

        int ready = select(sock+1, &readSet, NULL, NULL, &timeout);   // Attendre jusqu'à ce que le socket soit prêt
        if(ready < 0){
            perror("select");
            exit(1);
        }
        else if(ready == 0){
            printf("timeout\n");
                break;
        }
        else{
            if(FD_ISSET(sock,&readSet)){    // Si le socket est prêt
                bytesRead = recvfrom(sock, (void *)&receivedPacket, sizeof(Packet_recv), 0,(struct sockaddr *)&client_addr, &cli_addr_size);
                if(bytesRead < 0){
                    perror("recvfrom");
                    return 1;
                }
                Packet_recv *newPacket = (Packet_recv *)malloc(sizeof(Packet_recv)); // Créer un nouveau paquet
                newPacket->sequenceNumber = ntohs(receivedPacket.sequenceNumber);     // Copier les données du paquet reçu dans le nouveau paquet
                memcpy(newPacket->data, receivedPacket.data, strlen(receivedPacket.data));
                newPacket->next = NULL;
                printf("new packet created : %d with size : %ld\n", newPacket->sequenceNumber,strlen(newPacket->data));
                insertPacket(&packetsHead, newPacket);    // Insérer le nouveau paquet dans la liste
                numPacketsReceived++;                     // Incrémenter le nombre de paquets reçus
            }
        }
    }
    Packet_recv *currentPacket = packetsHead; // Pointeur vers le paquet courant
    printPackets(packetsHead);                // Afficher les paquets reçus
    while (currentPacket != NULL) {           // Écrire les données des paquets dans le fichier
        printf("Écriture du paquet %d de taille : %ld\n", currentPacket->sequenceNumber, strlen(currentPacket->data));
        int written = fwrite(currentPacket->data, sizeof(char), strlen(currentPacket->data), file);
        if(written < 0){
            perror("fwrite");
            return 1;
        }
        currentPacket = currentPacket->next;
    }
    freePackets(packetsHead);
    fclose(file);
    close(sock);
    return 0;
}

int generate_port(){ // Générer un port pour le client
  return PORT_UDP+id_client;
}

// Le client envoie une requête au serveur pour télécharger un fichier
int dl_file(int sock,uint16_t id,uint16_t numfil,uint16_t nb,const char* data,struct header *response){
  nb = generate_port();
  struct client_request msg;
  struct header header = {CODE_DL_FILE, id_client};
  memset(&msg, 0, sizeof(struct client_request));
  msg.codereq_id = htons(encode_header(header));
  msg.numfil = htons(numfil);
  msg.nb = htons(nb);
  msg.datalen = htons(strlen(data));
  memset(&msg.data, '\0', MAX_LEN_DATA * sizeof(char)); 
  strncpy(msg.data, data, strlen(data));
  char buffer[sizeof(struct client_request)];
  memset(&buffer, 0, sizeof(struct client_request));
  memcpy(buffer, &msg, sizeof(struct client_request));
  int s = send(sock,buffer,sizeof(struct client_request),0);
  if (s == -1){
    perror("send dl_file request");
    close(sock);
    return -1;
  }
  struct server_response* rp_msg = malloc(sizeof(struct server_response));
  if(get_server_reponse(sock,response,rp_msg)!=0){
    close(sock);
    return -1;
  }
  close(sock);
  // appelle à la fonction de réception de fichier
  if(receive_file(data, nb) != 0){
    perror("recv_file");
    close(sock);
    return -1;
  }
  return 0;
}

int connexion(){ //retourne le socket de connexion
  int sock;
  struct addrinfo hints,*p,*r;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if ((getaddrinfo(ADDRESS, PORT, &hints, &r)) != 0 || r == NULL)
    return -1;

  p = r;
  while( p != NULL ) {
    if((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) > 0) {
      if(connect(sock, p->ai_addr, p->ai_addrlen) == 0)
        break;
      close(sock);
    }
    p = p->ai_next;
  }
  // le client est maintenant connecté, la conversation avec le serveur peut commencer...
  freeaddrinfo(r);
  return sock;
}

// recevoir les notifications envoyé par le diffuseur
void* receive_notifications(){
  int nb_notifications = 0;
  fd_set tmp_followed;
  while(1){
    struct timeval timeout;
    timeout.tv_sec = 5;       // Temps d'attente de 5 secondes
    timeout.tv_usec = 0;
    pthread_mutex_lock(&lock);
    tmp_followed = followed;
    nb_notifications=  select(MAX_SOCK+1, &tmp_followed, NULL , NULL,  &timeout); // bloque jusqu'à ce qu'une notification soit reçue ou le timeout atteint
    if (nb_notifications == -1){
      perror("select");
      return NULL;
    }
    if (nb_notifications != 0){
      for (int i = 0; i < MAX_SOCK; i++){         // Parcours des sockets suivis
        if (FD_ISSET(followed_sockets[i], &tmp_followed)){  
          printf("received notification\n");
          char buffer[32];
          memset(&buffer, 0, 1024);
          int r = recv(followed_sockets[i], buffer, 32, 0);
          if (r == -1){
            perror("recvfrom");
            return NULL;
          }
          printf("received : pseudo %s\n",buffer+2*sizeof(uint16_t));
          FD_SET(followed_sockets[i], &followed); // Rajout du socket à la liste des sockets suivis
        }
      }
    }
    pthread_mutex_unlock(&lock);
  }
}
