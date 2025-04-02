#include "serveur.h"

struct client *clients = NULL;
struct fil *fils = NULL;
int nb_clients=0;
int nb_fil=0;
pthread_mutex_t clients_list_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t fil_list_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t notifications_list_lock = PTHREAD_MUTEX_INITIALIZER;
struct multi_diffusion *diffusion_addresses=NULL;
struct notification_stack *notifications=NULL;


struct fil* copy_fil(struct fil* original) {
    if (original == NULL) {
        pthread_mutex_unlock(&fil_list_lock);
        return NULL; // Si la structure originale est NULL, la copie sera NULL
    }
    struct fil* copy = (struct fil*)malloc(sizeof(struct fil)); // Allouer l'espace mémoire pour la copie
    strcpy(copy->origine, original->origine); // Copier la chaîne de caractères origine de la structure originale à la copie
    copy->numfil = original->numfil; // Copier l'entier numfil de la structure originale à la copie
    copy->nb_posts = original->nb_posts; // Copier l'entier nb_posts de la structure originale à la copie
    if (original->posts != NULL) {
        copy->posts = (struct post*)malloc(original->nb_posts * sizeof(struct post)); // Allouer l'espace mémoire pour les posts de la copie
        memcpy(copy->posts, original->posts, original->nb_posts * sizeof(struct post)); // Copier les données des posts de la structure originale à la copie
    } else {
        copy->posts = NULL; // Si la structure originale ne contient pas de posts, la copie aura un pointeur NULL
    }
    if (original->next != NULL) {
        copy->next = copy_fil(original->next); // Appeler récursivement la fonction pour copier la structure suivante
    } else {
        copy->next = NULL; // Si la structure originale ne contient pas de structure suivante, la copie aura un pointeur NULL
    }
    return copy; // Retourner la copie
}

uint16_t char_to_uint16(const char *str){ // Fonction qui convertit une chaîne de caractères en entier 16 bits
  uint16_t num = 0;
  num = (uint16_t)  atoi(str);
  return num; 
}

int create_server(int port ,const char *address) { // Fonction qui crée un serveur
  int no = 0;
  int sock = socket(PF_INET6, SOCK_STREAM, 0); // Créer une socket TCP
  if(sock < 0){
    perror("creation socket");
    return -1;
  }
  // Définir l'adresse du serveur
  struct sockaddr_in6 address_sock;
  memset(&address_sock, 0, sizeof(address_sock));
  address_sock.sin6_family = AF_INET6;
  address_sock.sin6_port = htons(port);
  address_sock.sin6_addr = in6addr_any;
  int set_sock_option = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)); // Permettre à la socket d'accepter les connexions IPv4 et IPv6
  //allow multiple connections on the same port
  int yes = 1;
  set_sock_option = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)); // Permettre à la socket d'accepter plusieurs connexions sur le même port
  if(set_sock_option < 0) fprintf(stderr, "Failure setsockopt() : (%d)\n", errno);

  int bind_r = bind(sock, (struct sockaddr *) &address_sock, sizeof(address_sock)); // Lier la socket à l'adresse
  if(bind_r < 0){
    perror("bind");
    return -1;
  }
  int listen_r = listen(sock,0); // Mettre la socket en écoute
  if(listen_r < 0){
    perror("listen");
    return -1;
  }
  return sock;
}

int init_clients(char *filepath, struct client ** clients) { // Fonction qui initialise la liste des clients
  int length = 0;
  FILE *fic = fopen(filepath, "r"); // Ouvrir le fichier en lecture seule
  if (fic == NULL) {
    perror("fopen");
    return -1;
  }
  char buf[100];
  memset(buf, 0, sizeof(buf));
  struct client * head = *clients;
  while (fgets(buf, sizeof(buf), fic)) { // Lire le fichier ligne par ligne
    length++;
    nb_clients++;
    if (buf[strlen(buf) - 1] == '\n')
      buf[strlen(buf) - 1] = 0;
    char *space = strchr(buf, ' ');
    *space = 0;
    struct client *new_client = malloc(sizeof(struct client));
    strcpy(new_client->username, buf);
    char *id = space + 1;
    new_client->id = char_to_uint16(id);
    new_client->next = head;
    head = new_client;
  }
  fclose(fic);
  *clients = head;
  return length;
}

/*
 * Affiche la liste des tuteurs
 * @param[in]	tutors  	La tête de la liste des tuteurs
 */
// write to file 
void write_to_file(char *filepath, struct client *clients){ // Fonction qui écrit la liste des clients dans un fichier
  pthread_mutex_lock(&clients_list_lock);
  FILE *fic = fopen(filepath, "a+");
  while(clients != NULL){
    fprintf(fic, "%s %u\n", clients->username, clients->id);
    clients = clients->next;
  }
  fclose(fic);
  pthread_mutex_unlock(&clients_list_lock);
}

void print_clients(struct client* clients){ // Fonction qui affiche la liste des clients
  printf("BEGIN DEBUG\n");
  while(clients != NULL){
    printf("%s %u\n", clients->username, clients->id);
    clients = clients->next;
  }
  printf("END DEBUG\n");
}
uint16_t encode_header(struct header header){ // Fonction qui encode un header en un entier 16 bits
    uint16_t num = (header.id  << 5) | header.codereq;
    return num;
}
struct header decode_header(uint16_t num){ // Fonction qui décode un entier 16 bits en un header
    struct header header;
    memset(&header, 0, sizeof(struct header));
    uint16_t first_five_bits = num & 0x1F; // extract first 5 bits
    uint16_t rest_bits = (num >> 5) & 0x7FF; // extract rest of the bits
    header.codereq = first_five_bits;
    header.id = rest_bits;
    return header;
}
struct client *  add_client(const char * username){ // Fonction qui ajoute un client à la liste des clients
  pthread_mutex_lock(&clients_list_lock); // Verrouiller la liste des clients
  struct client *head = clients; 
  struct client *new_client = malloc(sizeof(struct client));
  memset(new_client, 0, sizeof(struct client));
  new_client->next = NULL;
  strcpy(new_client->username, username);
  nb_clients++; // Incrémenter le nombre de clients
  new_client->id =nb_clients; 
  while(head->next != NULL){
    head = head->next;
  }
  head->next = new_client; // Ajouter le nouveau client à la fin de la liste
  pthread_mutex_unlock(&clients_list_lock); // Déverrouiller la liste des clients
  return new_client;
}

void send_response_error(int sock_client){ // Fonction qui envoie une réponse d'erreur au client
  struct header header; 
  memset(&header, 0, sizeof(header));
  header.codereq = htons(CODE_ERROR);
  header.id = htons(0);   
  struct server_response response;
  memset(&response, 0, sizeof(response));
  response.codereq_id =  encode_header(header);
  response.numfil = 0;
  response.nb = 0;
  char buffer[sizeof(struct server_response)];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, &response, sizeof(struct server_response));
  int write_r = send(sock_client, buffer, sizeof(struct server_response),0);
  if(write_r < 0){
    perror("write");
    return;
  }
  close(sock_client);
}

void sign_up_client(int sock_client,char *username){ // Fonction qui ajoute un client à la liste des clients
  //Critical section
  struct client* new_client = add_client(username); // Ajouter le nouveau client à la liste des clients
  write_to_file("users.txt", new_client); // Ecrire la liste des clients dans le fichier users.txt
  //Critical section
  printf("New client added : %s %u\n", new_client->username, new_client->id);
  printf("New client written : %s %u\n", new_client->username, new_client->id);
  struct header header; 
  memset(&header, 0, sizeof(header));
  header.codereq = (CODE_SIGN_UP); 
  header.id = (new_client->id);   
  struct server_response response;
  memset(&response, 0, sizeof(response));
  response.codereq_id = htons( encode_header(header));
  
  response.numfil = 0;
  response.nb = 0;
  char buffer[sizeof(struct server_response)];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, &response, sizeof(struct server_response));
  int write_r = send(sock_client, buffer, sizeof(struct server_response),0);
  if(write_r < 0){
    perror("write");
    return;
  }
  close(sock_client);
}

int id_client_exists(uint16_t id){ // Fonction qui vérifie si un client existe dans la liste des clients (avec son id)
  pthread_mutex_lock(&clients_list_lock);
  struct client *head = clients;
  while(head != NULL){
    if(head->id == id){
      pthread_mutex_unlock(&clients_list_lock);
      return 1;
    }
    head = head->next;
  }
  pthread_mutex_unlock(&clients_list_lock);
  return 0;
}

char * get_username_from_id(uint16_t id){ // Fonction qui retourne le nom d'utilisateur d'un client à partir de son id
  pthread_mutex_lock(&clients_list_lock);
  struct client *head = clients;
  while(head != NULL){
    if(head->id == id){
      pthread_mutex_unlock(&clients_list_lock);
      return strdup(head->username);
    }
    head = head->next;
  }
  pthread_mutex_unlock(&clients_list_lock);
  return NULL;
}


int add_fil(u_int16_t id_client){ // Fonction qui ajoute un fil à la liste des fils
  pthread_mutex_lock(&fil_list_lock); // Verrouiller la liste des fils
  struct fil *head = fils; 
  struct fil *new_fil = malloc(sizeof(struct fil)); 
  memset(new_fil, 0, sizeof(struct fil));
  memset(new_fil->origine, '\0', sizeof(char) * MAX_LEN_USERNAME+1);
  strcpy(new_fil->origine, get_username_from_id(id_client));
  new_fil->next = NULL;
  nb_fil++; // Incrémenter le nombre de fils
  new_fil->numfil = nb_fil; 
  new_fil->posts = NULL;
  new_fil->nb_posts = 0;
  if(head == NULL){ // Si la liste des fils est vide
    fils = new_fil;
  }
  else{ // Sinon, ajouter le nouveau fil à la fin de la liste
    while(head->next != NULL){ 
      head = head->next;
    }
    head->next = new_fil;
  }
  pthread_mutex_unlock(&fil_list_lock); // Déverrouiller la liste des fils
  return new_fil->numfil;
}

struct post *add_post_to_fil(int numfil, uint16_t id, char *message) {
    struct fil *current = fils; // Parcourir la liste des fils
    if (current == NULL) { // Si la liste des fils est vide
        return NULL;
    }
    while (current != NULL) { // Chercher le fil avec le numéro numfil
        if (current->numfil == numfil) { // Si le fil est trouvé
            struct post *new_post = malloc(sizeof(struct post));
            memset(new_post->author, '\0', sizeof(char) * (MAX_LEN_USERNAME + 1));
            strcpy(new_post->author, get_username_from_id(id));
            memset(new_post->message, '\0', sizeof(char) * (MAX_LEN_DATA + 1));
            strcpy(new_post->message, message);
            new_post->next = current->posts; // Nouveau post pointe vers l'ancienne tête de liste des posts
            current->posts = new_post; // Le nouveau post devient la nouvelle tête de liste
            current->nb_posts++;
            return new_post;
        }
        current = current->next;
    }
    return NULL;
}


void print_fil(int n){ // Fonction qui affiche le contenu d'un fil
  struct fil *head = fils;
  while(head != NULL){
    if(head->numfil == n){
      struct post *post = head->posts;
      if(post == NULL){
        printf("post == NULL\n");
      }
      else{
        while(post != NULL){
          printf("post ->%s, dans le fil %d par %s\n", post->message,n, post->author);
          post = post->next;
        }
      }
    }
    head = head->next;
  }
}

struct fil* get_fil(int numfil){ // Fonction qui retourne un fil à partir de son numéro
  struct fil *head = copy_fil(fils);
  if(head == NULL){
    return NULL;
  }
  while(head != NULL){
    if(head->numfil == numfil){
      return head;
    }
    head = head->next;
  }
  return NULL;
}

// recupere l'adresse de mutli_diffusion d'un fil
struct multi_diffusion *get_multi_diffusion(int fil_id){
  struct multi_diffusion *tmp = diffusion_addresses;
  while(tmp != NULL){
    if(tmp->numfil == fil_id){
      return tmp;
    }
    tmp = tmp->next;
  }
  return NULL;
}

// ajout des notifications à envoyé dans une pile
void push_notification_stack(struct post* ticket,uint16_t id_client ,uint16_t numfil ){
  if (get_multi_diffusion(numfil) == NULL){
    return;
  }
  // initialisation de la notification que le serveur va envoyé
  struct notification_stack *new = malloc(sizeof(struct notification_stack));
  struct header header;
  memset(&header, 0, sizeof(header));
  header.codereq = (CODE_SUBSCRIBE);
  header.id = 0;
  new->codereq = htons(encode_header(header));
  new->numfil = numfil;
  memcpy(new->pseudo_data,get_username_from_id(id_client),MAX_LEN_USERNAME);
  memcpy(new->pseudo_data+MAX_LEN_USERNAME,ticket->message,strlen(ticket->message)+1);
  if (strlen(new->pseudo_data) < 20){
    memset(new->pseudo_data+strlen(new->pseudo_data),'\0',20-strlen(new->pseudo_data));
  }
  new->next = NULL;
  pthread_mutex_lock(&notifications_list_lock);
  if(notifications == NULL){
    notifications = new;
  }else{
    struct notification_stack *tmp = notifications;
    while(tmp->next != NULL){
      tmp = tmp->next;
    }
    tmp->next = new;
  }
  pthread_mutex_unlock(&notifications_list_lock);
}

void post_ticket_client(int sock_client, uint16_t id_client,struct client_request req){ // Fonction qui traite la requête d'un client pour poster un ticket
  uint16_t numfil = ntohs(req.numfil);
  uint16_t nb = ntohs(req.nb);
  if(numfil > nb_fil){ // Si le numéro du fil est supérieur au nombre de fils
    send_response_error(sock_client);
    return;
  }
  //Critical section
  if(numfil == 0){ // Si le numéro du fil est égal à 0, ajouter un nouveau fil
    numfil = add_fil(id_client);
  }
  struct post* ticket = add_post_to_fil(numfil,id_client, req.data); // Ajouter le ticket au fil
  //Critical section
  print_fil(numfil); // Afficher le contenu du fil
  struct header header; 
  memset(&header, 0, sizeof(header));
  header.codereq = (CODE_POST_TICKET);
  header.id = (id_client);   
  struct server_response response; // Strcuture de la réponse du serveur
  memset(&response, 0, sizeof(response));
  response.codereq_id =  htons(encode_header(header));
  response.numfil = htons(numfil);
  response.nb = htons(nb);
  char buffer[sizeof(struct server_response)];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, &response, sizeof(struct server_response));
  int write_r = send(sock_client, buffer, sizeof(struct server_response),0); // Envoyer la réponse au client
  if(write_r < 0){
    perror("write");
    return;
  }
  push_notification_stack(ticket,id_client,numfil); // Ajouter le ticket à la pile des notifications
}


// envoie des billets demandé par le client
void send_tickets_to_client(int sock_client, int numfil, int nb){
  struct fil *current_fil = get_fil(numfil);        // recuperation du fil
  struct post *current_post = current_fil->posts;   // pointeur sur le premier post du fil
  while(nb > 0){    // parcours de touts les posts du fil à envoyer
    struct ticket ticket;
    memset(&ticket, 0, sizeof(ticket));
    // initialisation du billets avec les bons arguments
    ticket.numfil = htons(numfil);
    memset(ticket.origine, '\0', sizeof(char) * MAX_LEN_USERNAME+1);
    memset(ticket.author, '\0', sizeof(char) * MAX_LEN_USERNAME+1);
    memset(ticket.message, '\0', sizeof(char) * MAX_LEN_DATA+1);
    strncpy(ticket.origine,current_fil->origine,strlen(current_fil->origine));
    strncpy(ticket.author,current_post->author,strlen(current_post->author));
    strncpy(ticket.message,current_post->message,strlen(current_post->message));
    ticket.datalen = strlen(current_post->message);
    char buffer[sizeof(struct ticket)];
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, &ticket, sizeof(struct ticket));
    int write_r = send(sock_client, buffer, sizeof(struct ticket),0);
    if(write_r < 0){
      perror("write");
      return;
    }
    nb--;
    current_post = current_post->next;
  }
}

// reponse du serveur au client pour la demande de billets
void last_n_ticket_client(int sock_client,int id_client, struct client_request req){
  uint16_t numfil = ntohs(req.numfil);
  uint16_t nb_toSend = ntohs(req.nb);
  if(numfil < 0 || nb_toSend < 0){
    send_response_error(sock_client);
    return;
  }
  else if(numfil == 0){ // parcourir tous les fils
    struct fil *tmp = copy_fil(fils);
    nb_toSend = 0;
    while(tmp != NULL){
    if(ntohs(req.nb) == 0 || ntohs(req.nb) > tmp->nb_posts){       // envoyer tous les derniers billets du fil
      nb_toSend += tmp->nb_posts;
    }else{                                  // envoyer les n dernier billets du fil
      nb_toSend += ntohs(req.nb);
    }
      tmp = tmp->next;
    }
    free(tmp);
  }
  else{ //nb doit avoir tout ou les n derniers billets du fil numfil
    struct fil *fil = get_fil(numfil);
    if(fil == NULL){
      send_response_error(sock_client);
      return;
    }
    else if(fil->nb_posts < nb_toSend || nb_toSend == 0){
      nb_toSend = fil->nb_posts;
    }else{
      nb_toSend = ntohs(req.nb);
    }
    free(fil);
  }
  //response du serveur au client
  struct header header;
  memset(&header, 0, sizeof(header));
  header.codereq = (CODE_LAST_N_TICKET);
  header.id = (id_client);   
  struct server_response response;
  memset(&response, 0, sizeof(response));
  response.codereq_id =  htons(encode_header(header));
  response.numfil = htons(numfil);
  response.nb = htons(nb_toSend);
  char buffer[sizeof(struct server_response)];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, &response, sizeof(struct server_response));
  int write_r = send(sock_client, buffer, sizeof(struct server_response),0);
  if(write_r < 0){
    perror("write");
    return;
  }
  //envoyer les billets
  if(numfil == 0){
    struct fil *tmp = copy_fil(fils);
    int nb = ntohs(req.nb);
    while(tmp != NULL){
      if(nb > 0 && nb <= tmp->nb_posts){       // envoyer les n derniers billets du fil
        send_tickets_to_client(sock_client ,tmp->numfil, nb);
      }else{                                  // envoyer tous les billets du fil
        send_tickets_to_client(sock_client ,tmp->numfil, tmp->nb_posts);
      }
      tmp = tmp->next;
    }
    free(tmp);
  }else{
    send_tickets_to_client(sock_client,numfil, nb_toSend);
  }
} 

void show_diffusion_addresses(){ // Afficher les adresses de diffusion
  struct multi_diffusion *tmp = diffusion_addresses;
  while(tmp != NULL){
    printf("numfil = %d, address = %s, port = %d\n", tmp->numfil, tmp->address, tmp->port);
    tmp = tmp->next;
  }
}

// creer une nouvelle adresse de diffusion pour le fil fil_id
struct multi_diffusion * create_new_multi_diffusion(int fil_id){
  struct multi_diffusion *new = malloc(sizeof(struct multi_diffusion));
  new->numfil = fil_id;
  new->address = malloc(sizeof(char) * MAX_LEN_MULTICAST_ADDRESS);
  sprintf(new->address, "%s%d", MULTICAST_BEING_ADDRESS_6, fil_id+1);
  new->port = MULTICAST_PORT;
  new->next = NULL;
  if(diffusion_addresses == NULL){
    diffusion_addresses = new;
  }else{
    struct multi_diffusion *tmp = diffusion_addresses;
    while(tmp->next != NULL){
      tmp = tmp->next;
    }
    tmp->next = new;
  }
  return new;
}

// envoie la reponse au client pour la demande d'abonnement
void send_multicast_address(int sock,struct multi_diffusion address, uint16_t header){
  struct server_subscribe response;
  memset(&response, 0, sizeof(response));
  sprintf(response.address, "%s", address.address);
  response.nb = htons(address.port);
  char buffer[sizeof(struct server_subscribe)];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, &response, sizeof(struct server_subscribe));
  int write_r = send(sock, &header, sizeof(uint16_t),0);
  if (write_r < 0){
    perror("write");
    send_response_error(sock);
  }
  int write_r2 = send(sock, buffer, sizeof(struct server_subscribe),0);
  if (write_r2 < 0){
    perror("write");
    send_response_error(sock);
  }
}

// recupere l'adresse de diffusion du fil fil_id ou la créer si elle n'existe pas
void subscribe_client(int sock , uint16_t id, struct server_subscribe req,uint16_t header){
  if(get_fil(req.numfil)==NULL){
    send_response_error(sock);
    return;
  }
  struct multi_diffusion *multi_diffusion = get_multi_diffusion(req.numfil);
  if(multi_diffusion == NULL){
    multi_diffusion = create_new_multi_diffusion(req.numfil);
  } 
  send_multicast_address(sock, *multi_diffusion, header);
}

void* diffuse() {
  int ifindex = if_nametoindex("eth0"); // Indice de l'interface réseau
  struct notification_stack *tmp, *next;
  struct multi_diffusion *multi_diffusion;
  struct sockaddr_in6 addr;
  char buff[34]; // données à envoyer
  while (1) {
    pthread_mutex_lock(&notifications_list_lock); // Verrouillage de la liste des notifications
    tmp = notifications;
    while (tmp != NULL) {
      multi_diffusion = get_multi_diffusion(tmp->numfil); // Récupération des informations de diffusion multicast
      if (multi_diffusion != NULL) {
        int sock = socket(AF_INET6, SOCK_DGRAM, 0); // Création de la socket
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(multi_diffusion->port);
        inet_pton(AF_INET6, multi_diffusion->address, &(addr.sin6_addr));

        if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
          perror("failed");
          return NULL;
        }

        memset(buff, 0, sizeof(buff));
        memcpy(buff, &(tmp->codereq), sizeof(uint16_t)); // Copie du code de demande dans le tampon
        memcpy(buff + sizeof(uint16_t), &(tmp->numfil), sizeof(uint16_t)); // Copie du numéro de fil dans le tampon
        memcpy(buff + 2 * sizeof(uint16_t), tmp->pseudo_data, strlen(tmp->pseudo_data)); // Copie des données pseudo dans le tampon
        printf("Sent notification = %s\n", buff + 2 * sizeof(uint16_t));
        int s = sendto(sock, buff, sizeof(buff), 0, (struct sockaddr *)&addr, sizeof(addr)); // Envoi des données
        if (s < 0) {
          perror("sendto");
          return NULL;
        }
        close(sock);
      }
      next = tmp->next;
      free(tmp);
      tmp = next;
    }
    notifications = NULL;
    pthread_mutex_unlock(&notifications_list_lock); // Déverrouillage de la liste des notifications
    sleep(NOTIFICATION_TIME_INTERVAL); // Attente avant la prochaine diffusion de notifications
  }
}

int generate_port(int id_client){ // Générer un port pour le client
  return PORT_UDP+id_client;
}

void printPackets(Packet_recv *head) { // Afficher les paquets
    Packet_recv *current = head;
    while (current != NULL) {
        printf("Sequence Number: %d\n", current->sequenceNumber);
        current = current->next;
    }
}

void insertPacket(Packet_recv **head, Packet_recv *packet) { // Insérer un paquet dans la liste tout en le triant
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
void freePackets(Packet_recv *head) { // Libérer la liste des paquets
    Packet_recv *current = head;
    Packet_recv *next;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
}
int receive_file(char* filename, int port){ //Fonction qui gére la réception d'un fichier
  FILE *file;
  char file_path[strlen(filename) + 14];
  memset(file_path, 0, sizeof(file_path));
  sprintf(file_path, "files_received/%s", filename); // Créer le chemin du fichier
  int sock = socket(AF_INET6, SOCK_DGRAM, 0); // Créer le socket UDP
  struct sockaddr_in6 serv_addr, client_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin6_family = AF_INET6;
  serv_addr.sin6_port = htons(port);
  serv_addr.sin6_addr = in6addr_any;
  if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) { // Bind le socket
    perror("bind");
    return -1;
  }
  socklen_t cli_addr_size = sizeof(client_addr);
   file = fopen(file_path, "wb"); // Ouvrir le fichier en mode écriture binaire
    if (file == NULL) {
        perror("Impossible d'ouvrir le fichier");
        return -1;
    }

    Packet_recv *packetsHead = NULL;
    int numPacketsReceived = 0;

    Packet_recv receivedPacket; // Paquet reçu
    ssize_t bytesRead; // Nombre d'octets lus

    fd_set readSet; // Ensemble de descripteurs de fichiers (un seul ici en l'occurence)
    struct timeval timeout; // Temps d'attente pour le select
    while(1){
        FD_ZERO(&readSet); // Initialiser l'ensemble
        FD_SET(sock, &readSet); // Ajouter le socket à l'ensemble
        timeout.tv_sec = 10; // Temps d'attente
        timeout.tv_usec = 0;

        int ready = select(sock+1, &readSet, NULL, NULL, &timeout); // Attendre jusqu'à ce que le socket soit prêt
        if(ready < 0){ // Erreur
            perror("select");
            return -1;
        }
        else if(ready == 0){ // Timeout
            printf("timeout\n");
                break;
        }
        else{
            if(FD_ISSET(sock,&readSet)){ // Le socket est prêt
                bytesRead = recvfrom(sock, (void *)&receivedPacket, sizeof(Packet_recv), 0,(struct sockaddr *)&client_addr, &cli_addr_size); // Lire le paquet
                if(bytesRead < 0){
                    perror("recvfrom");
                    return -1;
                }
                Packet_recv *newPacket = (Packet_recv *)malloc(sizeof(Packet_recv)); // Créer un nouveau paquet
                newPacket->sequenceNumber = ntohs(receivedPacket.sequenceNumber);  // Copier les données du paquet reçu dans le nouveau paquet
                memcpy(newPacket->data, receivedPacket.data, strlen(receivedPacket.data));
                newPacket->next = NULL;
                printf("new packet created : %d with size : %ld\n", newPacket->sequenceNumber,strlen(newPacket->data));
                insertPacket(&packetsHead, newPacket); // Insérer le paquet dans la liste
                numPacketsReceived++; // Incrémenter le nombre de paquets reçus
            }
        }
    }
    Packet_recv *currentPacket = packetsHead; // Paquet courant
    printPackets(packetsHead); // Afficher les paquets
    while (currentPacket != NULL) { // Ecrire les paquets dans le fichier
        printf("Écriture du paquet %d de taille : %ld\n", currentPacket->sequenceNumber, strlen(currentPacket->data));
        int written = fwrite(currentPacket->data, sizeof(char), strlen(currentPacket->data), file);
        if(written < 0){
            perror("fwrite");
            return -1;
        }
        currentPacket = currentPacket->next;
    }
    freePackets(packetsHead);
    fclose(file);
    close(sock);
    return 0;
}

// envoie la reponse au client pour sa requete d'envoie de fichier
void send_file(int sock_client,uint16_t id_client,struct client_request req){
  uint16_t numfil = ntohs(req.numfil);
  if(numfil > nb_fil || numfil == 0){
    send_response_error(sock_client);
    return;
  }
  // envoie de la reponse avec l'adresse et le port ou le serveur va recevoir le fichier
  struct header header; 
  memset(&header, 0, sizeof(header));
  header.codereq = (CODE_SEND_FILE);
  header.id = (id_client);   
  struct server_response response;
  memset(&response, 0, sizeof(response));
  response.codereq_id =  htons(encode_header(header));
  response.numfil = htons(numfil);
  response.nb = htons(generate_port(id_client));
  char buffer[sizeof(struct server_response)];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, &response, sizeof(struct server_response));
  int write_r = send(sock_client, buffer, sizeof(struct server_response),0);
  if(write_r < 0){
    perror("write");
    return;
  }
  close(sock_client);
  // reception du fichier
  if(receive_file(req.data, ntohs(response.nb)) == 0){
    struct post* ticket = add_post_to_fil(numfil, id_client, req.data);
      push_notification_stack(ticket,id_client,numfil); // Ajouter le ticket à la pile des notifications
    print_fil(numfil);
  }
}

// recupére le post 'data' du fil 'numfil'
struct post* get_post_from_fil(uint16_t numfil, char data[MAX_LEN_DATA]){
  struct fil* current_fil = get_fil(numfil);
  if(current_fil == NULL){
    return NULL;
  }
  struct post* current_post = current_fil->posts;
  while(current_post != NULL){
    if(strncmp(current_post->message,data,sizeof(current_post->message)) == 0){
      return current_post;
    }
    current_post = current_post->next;
  }
  return NULL;
}

// envoie du fichier au client apres sa demande de telechargement
void send_file_to_client(const char* filename,int port){
  FILE * file = fopen(filename, "rb");      // Ouverture du fichier en lecture
  if (file == NULL) {
      perror("Impossible d'ouvrir le fichier");
      return;
  }
  // adresse et port ou sera envoyé le fichier
  struct sockaddr_in6 serverAddr;
  socklen_t addr_size;
  int sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("Erreur lors de la création de la socket");
    return;
  }
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin6_family = AF_INET6;
    serverAddr.sin6_port = htons(port);
    inet_pton(AF_INET6, ADDRESS, &serverAddr.sin6_addr);
    addr_size = sizeof(serverAddr);

    // Lecture et envoi du fichier
    char buffer[MAX_LEN_PACKET];
    size_t bytesRead;
    int sequenceNumber = 0;

    while ((bytesRead = fread(buffer, sizeof(char), MAX_LEN_PACKET, file)) > 0){  // Lire le fichier
        usleep(300);
        printf("Envoi du paquet %d\n", sequenceNumber);
        Packet_send packet;
        packet.sequenceNumber = htons(sequenceNumber);
        memset(packet.data,'\0',sizeof(packet.data));
        memcpy(packet.data, buffer, bytesRead);
        ssize_t bytesSent = sendto(sock, (void *)&packet, sizeof(Packet_send), 0,(struct sockaddr *)&serverAddr, addr_size);
        if (bytesSent < 0) {
            perror("Erreur lors de l'envoi du fichier");
            return;
        }
        sequenceNumber++;
    }
    fclose(file);
    close(sock);
    printf("Le fichier a été envoyé avec succès.\n");
}

// envoie la reponse au client pour sa requete de telechargement de fichier
void dl_file(int sock_client, uint16_t id_client,struct client_request req){
  uint16_t numfil = ntohs(req.numfil);
  uint16_t nb = ntohs(req.nb);
  struct post* post = get_post_from_fil(numfil, req.data);
  if(numfil > nb_fil || numfil == 0 || post == NULL){
    send_response_error(sock_client);
    return;
  }
  // envoie de la reponse au client
  struct header header; 
  memset(&header, 0, sizeof(header));
  header.codereq = (CODE_DL_FILE);
  header.id = (id_client);   
  struct server_response response;
  memset(&response, 0, sizeof(response));
  response.codereq_id = htons(encode_header(header));
  response.numfil = htons(numfil);
  response.nb = htons(nb);
  char buffer[sizeof(struct server_response)];
  memset(buffer, 0, sizeof(buffer));
  memcpy(buffer, &response, sizeof(struct server_response));
  int write_r = send(sock_client, buffer, sizeof(struct server_response),0);
  if(write_r < 0){
    perror("write");
    return;
  }
  close(sock_client);
  // envoie du fichier au client
  send_file_to_client(post->message, nb);
}

void* handle_client(void* sock){ //Fonction qui gère les requêtes des clients
  int sock_client =  *(int *)sock;
  uint16_t header; //header de la requête du client
  char buffer[sizeof (uint16_t)];
  memset(buffer, 0, sizeof(buffer));
  memset(&header, 0, sizeof(header));
  int read_r = read(sock_client, buffer, sizeof(uint16_t)); //lecture du header
  
  if(read_r < 0){
    perror("read");
    return NULL;
  }
  memcpy(&header,buffer, sizeof(uint16_t));
  header = ntohs(header); 
  struct header header_response = decode_header(header); //décodage du header
  if (header_response.codereq == CODE_SIGN_UP){ //si le client veut s'inscrire
    char username[MAX_LEN_USERNAME+1]; //username du client
    memset(username, 0, sizeof(username));
    read_r = read(sock_client, username, MAX_LEN_USERNAME+1); //lecture du reste de la requête
    if(read_r < 0){
      perror("read");
      return NULL;
    }
    sign_up_client(sock_client, username); //appel de la fonction d'inscription
  } 
  else if(header_response.codereq == CODE_POST_TICKET){ //si le client veut poster un ticket
    uint16_t id = header_response.id; //id du client
    if(id_client_exists(id)){ //si l'id existe                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
      struct client_request req;
      char buffer[sizeof(struct client_request)]; //buffer pour la suite de la requête
      memset(buffer, 0, sizeof(buffer));
      memset(&req, 0, sizeof(req));
      read_r = read(sock_client, buffer, sizeof(struct client_request)); //lecture du reste de la requête
      if(read_r < 0){
        perror("read");
        return NULL;
      }
      memcpy(&req, buffer, sizeof(struct client_request));
      post_ticket_client(sock_client,id,req); //appel de la fonction de post de ticket
      }
    
    else {
      send_response_error(sock_client); //si l'id n'existe pas
      }
  }
  else if(header_response.codereq == CODE_LAST_N_TICKET){ //si le client veut les n derniers tickets
      uint16_t id = header_response.id;
      if(id_client_exists(id)){ //si l'id existe
        struct client_request req; //Struct ou sera stocké le reste de la requete du client
        char buffer[sizeof(struct client_request)];
        memset(buffer, 0, sizeof(buffer));
        memset(&req, 0, sizeof(req));
        read_r = read(sock_client, buffer, sizeof(struct client_request)); //lecture du reste de la requête
        if(read_r < 0){
          perror("read");
          return NULL;
        }
        memcpy(&req, buffer, sizeof(struct client_request));
        last_n_ticket_client(sock_client,id,req); //appel de la fonction qui envoie les n derniers tickets
      }
      else{
        send_response_error(sock_client); //si l'id n'existe pas
      }
    }
  
  else if (header_response.codereq == CODE_SUBSCRIBE){ //si le client veut s'abonner à un fil
    uint16_t id = header_response.id;
    if(id_client_exists(id)){                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
      struct server_subscribe req;
      char buffer[sizeof(struct server_subscribe)];
      memset(buffer, 0, sizeof(buffer));
      memset(&req, 0, sizeof(req));
      read_r = read(sock_client, buffer, sizeof(struct server_subscribe));
      if(read_r < 0){
        perror("read");
        return NULL;
      }
      memcpy(&req, buffer, sizeof(struct server_subscribe));
      req.numfil = ntohs(req.numfil);
      subscribe_client(sock_client,id,req,htons(header)); 
      printf("New Client subscribed to fil %d\n",req.numfil);
      }
    
    else {
      send_response_error(sock_client);
      }
    }
    else if(header_response.codereq == CODE_SEND_FILE){ //si le client veut envoyer un fichier
      uint16_t id = header_response.id; //id du client
      if(id_client_exists(id)){ //si l'id existe
        struct client_request req; //Struct ou sera stocké le reste de la requete du client
        char buffer[sizeof(struct client_request)];
        memset(buffer, 0, sizeof(buffer));
        memset(&req, 0, sizeof(req));
        read_r = read(sock_client, buffer, sizeof(struct client_request)); //lecture du reste de la requête
        if(read_r < 0){
          perror("read");
          return NULL;
        }
        memcpy(&req, buffer, sizeof(struct client_request));
        send_file(sock_client,id,req); //appel de la fonction qui envoie les n derniers tickets
      }
      else{
        send_response_error(sock_client);
      }
    }
    else if(header_response.codereq == CODE_DL_FILE){ //si le client veut télécharger un fichier
      uint16_t id = header_response.id;
      if(id_client_exists(id)){
        struct client_request req;
        char buffer[sizeof(struct client_request)];
        memset(buffer, 0, sizeof(buffer));
        memset(&req, 0, sizeof(req));
        read_r = read(sock_client, buffer, sizeof(struct client_request));
        if(read_r < 0){
          perror("read");
          return NULL;
        }
        memcpy(&req, buffer, sizeof(struct client_request));
        dl_file(sock_client,id,req);
      }
      else{
        send_response_error(sock_client);
      } 
    }
  else {
    send_response_error(sock_client);
  }
  return NULL;
}

void accept_client(int sock){
  while(1){
    struct sockaddr_in6 address_client;
    socklen_t address_client_len = sizeof(address_client);
    memset(&address_client, 0, sizeof(address_client));
    int client = accept(sock, (struct sockaddr *) &address_client, &address_client_len);
    if(client < 0){
      perror("accept");
    }
    else {
      printf("New client connected\n");
      pthread_t thread;
      if (pthread_create(&thread, NULL, handle_client,(&client))){
        perror("pthread_create");
        close(client);
      }
    } 
  }
}

int main(int argc, char *argv[]) {
  pthread_t diffuser;
  if (pthread_create(&diffuser, NULL, diffuse,NULL)){
    perror("pthread_create");
  }
  int sock = create_server(PORT, ADDRESS);
  printf("Server started on port %d and address %s \n", PORT, ADDRESS);
  nb_clients = init_clients("users.txt", &clients);
  print_clients(clients);
  accept_client(sock);
  close(sock);
}