CC=gcc
CFLAGS= -Wall -pedantic -g 
INCLUDES = -I./include
CCLINK = -pthread

main serveur : main.o client.o serveur.o
	$(CC) $(INCLUDES) -o main main.o client.o $(CCLINK)
	$(CC) $(INCLUDES) -o serveur serveur.o $(CCLINK)

main.o : main.c client.h serveur.h
	$(CC) -c $(CFLAGS) -o main.o main.c

client.o : client.c client.h
	$(CC) -c $(CFLAGS) -o client.o  client.c

serveur.o : serveur.c serveur.h
	$(CC) -c $(CFLAGS) -o serveur.o serveur.c

clean :
	rm -rf *.o

cleanall:
	rm -rf *.o main serveur