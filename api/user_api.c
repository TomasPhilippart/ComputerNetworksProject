#include "user_api.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

// To be shared with user.c
char *server_ip = "127.0.0.1";
int server_port = 58043;

int fd,errcode; 
ssize_t n;
socklen_t addrlen;
struct addrinfo hints,*res;
struct sockaddr_in addr;
char buffer[128];

int startup() {
	fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
	if (fd == 1) {
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_DGRAM; // UDP socket
}

int validate_dns(char *name) {
    return getaddrinfo(name, server_port, &hints, &res);
}

