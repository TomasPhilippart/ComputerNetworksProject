#include "user_api.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>

#define MAX_LINE_SIZE 300


char *server_ip = "127.0.0.1";
char *server_port = "58043";

int udp_socket, errcode; 
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res;
struct sockaddr_in addr;
char buffer[MAX_LINE_SIZE];

int startup() {
	// Create UDP socket
	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_socket == -1) {
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_DGRAM; // UDP socket
}

int create_connection() {
	if (getaddrinfo(server_ip, server_port, &hints, &res) != 0) {
		return -1;
	}

	return 0;
}
int validate_dns(char *name) {
    if (getaddrinfo(name, NULL, &hints, &res) == 0) {
		server_ip = strdup(name);
		return 1;
	} 
	return 0;
}

int validate_ip(char *ip_addr) {
	if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) > 0) {
		server_ip = strdup(ip_addr);
		return 1;
	}
	return 0;
}

int validate_port(char *port) {
	int port_number = atoi(port);
	if (port_number > 0 && port_number <= 65535) {
		server_port = strdup(port);
		return 1;
	}
	return 0;
}

int send_message_udp(char *message) {
	n = sendto(udp_socket, message, strlen(message)+1, 0, res->ai_addr, res->ai_addrlen);
		
}