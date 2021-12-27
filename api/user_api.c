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
struct addrinfo hints, *res;
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

/* Checks if name points to a valid hostname that exists in the DNS
   Input:
	- name: the name to be checked
   Output: 1 if name is a valid hostname, 0 otherwise
*/
int validate_hostname(char *name) {
	struct addrinfo *aux;
    if (getaddrinfo(name, NULL, NULL, &aux) == 0) {
		server_ip = strdup(name);
		freeaddrinfo(aux);
		return 1;
	} 
	return 0;
}

/* Checks if ipd_addr points to a string with a valid IPv4 address 
   Input:
	- ip_addr: string to be checked
   Output: 1 if ip_addr is a valid address, 0 otherwise
*/
int validate_ip(char *ip_addr) {
	struct sockaddr_in addr;
	if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) > 0) {
		server_ip = strdup(ip_addr);
		return 1;
	}
	return 0;
}

/* Checks if port points to a string with a valid port number
   Input:
	- port: string to be checked 
   Output: 1 if port is a valid port, 0 otherwise
*/
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