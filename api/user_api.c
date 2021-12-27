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

char *server_ip = "127.0.0.1";
char *server_port = "58043";

char UID[5];
char password[8];

int udp_socket, errcode; 
ssize_t n;
struct addrinfo hints, *res;
struct sockaddr_in addr;
socklen_t addrlen;
char buffer[MAX_LINE_SIZE];

/* Creates client socket and sets up the server address */
int setup() {
	/* Create UDP socket */
	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_socket == -1) {
		exit(1);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; /* IPv4 */
	hints.ai_socktype = SOCK_DGRAM; /* UDP socket */

	addrlen = sizeof(addr); /* for receiving messages */

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

/*	Registers a user
	Input:
	- UID: a 5 char numerical string
	- pass: a 8 char alphanumerical string
	Output: OK, DUP, NOK
*/
int register_user(char *user, char *pass) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "REG", user, pass);

	if (!send_message_udp(buf)) {
		return FAIL;
	}

	memset(buf, 0, sizeof(buf));

	if (!rcv_message_udp(buf)) {
		return FAIL;
	}

	printf("Received: %s\n", buf);
	
	int numTokens = sscanf(buf, "%s %s\n", command, status);
	if (numTokens != 2 || strcmp(command, "RRG") != 0) {
		return FAIL;
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "DUP")) {
		return STATUS_DUP;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} 
	return FAIL;	
}

/*	Unregisters a user
	Input:
	- UID: a 5 char numerical string
	- pass: a 8 char alphanumerical string
	Output: TODO
*/
int unregister_user(char *user, char *pass) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	snprintf(buf, sizeof(buf), "%s %s %s\n", "UNR", user, pass);

	if (!send_message_udp(buf)) {
		return FAIL;
	}

	memset(buf, 0, sizeof(buf));

	if (!rcv_message_udp(buf)) {
		return FAIL;
	}

	printf("Received: %s", buf);

	int numTokens = sscanf(buf, "%s %s", command, status);
	if (numTokens != 2 || strcmp(command, "RUN") != 0) {
		return FAIL;
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} 
	return FAIL;
}

/*	Login
	Input:
	- UID: a 5 char numerical string
	- pass: a 8 char alphanumerical string
	Output: TODO
*/
int login(char *user, char *pass) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "LOG", user, pass);

	if (!send_message_udp(buf)) {
		return FAIL;
	}

	memset(buf, 0, sizeof(buf));

	if (!rcv_message_udp(buf)) {
		return FAIL;
	}

	printf("Received: %s", buf);
	
	int numTokens = sscanf(buf, "%s %s\n", command, status);
	if (numTokens != 2 || strcmp(command, "RLO") != 0) {
		return FAIL;
	}

	if (!strcmp(status, "OK")) {
		strcpy(UID, user);
		strcpy(password, pass);
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} 
	return FAIL;	
}

int logout() {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "OUT", UID, password);
	

	if (!send_message_udp(buf)) {
		return FAIL;
	}

	memset(buf, 0, sizeof(buf));

	if (!rcv_message_udp(buf)) {
		return FAIL;
	}

	printf("Received: %s", buf);
	
	int numTokens = sscanf(buf, "%s %s\n", command, status);
	if (numTokens != 2 || strcmp(command, "ROU") != 0) {
		return FAIL;
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} 
	return FAIL;	
}

int rcv_message_udp(char *buffer) {
	if (recvfrom(udp_socket, buffer, MAX_LINE_SIZE , 0, (struct sockaddr*) &addr, &addrlen) > 0) {
		return 1;
	}
	return 0;
}


int send_message_udp(char *message) {
	if (sendto(udp_socket, message, strlen(message), 0, res->ai_addr, res->ai_addrlen) > 0) {
		return 1;
	}
	return 0;
}

void end_session(){
	close(udp_socket);
}