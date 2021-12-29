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

#define EXITFAILURE 1
#define GIANT_SIZE 3500

/* Default server ip and port */
char *server_ip = "127.0.0.1";
char *server_port = "58043";

/* User ID, password, and flag for when a user is logged in */
char UID[5];
char password[8];
int logged_in = 0;

/* variables needed for UDP connection */
int udp_socket; 
ssize_t n;
struct addrinfo hints, *res;
struct sockaddr_in addr;
socklen_t addrlen;
char buf[MAX_LINE_SIZE];

void exchange_messages_udp(char *buf, ssize_t max_rcv_size);

/*	Creates client socket and sets up the server address.
	Terminates program if socked could not be created or hostname/IP address
	could not be resolved.
	Input: None
	Output: None
*/
void setup() {
	/* Create UDP socket */
	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_socket == -1) {
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; /* IPv4 */
	hints.ai_socktype = SOCK_DGRAM; /* UDP socket */

	addrlen = sizeof(addr); /* for receiving messages */

	if (getaddrinfo(server_ip, server_port, &hints, &res) != 0) {
		exit(EXIT_FAILURE);
	}
	
}

/* Checks if name points to a valid hostname that exists in the DNS.
   Input:
	- name: the name to be checked
   Output: 1 if name is a valid hostname, 0 otherwise.
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

/* Checks if ip_addr is a valid IPv4 address.
   Input:
	- ip_addr: string to be checked
   Output: 1 if ip_addr is a valid address, 0 otherwise.
*/
int validate_ip(char *ip_addr) {
	struct sockaddr_in addr;
	if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) > 0) {
		server_ip = strdup(ip_addr);
		return 1;
	}
	return 0;
}

/* Checks if port points to a string with a valid port number.
   Input:
	- port: string to be checked 
   Output: 1 if port is a valid port, 0 otherwise.
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

	exchange_messages_udp(buf, MAX_LINE_SIZE);
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RRG") != 0) {
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
	- UID: a valid UID (a 5 char numerical string)
	- pass: a valid pass (8 char alphanumerical string)
	Output: TODO
*/
int unregister_user(char *user, char *pass) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	snprintf(buf, sizeof(buf), "%s %s %s\n", "UNR", user, pass);

	exchange_messages_udp(buf, MAX_LINE_SIZE);

	int num_tokens = sscanf(buf, "%s %s", command, status);
	if (num_tokens != 2 || strcmp(command, "RUN") != 0) {
		return FAIL;
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} 
	return FAIL;
}

/*	Login a user 
	Input:
	- UID: a valid UID 
	- pass: a valid pass 
	Output: A integer s.t.:
	- OK: if the login was successful
	- NOK: otherwise
*/
int login(char *user, char *pass) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "LOG", user, pass);

	exchange_messages_udp(buf, MAX_LINE_SIZE);
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RLO") != 0) {
		return FAIL;
	}

	if (!strcmp(status, "OK")) {
		strncpy(UID, user, 5);
		strncpy(password, pass, 8);
		logged_in = 1;
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} 
	return FAIL;	
}

/*	Logout
	Input:
	- UID: a valid UID 
	- pass: a valid pass 
	Output: A integer s.t.:
	- OK: if the login was successful
	- NOK: otherwise
*/
int logout() {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "OUT", UID, password);

	exchange_messages_udp(buf, MAX_LINE_SIZE);
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "ROU") != 0) {
		return FAIL;
	}

	if (!strcmp(status, "OK")) {
		logged_in = 0;
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} 
	return FAIL;	
}

/*	Getter for the current user ID
	Input: None
	Returns: the current UID. If there is
	no user logged in, UID is an empty string
*/
char *get_uid () {
	return UID;	
}

/*	Getter for all the available groups in the DS server
	Input: None
	Returns: an array of arrays of 2 string of the format
	[GID, Gname], one for each available group
*/
char ***get_all_groups() {
	char *command, *num_groups, buf[GIANT_SIZE];
	char ***response = NULL;
	
	sprintf(buf, "%s\n", "GLS");
	
	exchange_messages_udp(buf, GIANT_SIZE);

	command = strtok(buf, " ");
	num_groups = strtok(NULL, " ");
	printf("%s %s\n", command, num_groups);
	if (command == NULL || num_groups == NULL) {
		return FAIL;
	} 
	
	response = (char***) malloc(sizeof(char**) * (atoi(num_groups) + 1));
	for (int i = 0; i < atoi(num_groups) + 1; i++) {
		response[i] = (char **) malloc(sizeof(char*) * 2);
		for (int j = 0; j < 2; j++) {
			response[i][j] = (char *) malloc(sizeof(char) * 24);
		}
	}

	for (int i = 0; i < atoi(num_groups); i++) {
		response[i][0] = strtok(NULL, " ");
		response[i][1] = strtok(NULL, " ");
		strtok(NULL, " ");
	}

	response[atoi(num_groups)][0] = "";

	return response; // TODO tratar do buf para print no user
}

/*	Subscribes current user to the specified group
	Input: A valid GID and a group name
	Returns: one of the following integer status codes:
	- OK: if the subscription was successful
	- NEW: if a group was created
	- E_SR: if the provided user is invalid
	- E_GNAME: if the proivdade group name is invalid
	- E_FULL: if a new group could not be created
*/
int subscribe_group(char *gid, char *gName) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s %s\n", "GSR", "95565", gid, gName);

	printf("Yeee\n");

	exchange_messages_udp(buf, MAX_LINE_SIZE);

	printf("Yeee\n");

	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RGS") != 0) {
		return FAIL;
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "NEW")) {
		return STATUS_NEW_GROUP;
	} else if (!strcmp(status, "E_SR")) {
		return STATUS_USR_INVALID;
	} else if (!strcmp(status, "E_GRP")) {
		return STATUS_GID_INVALID;
	} else if (!strcmp(status, "E_GNAME")) {
		return STATUS_GNAME_INVALID;
	} else if (!strcmp(status, "E_FULL")) {
		return STATUS_GROUPS_FULL;
	}
	return FAIL;
}

/*	Sends the message in buf to the server through the UDP socket 
	and puts a response of size max_rcv_size in buf 
	Input:
	- buf: a buffer that contains the message to be sent and that will
	contained the received message
	- max_rcv_size: maximum size of the response
*/
void exchange_messages_udp(char *buf, ssize_t max_rcv_size) {
	
	if (sendto(udp_socket, buf, strlen(buf), 0, res->ai_addr, res->ai_addrlen) != strlen(buf) * sizeof(char)) {
		exit(EXITFAILURE);
	}

	memset(buf, 0, strlen(buf) * sizeof(char));
	
	if (recvfrom(udp_socket, buf, max_rcv_size, 0, (struct sockaddr*) &addr, &addrlen) <= 0) {
		exit(EXITFAILURE);
	}
	
	//printf("Received: %s\n", buf);
	
}

void end_session(){
	close(udp_socket);
}

int is_logged_in () {
	return logged_in;
}