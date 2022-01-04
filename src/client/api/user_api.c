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
#include <sys/stat.h>
// NOTE remove just for debug
#include <errno.h>

#define GIANT_SIZE 3500		// NOTE: please change this in the future ffs
// NOTE need to free malloc stuff

/* Default server ip and port */
char *server_ip = "127.0.0.1";
char *server_port = "58043";

/* User ID, password, group ID and flag for when a user is logged in */
char UID[6] = ""; // 5 digit numeric
char password[9] = ""; // 8 alphanumeric characters
char GID[3] = ""; // 2 digit numeric (01-99)
int logged_in = 0;

/* variables needed for UDP connection */
int udp_socket; 
struct addrinfo *res_udp;
struct addrinfo hints_udp;

/* variables needed for TCP connection */
int tcp_socket;
struct addrinfo *res_tcp;
struct addrinfo hints_tcp;

ssize_t n;
struct sockaddr_in addr;
socklen_t addrlen;

char ***parse_groups (char *buf, int num_groups);
char **parse_uids (char *buf);
char ***parse_messages(char *buf, int num_messages);
void exchange_messages_udp(char *buf, ssize_t max_rcv_size);
void exchange_messages_tcp(char **buf, ssize_t num_bytes);

/*	Creates client socket and sets up the server address.
	Terminates program if socked could not be created or hostname/IP address
	could not be resolved.
	Input: None
	Output: None
*/
void setup_udp() {
	/* Create UDP socket */
	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_socket == -1) {
		exit(EXIT_FAILURE);
	}

	memset(&hints_udp, 0, sizeof(hints_udp));
	hints_udp.ai_family = AF_INET; /* IPv4 */
	hints_udp.ai_socktype = SOCK_DGRAM; /* UDP socket */

	addrlen = sizeof(addr); /* for receiving messages */

	if (getaddrinfo(server_ip, server_port, &hints_udp, &res_udp) != 0) {
		exit(EXIT_FAILURE);
	}

}

void setup_tcp() {

	/* Create TCP socket */
	tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_socket == -1) {
		exit(EXIT_FAILURE);
	}

	memset(&hints_tcp, 0, sizeof(hints_tcp));
	hints_tcp.ai_family = AF_INET; /* IPv4 */
	hints_tcp.ai_socktype = SOCK_STREAM; /* UDP socket */

	addrlen = sizeof(addr); /* for receiving messages */

	if (getaddrinfo(server_ip, server_port, &hints_tcp, &res_tcp) != 0) {
		exit(EXIT_FAILURE);
	}

	connect(tcp_socket, res_tcp->ai_addr, res_tcp->ai_addrlen); 
}

/*	Checks if name points to a valid hostname that exists in the DNS.
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

/*	Checks if ip_addr is a valid IPv4 address.
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

/*	Checks if port points to a string with a valid port number.
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
	Output: 
	- OK, if the registration was successfull
	- DUP, if the registration UID is duplicated
	- NOK, if UID is invalid or pass is wrong
*/
int register_user(char *user, char *pass) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "REG", user, pass);

	exchange_messages_udp(buf, MAX_LINE_SIZE);
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RRG") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "DUP")) {
		return STATUS_DUP;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else {
		end_session(EXIT_FAILURE);	
	}

}

/*	Unregisters a user
	Input:
	- UID: a valid UID (a 5 char numerical string)
	- pass: a valid pass (8 char alphanumerical string)
	Output: 
	- OK, if the unregistration was successfull
	- NOK, if UID is invalid or pass is wrong 
*/
int unregister_user(char *user, char *pass) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	snprintf(buf, sizeof(buf), "%s %s %s\n", "UNR", user, pass);

	exchange_messages_udp(buf, MAX_LINE_SIZE);

	int num_tokens = sscanf(buf, "%s %s", command, status);
	if (num_tokens != 2 || strcmp(command, "RUN") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else {
		end_session(EXIT_FAILURE);
	}
}

/*	Login a user 
	Input:
	- UID: a valid UID 
	- pass: a valid pass 
	Output: A integer s.t.:
	- OK: if the login was successful
	- NOK: invalid user or wrong pass
*/
int login(char *user, char *pass) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "LOG", user, pass);

	exchange_messages_udp(buf, MAX_LINE_SIZE);
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RLO") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		strncpy(UID, user, 6);
		strncpy(password, pass, 9);
		logged_in = 1;
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else {
		end_session(EXIT_FAILURE);	
	}
}

/*	Logout
	Input:
	- UID: a valid UID 
	- pass: a valid pass 
	Output: A integer s.t.:
	- OK: if the login was successful
	- NOK: otherwise (NOTE: this is a little bit
	redundant, since we guarantee that both are correct, unless another
	session unregisters the account or something)
*/
int logout() {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "OUT", UID, password);

	exchange_messages_udp(buf, MAX_LINE_SIZE);
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "ROU") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		logged_in = 0;
		memset(UID, 0, sizeof(UID));
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else {
		end_session(EXIT_FAILURE);	
	}
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
void get_all_groups(char ****list) {
	char buf[GIANT_SIZE];
	char *command, *num_groups;

	sprintf(buf, "%s %s\n", "GLS", UID);
	exchange_messages_udp(buf, GIANT_SIZE);

	command = strtok(buf, " ");
	num_groups = strtok(NULL, " ");

	if (strcmp(command, "RGL") || (atoi(num_groups) == 0 && strcmp(num_groups, "0"))) {
		end_session(EXIT_FAILURE);
	} 
	
	*list = parse_groups(buf, atoi(num_groups));

}

/*	Subscribes current user to the specified group
	Input: A valid GID and a group name
	Returns: one of the following integer status codes:
	- OK: if the subscription was successful
	- NEW: if a group was created
	- E_SR: if the provided user is invalid
	- E_GNAME: if the proivdade group name is invalid
	- E_FULL: if a new group could not be created
	- NOK: if another error occurs
*/
int subscribe_group(char *gid, char *gName) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	printf("%s\n", UID);

	/* add a zero on the left if gid = 0 for new group creation */
	if (!strcmp(gid, "0")) {
		char *aux = gid;
		gid = (char *) malloc(sizeof(*aux) + 1);
		gid[0] = '0';
		strcpy(gid + 1, aux);
	}

	sprintf(buf, "%s %s %s %s\n", "GSR", UID, gid, gName);


	exchange_messages_udp(buf, MAX_LINE_SIZE);

	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RGS") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "NEW")) {
		return STATUS_NEW_GROUP;
	} else if (!strcmp(status, "E_USR")) {	/* Not logged in */
		return STATUS_USR_INVALID;
	} else if (!strcmp(status, "E_GRP")) {	/* Bad names */
		return STATUS_GID_INVALID;
	} else if (!strcmp(status, "E_GNAME")) {
		return STATUS_GNAME_INVALID;
	} else if (!strcmp(status, "E_FULL")) {
		return STATUS_GROUPS_FULL;
	} else if (!strcmp(status, "NOK")) { /* NOTE: This is activated, for example, when a negative UID is given */
		return STATUS_NOK;
	} else {
		end_session(EXIT_FAILURE);
	}

}

/*	Unsubscribes current user from the specified group
	Input: A valid GID and a group name
	Returns: one of the following integer status codes:
	- OK: if the unsubscription was successful
	- E_USR: if the provided user is invalid
	- E_GNAME: if the proivdade group name is invalid
	- NOK: if another error occurs
*/
int unsubscribe_group(char *gid) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "GUR", UID, gid);

	exchange_messages_udp(buf, MAX_LINE_SIZE);

	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RGU") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "E_USR")) {
		return STATUS_USR_INVALID;
	} else if (!strcmp(status, "E_GRP")) {
		return STATUS_GID_INVALID;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else {
		end_session(EXIT_FAILURE);
	}
}

int get_subscribed_groups(char ****list) {
	char buf[GIANT_SIZE];
	char *command, *num_groups;

	sprintf(buf, "%s %s\n", "GLM", UID);
	exchange_messages_udp(buf, GIANT_SIZE);

	command = strtok(buf, " ");
	num_groups = strtok(NULL, " ");

	if (!strcmp(num_groups, "E_USR")) {
		return STATUS_USR_INVALID;
	}

	if (strcmp(command, "RGM") || (atoi(num_groups) == 0 && strcmp(num_groups, "0"))) {
		end_session(EXIT_FAILURE);
	} 
	
	*list = parse_groups(buf, atoi(num_groups));

	return STATUS_OK;

}

/*	Parses a response from the server regarding group listing
	to an array of arrays of 2 string of the format
	{GID, Gname}, one for each available group. The last entry
	has GID = ""
	Input: 
	- buf: the buffer with the response
	Output:
	- the array of {GID, Gname} elements
*/
char ***parse_groups(char *buf, int num_groups) {
	char ***response = NULL;
	
	/* Allocate and fill response entries with each GID and GNAME */
	response = (char***) malloc(sizeof(char**) * num_groups + 1);
	for (int i = 0; i < num_groups + 1; i++) {
		response[i] = (char **) malloc(sizeof(char*) * 2);
		for (int j = 0; j < 2; j++) {
			response[i][j] = (char *) malloc(sizeof(char) * 24);
		}
	}

	for (int i = 0; i < num_groups; i++) {
		response[i][0] = strtok(NULL, " ");
		response[i][1] = strtok(NULL, " ");
		strtok(NULL, " ");
	}

	response[num_groups][0] = "";

	return response;
}

void set_gid(char *gid) {
	strncpy(GID, gid, 3);
}

char* get_gid() {
	return GID;
}

/*	Parses a response from the server regarding listing
	users from a group.
	Input: 
	- list: the list to be filled with the UID's
	Output: None
*/
int get_uids_group(char ***list) {

	char *buf = (char *) malloc(sizeof(char) * GIANT_SIZE);
	char *command, *status, *group_name;

	sprintf(buf, "%s %s\n", "ULS", GID);
	exchange_messages_tcp(&buf, strlen(buf) * sizeof(char));

	command = strtok(buf, " ");
	status = strtok(NULL, " ");
	group_name = strtok(NULL, " ");

	if (strcmp(command, "RUL")) {
		printf("Here 1\n");
		end_session(EXIT_FAILURE);
	} 

	if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} 

	if (group_name == NULL) {
		printf("Here 2\n");
		end_session(EXIT_FAILURE);
	} 

	*list = parse_uids(buf);

	return STATUS_OK;

}

/*	Parses a response from the server regarding listing
	users from a group.
	Input: 
	- buf: the buffer with the response
	Output:
	- the array of {UID} elements. The last element is an 
	empty string.
*/
char **parse_uids(char *buf) {
	char **response = NULL;
	ssize_t base_size = GIANT_SIZE;
	char *token;
	int parsed_tokens = 0;
	
	/* Allocate and fill response entries with each UID */
	response = (char**) malloc(sizeof(char*) * base_size);

	for (int i = 0; i < base_size; i++) {
		response[i] = (char *) malloc(sizeof(char*) * 6);
	}

	while ((token = strtok(NULL, " ")) != NULL) {
		response[parsed_tokens ++] = token;
		if (parsed_tokens % base_size == 0) {
			response = (char **) realloc(response, (sizeof(response) + base_size) * sizeof(char *));
		}
	}

	/* Deal with '\n' at the end */
	if (parsed_tokens > 0) {
		response[parsed_tokens - 1][strlen(response[parsed_tokens - 1]) - 1] = '\0';
	}

	response[parsed_tokens] = "";

	return response;
}


int post(char* text, char *mid, char *filename) {
	char *buf = (char *) malloc(sizeof(char) * GIANT_SIZE);
	unsigned char *content;
	char command[MAX_ARG_SIZE], status[MAX_ARG_SIZE];
	FILE *file;
	ssize_t filesize;
	ssize_t initial_size;

	if (filename == NULL) { // no filename provided
		sprintf(buf, "%s %s %s %ld %s\n", "PST", UID, GID, strlen(text), text);

	} else if ((file = fopen(filename, "rb"))) { // filename provided
		fseek(file, 0, SEEK_END);
		filesize = ftell(file);
		fseek (file, 0, SEEK_SET);

		content = (unsigned char *) malloc (filesize * sizeof(unsigned char *));
		if (content) {
			fread(content, sizeof(unsigned char), filesize, file);
		}
		fclose(file);

		buf = (unsigned char *) realloc(buf, (GIANT_SIZE + filesize) * sizeof(char));
		sprintf(buf, "%s %s %s %ld %s %s %ld ", "PST", UID, GID, strlen(text), text, filename, filesize);
		initial_size = strlen(buf) * sizeof(char);

		char *ptr = buf + initial_size;
		int i;
		for (i = 0; i < filesize; i++) {
			sprintf(ptr + i, "%c", content[i]);
		}
		
		ptr[i] = '\n';

		//printf("Sent: %s\n, Size: %lu\n", buf, strlen(buf));
	} else {	
		return FAIL;
	}

	exchange_messages_tcp(&buf, initial_size + filesize + 1);

	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RPT") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	}

	if (atoi(status) == 0 || strlen(status) != 4) {
		exit(EXIT_SUCCESS);
	}

	strcpy(mid, status);
	return STATUS_OK;
}

int retrieve(char *mid, char ****list) {

	char *buf = (char *) malloc(sizeof(char) * GIANT_SIZE);
	char *command, *status, *num_messages;
	char *saveptr;

	sprintf(buf, "%s %s %s %s\n", "RTV", UID, GID, mid);
	exchange_messages_tcp(&buf, strlen(buf) * sizeof(char));

	command = strtok_r(buf, " ", &saveptr);
	status = strtok_r(NULL, " ", &saveptr);
	num_messages = strtok_r(NULL, " ", &saveptr);


	if (strcmp(command, "RRT")) {
		end_session(EXIT_FAILURE);
	} 

	if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else if (!strcmp(status, "EOF")) {
		return STATUS_EOF;
	} 

	if (atoi(num_messages) == 0) {
		end_session(EXIT_FAILURE);
	} 

	printf("Numero de mensagens: %d\n", atoi(num_messages));

	*list = parse_messages(saveptr, atoi(num_messages));

	return STATUS_OK;

}

/*
*/
char ***parse_messages(char *buf, int num_messages) {

	char ***response = NULL;
	char *content, *ptr = buf;
	char *saveptr;
	ssize_t text_size;
	FILE *file;

	printf("Ye 1\n");
	
	/* Allocate and fill response entries  */
	response = (char***) malloc((sizeof(char**) * num_messages) + 1);
	for (int i = 0; i < num_messages; i++) {
		response[i] = (char **) malloc(sizeof(char*) * 2);

		strtok(ptr, " ");
		strtok(NULL, " ");

		printf("Ye 2\n");

		int text_size = atoi(strtok(NULL, " "));

		if (text_size <= 0) {
			exit(EXIT_FAILURE);
		}

		printf("Ye 3\n");

		//response[i][0] = (char *) malloc(sizeof(char) * (text_size + 1));
		//int j;
		//for (j = 0;  < text_size; j++) {
		//	response[i][0][j] = *(ptr + j);
		//}
		//response[i][0][j] = '\0'; 


		printf("Ye 4\n");

		if (strcmp((ptr = strtok(ptr + text_size, " ")), "/")) {
			continue;
		}

		printf("Ye 5\n");

		response[i][1] = (char *) malloc(sizeof(char) * 25);
		response[i][1] = strtok(NULL, " ");

		printf("Ye 6\n");
		
		int file_size = atoi(strtok(NULL, " "));

		if (file_size <= 0) {
			exit(EXIT_FAILURE);
		}

		printf("Ye 7\n");

		file = fopen(response[i][1], "wb");
		if (file == NULL){
			exit(EXIT_FAILURE);
		}

		printf("Ye 8\n");

		content = strtok(NULL, " ");
		fwrite(content, sizeof(char), file_size, file); // Check sys call result

		printf("Ye 9\n");

		ptr = content + file_size;
	}

	response[num_messages] = NULL;

	printf("Ye 10\n");

	return response;
}


/* The message in buf to the server through the UDP socket 
	and puts a response of size max_rcv_size in buf 
	Input:
	- buf: a buffer that contains the message to be sent and that will
	contained the received message
	- max_rcv_size: maximum size of the response
*/
void exchange_messages_udp(char *buf, ssize_t max_rcv_size) {
	
	if (sendto(udp_socket, buf, strlen(buf), 0, res_udp->ai_addr, res_udp->ai_addrlen) != strlen(buf) * sizeof(char)) {
		exit(EXIT_FAILURE);
	}

	memset(buf, 0, strlen(buf) * sizeof(char));
	
	if (recvfrom(udp_socket, buf, max_rcv_size, 0, (struct sockaddr*) &addr, &addrlen) <= 0) {
		exit(EXIT_FAILURE);
	}
	
	// DEBUG :
	//printf("Received: %s\n", buf);
	// NOTE : must the client close the socket? or the server?
	
}

/*	Sends the message in buf to the server through the UDP socket 
	and puts a response of size max_rcv_size in buf 
	Input:
	- buf: a buffer that contains the message to be sent and that will
	contained the received message
	- max_rcv_size: maximum size of the response
*/
void exchange_messages_tcp(char **buf, ssize_t num_bytes) {

	setup_tcp();

	ssize_t num_bytes_left = num_bytes;
	ssize_t num_bytes_written, num_bytes_read, base_bytes;
	char *aux = *buf;
	int i = 0;
	while (num_bytes_left > 0) {
		num_bytes_written = write(tcp_socket, aux, num_bytes_left);
		if (num_bytes_written < 0) {
			printf("What 1?\n");
			exit(EXIT_FAILURE);
		}
		num_bytes_left -= num_bytes_written;
		aux += num_bytes_written;
	}

	printf("Sent: %s\n", *buf);

	memset(*buf, '\0', sizeof(*buf) * sizeof(char));

	num_bytes_left = num_bytes;  
	base_bytes = num_bytes;
	aux = *buf;
	while (1) {
		num_bytes_read = read(tcp_socket, aux, num_bytes_left);
		if (num_bytes_read == -1) {
			printf("What 2?\n");
			printf("Manoooo, o que é que se passou mano? %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		else if (num_bytes_read == 0) {
			*aux = '\0';
			break;
		}
		aux += num_bytes_read;
		num_bytes_left -= num_bytes_read;
		if (num_bytes_left == 0) {
			int offset = aux - (*buf);
			*buf = (char *) realloc(*buf, sizeof(*buf) + base_bytes);
			aux = (*buf) + offset;
			num_bytes_left = base_bytes;
		}
	}

	// Debug
	printf("Received: %s\n", *buf);
}

void end_session(int status) {
	close(udp_socket);
	exit(status);
}

int is_logged_in () {
	return logged_in;
}