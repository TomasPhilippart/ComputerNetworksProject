#include "user_api.h"
#include "../../constants.h"
#include "../../aux_functions.h"

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
#include<math.h>


// NOTE check if every response ends with /n
// NOTE check extra token on response
// NOTE check filesize
// NOTE pass error string to end session
// NOTE check all regexes!!!

/* Default server ip and port */
char *server_ip = NULL;
char server_port[MAX_PORT_SIZE + 1] = "58043";

/* User ID, password, group ID and flag for when a user is logged in */
char UID[UID_SIZE + 1] = ""; // 5 digit numeric
char password[PASSWORD_SIZE + 1] = ""; // 8 alphanumeric characters
char GID[GID_SIZE + 1] = ""; // 2 digit numeric (01-99)
int logged_in = FALSE;

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
void send_message_tcp(char *buf, ssize_t num_bytes);
int rcv_message_tcp(char *buf, int num_bytes);
int start_timer(int fd);
int stop_timer(int fd);

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
		printf("Error: Failed to create UDP socket.\n");
		exit(EXIT_FAILURE);
	}

	memset(&hints_udp, 0, sizeof(hints_udp));
	hints_udp.ai_family = AF_INET; 	/* IPv4 */
	hints_udp.ai_socktype = SOCK_DGRAM; /* UDP socket */

	addrlen = sizeof(addr); /* for receiving messages */

	if (getaddrinfo(server_ip, server_port, &hints_udp, &res_udp) != 0) {
		printf("Error: DNS couldn't resolve server's IP address for UDP connection.\n");
		exit(EXIT_FAILURE);
	}
}

void setup_tcp() {

	/* Create TCP socket */
	tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_socket == -1) {
		printf("Error: Failed to create TCP socket.\n");
		exit(EXIT_FAILURE);
	}

	memset(&hints_tcp, 0, sizeof(hints_tcp));
	hints_tcp.ai_family = AF_INET; /* IPv4 */
	hints_tcp.ai_socktype = SOCK_STREAM; /* UDP socket */

	addrlen = sizeof(addr); /* for receiving messages */

	if (getaddrinfo(server_ip, server_port, &hints_tcp, &res_tcp) != 0) {
		printf("Error: DNS couldn't resolve server's IP address for TCP connection.\n");
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
		return TRUE;
	} 
	return FALSE;
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
		return TRUE;
	}
	return FALSE;
}

/*	Checks if port points to a string with a valid port number.
	Input:
	- port: string to be checked 
    Output: 1 if port is a valid port, 0 otherwise.
*/
int validate_port(char *port) {
	int port_number = atoi(port);
	if (port_number > 0 && port_number <= 65535) {
		strcpy(server_port, port);
		return TRUE;
	} 
	return FALSE;
}

/*	Registers a user
	Input:
	- UID: a 5 char numerical string
	- pass: a 8 char alphanumerical string
	Output: 
	- STATUS_OK, if the registration was successful
	- STATUS_DUP, if the registration UID is duplicated
	- STATUS_NOK, if UID is invalid or pass is wrong
	- STATUS_ERR: if the message did not arrive correctly at the server
*/
int register_user(char *user, char *pass) {
	char buf[MAX_LINE_SIZE] = "";
	char status[MAX_ARG_SIZE] = "";
	char command[MAX_ARG_SIZE] = "";
	sprintf(buf, "%s %s %s\n", "REG", user, pass);

	exchange_messages_udp(buf, strlen(buf));
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);

	if (num_tokens < 1) {
		end_session(EXIT_FAILURE);
	}
	if (!strcmp(status, "ERR")) {
		return STATUS_ERR;
	}
	if (num_tokens != 2 || strcmp(command, "RRG") != 0) {
		printf("Error: Bad message received, %s.\n", buf);
		end_session(EXIT_FAILURE);
	}

	// REVIEW
	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "DUP")) {
		return STATUS_DUP;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else {
		printf("Error: Unexpected status received, status = %s\n.", status);
		end_session(EXIT_FAILURE);	
	}
}

/*	Unregisters a user
	Input:
	- UID: a valid UID (a 5 char numerical string)
	- pass: a valid pass (8 char alphanumerical string)
	Output: 
	- STATUS_OK, if the unregistration was succesful
	- STATUS_NOK, if UID is invalid or pass is wrong 
	- STATUS_ERR: if the message did not arrive correctly at the server
*/
int unregister_user(char *user, char *pass) {
	char buf[MAX_LINE_SIZE] = "";
	char status[MAX_ARG_SIZE] = "";
	char command[MAX_ARG_SIZE] = "";
	
	snprintf(buf, sizeof(buf), "%s %s %s\n", "UNR", user, pass);
	exchange_messages_udp(buf, strlen(buf));

	int num_tokens = sscanf(buf, "%s %s", command, status);
	if (num_tokens != 2 || strcmp(command, "RUN") != 0) {
		printf("Error: Invalid message format, %s.\n", buf);
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		logged_in = FALSE;
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else if (!strcmp(status, "ERR")) {
		return STATUS_ERR;
	} else {
		printf("Error: Unexpected status received, %s.\n", status);
		end_session(EXIT_FAILURE);
	}
}

/*	Login a user 
	Input:
	- UID: a valid UID 
	- pass: a valid pass 
	Output: A integer s.t.:
	- STATUS_OK: if the login was successful
	- STATUS_NOK: invalid user or wrong pass
	- STATUS_ERR: if the message did not arrive correctly at the server
*/
int login(char *user, char *pass) {
	char buf[MAX_LINE_SIZE] = "";
	char status[MAX_ARG_SIZE] = "";
	char command[MAX_ARG_SIZE] = "";
	sprintf(buf, "%s %s %s\n", "LOG", user, pass);

	exchange_messages_udp(buf, strlen(buf));
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RLO") != 0) {
		printf("Error: Invalid message format, %s.\n", buf);
		end_session(EXIT_FAILURE);
	}
	// printf("So i received %s\n", status);
	if (!strcmp(status, "OK")) {
		strncpy(UID, user, UID_SIZE + 1);
		strncpy(password, pass, PASSWORD_SIZE + 1);
		logged_in = TRUE;
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else if (!strcmp(status, "ERR")) {
		return STATUS_ERR;
	} else {
		printf("Error: Unexpected status received, %s.\n", status);
		end_session(EXIT_FAILURE);	
	}
}

/*	Logout
	Input:
	- UID: a valid UID 
	- pass: a valid pass 
	Output: A integer s.t.:
	- STATUS_OK: if the logout was successful
	- STATUS_NOK: if the logout was unsuccessful
	- STATUS_ERR: if the message did not arrive correctly at the server
*/
int logout() {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "OUT", UID, password);

	exchange_messages_udp(buf, strlen(buf));
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "ROU") != 0) {
		printf("Error: Invalid message format, %s\n", buf);
		end_session(EXIT_FAILURE);
	}
	if (!strcmp(status, "OK")) {
		logged_in = FALSE;
		memset(UID, 0, sizeof(UID) * sizeof(char));
		return STATUS_OK;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else {
		printf("Error: Unexpected status received, %s.\n", status);
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
	char buf[MAX_BUF_SIZE] = "";
	char command[COMMAND_SIZE + 2] = "";
	char num_groups[GID_SIZE + 2] = "";
	int num_tokens;
	char *aux;

	sprintf(buf, "%s\n", "GLS");
	exchange_messages_udp(buf, MAX_BUF_SIZE);

	num_tokens = sscanf(buf, "%" STR(5) "s %" STR(4) "s ", command, num_groups);

	if (num_tokens < 2) {
		printf("Error: Invalid message format, %s.\n", buf);
		end_session(EXIT_FAILURE);
	}
								
	if (strcmp(command, "RGL") || (atoi(num_groups) == 0 && strcmp(num_groups, "0"))) {
		printf("Error: Invalid message format, %s.\n", buf);
		end_session(EXIT_FAILURE);
	} 

	/* advance pointer to group section of server response for parsing */
	aux = buf + (strlen(command) + strlen(num_groups) + 1) * sizeof(char);
	*list = parse_groups(aux, atoi(num_groups));

}

/*	Subscribes current user to the specified group
	Input: A valid GID and a group name
	Returns: one of the following integer status codes:
	- STATUS_OK: if the subscription was successful
	- STATUS_NEW_GROUP: if a group was created
	- STATUS_USR_INVALID: if the provided user is invalid
	- STATUS_GNAME_INVALID: if the provided group name is invalid
	- STATUS_GROUPS_FULL: if there are already 99 groups
	- STATUS_NOK: if another error occurs
	- STATUS_ERR: if the message did not arrive correctly at the server
*/
int subscribe_group(char *gid, char *gName) {
	char buf[MAX_LINE_SIZE] = "";
	char status[MAX_ARG_SIZE] = "";
	char command[MAX_ARG_SIZE] = "";
	char new_gid[GID_SIZE + 1] = "";

	/* add a zero on the left if gid = 0 for new group creation */
	if (!strcmp(gid, "0")) {
		char *aux = gid;
		
		if ((gid = (char *) malloc(sizeof(char) * (strlen(aux) + 1))) == NULL) {
			printf("Error : malloc");
			exit(EXIT_FAILURE);
		}
		gid[0] = '0';
		strcpy(gid + 1, aux);
	}
	
	sprintf(buf, "%s %s %s %s\n", "GSR", UID, gid, gName);
	
	exchange_messages_udp(buf, strlen(buf));

	int num_tokens = sscanf(buf, "%s %s %s\n", command, status, new_gid);
	if (strcmp(command, "RGS") != 0) {
		printf("Error: Invalid message format, %s.\n", buf);
		end_session(EXIT_FAILURE);
	}
	

	if (!strcmp(status, "OK")) {
		return STATUS_OK;
	} else if (!strcmp(status, "NEW")) {
		strcpy(gid, new_gid);
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
		printf("Error: Unexpected status received, %s\n", status);
		end_session(EXIT_FAILURE);
	}

}

/*	Unsubscribes current user from the specified group
	Input: A valid GID and a group name
	Returns: one of the following integer status codes:
	- OK: if the unsubscription was successful
	- E_USR: if the provided user is invalid
	- E_GNAME: if the provided group name is invalid
	- NOK: if another error occurs
*/
int unsubscribe_group(char *gid) {
	char buf[MAX_LINE_SIZE] = "";
	char status[MAX_ARG_SIZE] = "";
	char command[MAX_ARG_SIZE] = "";
	
	sprintf(buf, "%s %s %s\n", "GUR", UID, gid);

	exchange_messages_udp(buf, strlen(buf));
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RGU") != 0) {
		printf("Error : unsubscribe group, bad message received, %s.\n", buf);
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		if (!strcmp(gid, GID)) {
			memset(GID, 0, sizeof(GID) * sizeof(char));
		}
		return STATUS_OK;
	} else if (!strcmp(status, "E_USR")) {
		return STATUS_USR_INVALID;
	} else if (!strcmp(status, "E_GRP")) {
		return STATUS_GID_INVALID;
	} else if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else if (!strcmp(status, "ERR")) {
		return STATUS_ERR;
	} else {
		printf("Error : unexpected status received, status = %s\n", status);
		end_session(EXIT_FAILURE);
	}
}

/*	Fills list with a list of the user subscribed groups
	Input:
	- list: the list to be filled 
	Output:
	- STATUS_OK: if the groups were successfully fetched
	- STATUS_USR_INVALID: if the current user is invalid
	- STATUS_ERROR: if there was in the message reception by the server
*/
int get_subscribed_groups(char ****list) {
	char buf[MAX_BUF_SIZE] = "";
	char command[COMMAND_SIZE + 2] = "";
	char num_groups[GID_SIZE + 3] = "";
	int num_tokens;
	char *aux;

	memset(buf, 0, MAX_BUF_SIZE);
	sprintf(buf, "%s %s\n", "GLM", UID);	
	exchange_messages_udp(buf, strlen(buf));

	num_tokens = sscanf(buf, "%" STR(COMMAND_SIZE) "s %" STR(5) "s ", command, num_groups);

	if (num_tokens < 2) {
		printf("Error: Invalid message format, %s.\n", buf);
		end_session(EXIT_FAILURE);
	}

	if (strcmp(command, "RGM")) { 
		printf("Error: Invalid message format, %s.\n", buf);
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(num_groups, "E_USR")) {
		return STATUS_USR_INVALID;
	} else if (!strcmp(num_groups, "ERR")) {
		return STATUS_ERR;
	}

	if (!parse_regex(num_groups, "^[0-9]{0,2}$")) {
		printf("Error: Invalid number of groups, %s.\n", num_groups);
		end_session(EXIT_FAILURE);
	} 
	
	/* advance pointer to group section of server response for parsing */
	aux = buf + strlen(command) + strlen(num_groups) + 1;
	*list = parse_groups(aux, atoi(num_groups));

	return STATUS_OK;

}

/*	Parses a response from the server regarding group listing
	to an array of arrays of 2 string of the format {GID, Gname}, 
	one for each available group, with the last entry being NULL.
	Input: 
	- buf: the buffer with the response of the type [ GID GName MID]*
	- num_groups: the number of entries of the list
	Output: 
	- the array of {GID, Gname} elements.
*/
char ***parse_groups(char *buf, int num_groups) {
	
	/* Allocate and fill response entries with each GID and GNAME */
	char ***response;
	if ((response = (char***) malloc(sizeof(char**) * (num_groups + 1))) == NULL) {
		printf("Error : malloc");
		exit(EXIT_FAILURE);
	}

	char mid[MID_SIZE + 1] = "";
	int num_tokens;
	char *aux = buf;

	for (int i = 0; i < num_groups; i++) {
		if ((response[i] = (char **) malloc(sizeof(char*) * (21))) == NULL) {
			printf("Error : malloc");
			exit(EXIT_FAILURE);
		}
		for (int j = 0; j < 2; j++) {
			if ((response[i][j] = (char *) malloc(sizeof(char) * (MAX_FNAME + 1))) == NULL) {
				printf("Error : malloc");
				exit(EXIT_FAILURE);
			}
		}
	}
	
	for (int i = 0; i < num_groups; i++) {
		
		num_tokens = sscanf(aux, " %s %s %s", response[i][0], response[i][1], mid);
		
		if (num_tokens != 3) {
			printf("Error: Invalid message format, %s.\n", buf);
			end_session(EXIT_FAILURE);
		}
		/* advance buf pointer 3 tokens */
		aux += (strlen(response[i][0]) + strlen(response[i][1]) + strlen(mid) + 3) * sizeof(char);
	}
	
	/* Ensure that there are exactly num_messages messages  */
	if (*(aux) != '\n') {
		printf("Error: Buffer doesn't end in a \\n\n");
		end_session(EXIT_FAILURE);
	}

	response[num_groups] = NULL;

	return response;
}

void set_gid(char *gid) {
	strncpy(GID, gid, GID_SIZE + 1);
}

char* get_gid() {
	return GID;
}

/*	Fetches a list with the UIDS of users subscribed
	to the current group.
	Input: 
	- list: the list to be filled with entries of the form [[UID]]
	Output: None
*/
int get_uids_group(char ****list) {

	char group_name[MAX_ARG_SIZE] = "";
	char buf[MAX_BUF_SIZE] = "";
	Buffer rcv_buffer = new_buffer(MAX_BUF_SIZE);
	int base_size = 100;	/* no of entries in which the list is incremented */
	int parsed_groups = 0;
	
	if (rcv_buffer == NULL) {
		printf("Error during buffer allocation.\n");
		exit(EXIT_FAILURE);
	}

	memset(buf, 0, MAX_BUF_SIZE);
	sprintf(buf, "ULS %." STR(MAX_ARG_SIZE) "s\n", GID); 

	// NOTE: check these
	setup_tcp();
	send_message_tcp(buf, strlen(buf));	
	write_to_buffer(rcv_buffer, 31, rcv_message_tcp);

	if (parse_regex(rcv_buffer->buf, "^ERR\\\n$") && (strlen("ERR\n") == rcv_buffer->tail)) {
		destroy_buffer(rcv_buffer);
		return STATUS_ERR;
	} else if (parse_regex(rcv_buffer->buf, "^RUL NOK\\\n$") && (strlen("RUL NOK\n$") == rcv_buffer->tail)) {
		destroy_buffer(rcv_buffer);
		return STATUS_NOK;
	} else if (!parse_regex(rcv_buffer->buf, "^RUL OK " GNAME_EXP)) {
		destroy_buffer(rcv_buffer);
		exit(EXIT_FAILURE);
	}

	sscanf(rcv_buffer->buf, "%*s %*s %s", group_name);
	
	if (!(*list = (char ***) malloc(sizeof(char **) * base_size))) {
		destroy_buffer(rcv_buffer);
		exit(EXIT_FAILURE);
	}
	memset(*list, 0, sizeof(char **) * base_size);

	/* flush "RUL OK GNAME" */
	flush_buffer(rcv_buffer, 7 + strlen(group_name));	

	while (1) {
		/* fetch remaining bytes to parse a " UID" token */
		if (rcv_buffer->tail < UID_SIZE + 1) {

			if (write_to_buffer(rcv_buffer, 1 + UID_SIZE - rcv_buffer->tail, rcv_message_tcp) < 1 + UID_SIZE - rcv_buffer->tail) {	
				break;
			}
		}
		
		if (!parse_regex(rcv_buffer->buf, "^ " UID_EXP)) {
			free_list(*list, 1);
			destroy_buffer(rcv_buffer);
			exit(EXIT_FAILURE);
		}

		if (((*list)[parsed_groups] = (char **) malloc(sizeof(char *))) == NULL) {
			printf("Error : malloc");
			exit(EXIT_FAILURE);
		}
		
		if (((*list)[parsed_groups][0] = (char *) malloc(sizeof(char) * (UID_SIZE + 1))) == NULL) {
			printf("Error : malloc");
			exit(EXIT_FAILURE);
		}
		
		sscanf(rcv_buffer->buf, " %s", (*list)[parsed_groups][0]);

		if (!atoi((*list)[parsed_groups][0])) {
			free_list(*list, 1);
			destroy_buffer(rcv_buffer);
			exit(EXIT_FAILURE);
		}

		/* flush current " UID" token */
		flush_buffer(rcv_buffer, UID_SIZE + 1);	
	
		if ((parsed_groups + 1) % base_size == 0) {
			*list = (char ***) realloc(*list, sizeof(char **) * (parsed_groups + base_size));
			memset(**list + (parsed_groups) * sizeof(char **), 0, base_size);
		}

		parsed_groups++;
	
	}

	if (!parse_regex(rcv_buffer->buf, "^\\\n$")) {
		free_list(*list, 1);
		destroy_buffer(rcv_buffer);
		exit(EXIT_FAILURE);
	}

	return STATUS_OK;
}

/*	Post a message with text (and possibly a file with name filename),
	saving its MID to mid 
	Input: 
	- text: the text to be posted
	- mid: will save the message MID
	- filename: name of the file to be posted
	Output:
	- STATUS_OK: if posting was succesful
	- STATUS_NOK: if there was an error
	- STATUS_ERR: if the message did not arrive correctly at the server
*/
int post(char* text, char *mid, char *filename) {

	char buf[MAX_BUF_SIZE] = "";
	char command[MAX_ARG_SIZE] = "";
	char status[MAX_ARG_SIZE] = "";
	FILE *file;
	ssize_t bytes_read, file_size;
	int rcv_size;

	// NOTE: check this
	setup_tcp();	
	memset(buf, 0, MAX_BUF_SIZE);
	
	if (filename == NULL) {  
		sprintf(buf, "PST %." STR(MAX_ARG_SIZE) "s %." STR(MAX_ARG_SIZE) "s %ld %." STR(MAX_TSIZE) "s\n", 
																				UID, GID, strlen(text), text); 
		send_message_tcp(buf, strlen(buf) * sizeof(char));	// NOTE: check this

	} else if ((file = fopen(filename, "rb"))) { // filename provided

		/* Get size of file data */
		if ((fseek(file, 0, SEEK_END) != 0) || 
			((file_size = ftell(file)) == -1) ||
			(fseek(file, 0, SEEK_SET) != 0)) {
			exit(EXIT_FAILURE);
		}

		/* Check maximum filesize */
		if (file_size >= pow(10, MAX_FSIZE)) {
			exit(EXIT_FAILURE);
		}
		
		// NOTE check this
		sprintf(buf, "PST %." STR(MAX_ARG_SIZE) "s %." STR(MAX_ARG_SIZE) "s %ld %." STR(MAX_TSIZE) "s %." 
							  STR(MAX_ARG_SIZE) "s %ld ", UID, GID, strlen(text), text, filename, file_size); 
		send_message_tcp(buf, strlen(buf) * sizeof(char));	// NOTE: check this
		
		int total = 0;
		while (1) {
			bytes_read = fread(buf, sizeof(char), MAX_BUF_SIZE - 1, file);
			total += bytes_read;
			if (feof(file)) {
				break;
			} else if (ferror(file)) {
				exit(EXIT_FAILURE);
			}
			send_message_tcp(buf, bytes_read);	// NOTE: check this
		}

		buf[bytes_read] = '\n';
		send_message_tcp(buf, bytes_read + 1); // NOTE: check this
		if (fclose(file) != 0) {
			exit(EXIT_FAILURE);
		}

	} else {	
		end_session(EXIT_FAILURE);
	}
	
	memset(buf, 0, sizeof(char) * MAX_BUF_SIZE);
	rcv_size = rcv_message_tcp(buf, MAX_LINE_SIZE - 1);	// NOTE: check this
	buf[rcv_size] = '\0';
	freeaddrinfo(res_tcp);

	if (close(tcp_socket) == -1) {
		exit(EXIT_FAILURE);
	}
	
	if (parse_regex(buf, "^ERR\\\n$") && (strlen("ERR\n") == rcv_size)) {
		return STATUS_ERR;
	} else if (parse_regex(buf, "^RPT NOK\\\n$") && (strlen("RPT NOK\n$") == rcv_size)) {
		return STATUS_NOK;
	} else if (parse_regex(buf, "^RPT [0-9]{" STR(MID_SIZE) "}\\\n") && ((strlen("RPT ") + MID_SIZE + 1) == rcv_size)) {
		sscanf(buf, "%*s %s\n", mid);
		if (!atoi(mid)) {
			exit(EXIT_FAILURE);
		}
		return STATUS_OK;
	} else {
		exit(EXIT_FAILURE);
	}

}

/*	Retrieves up to 20 unread messages from the current
	group and starting from the one with MID mid.
	Input:
	- mid: the MID
	- list: a pointer to be filled with entries of the type
	[GID, Text, [Fname]*], with the last entry being NULL.
	Output:
	- STATUS_OK: if the retrieving was succesful
	- STATUS_NOK: if there was an error
	- STATUS_EOF: if there are no messages to retrieve
	- STATUS_ERR: if the message did not arrive correctly at the server
*/
int retrieve(char *mid, char ****list) {

	char buf[MAX_BUF_SIZE] = "";
	char command[MAX_ARG_SIZE] = "";
	char status[MAX_ARG_SIZE] = "";
	char num_messages[MAX_ARG_SIZE] = "";
	Buffer rcv_buf = new_buffer(MAX_BUF_SIZE); /* This a circular-ish buffer, see aux_functions.c */
	FILE *file;
	int num_tokens, rcv_bytes, excess;

	if (rcv_buf == NULL) {
		exit(EXIT_FAILURE);
	}

	sprintf(buf, "RTV %." STR(MAX_ARG_SIZE) "s %." STR(MAX_ARG_SIZE) "s %." STR(MAX_ARG_SIZE) "s\n", UID, GID, mid); 

	// NOTE check these
	setup_tcp(); 
	send_message_tcp(buf, strlen(buf));	

	/* Parse "RRT status N" which has its maximum size when status = OK */
	reset_buffer(rcv_buf);
	write_to_buffer(rcv_buf, strlen("RRT OK ") + MAX_NUM_MSG_DIGITS,  rcv_message_tcp); // NOTE: return value??
	
	// NOTE: use regex to parse spaces, one for each case!!!*/
	num_tokens = sscanf(rcv_buf->buf, "%" STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s %" 
								 STR(MAX_ARG_SIZE) "s\n", command, status, num_messages);


	if ((num_tokens == 1) && !strcmp(command, "ERR")) {
		destroy_buffer(rcv_buf);
		return STATUS_ERR;
	} else if ((num_tokens == 2) && !strcmp(command, "RRT") && !strcmp(status, "NOK")) {
		destroy_buffer(rcv_buf);
		return STATUS_NOK;
	} else if ((num_tokens == 2) && !strcmp(command, "RRT") && !strcmp(status, "EOF")) {
		destroy_buffer(rcv_buf);
		return STATUS_EOF;
	} else if (!((num_tokens == 3)  && !strcmp(command, "RRT") && !strcmp(status, "OK") \
									&& parse_regex(num_messages, "^[0-9]{1,}$") && atoi(num_messages) != 0)) {
		destroy_buffer(rcv_buf);
		end_session(EXIT_FAILURE);
	}

	/* Allocate space for resulting list */
	if ((*list = (char ***) malloc (sizeof(char **) * (atoi(num_messages) + 1))) == NULL) {
		end_session(EXIT_FAILURE);
	} 

	for (int j = 0; j < atoi(num_messages); j++) {
		if (((*list)[j] = (char **) malloc(sizeof(char *) * 3)) == NULL) {
			destroy_buffer(rcv_buf);
			free_list(*list, 3);
			end_session(EXIT_FAILURE);
		}
		memset((*list)[j], 0, 3 * sizeof(char *));
	}
	(*list)[atoi(num_messages)] = NULL;

	/* push rest of response to the front of the buffer */
	flush_buffer(rcv_buf, strlen(command) + strlen(status) + strlen(num_messages) + 2);
	write_to_buffer(rcv_buf, MAX(0, 3 + MID_SIZE + UID_SIZE + 3 - rcv_buf->tail), rcv_message_tcp);
	

	for (int i = 0; i < atoi(num_messages); i++) {

		/* Parse [ MID UID Tsize text] */
		if (!parse_regex(rcv_buf->buf, "^ [0-9]{" STR(MID_SIZE) "} [0-9]{" STR(UID_SIZE) "} [0-9]{1,3}")) {
			destroy_buffer(rcv_buf);
			free_list(*list, 3);
			exit(EXIT_FAILURE);
		}
		
		char text_size[4], mid_aux[MID_SIZE + 1], uid_aux[UID_SIZE + 1];
		sscanf(rcv_buf->buf, " %s %s %s", mid_aux, uid_aux, text_size);
	
		flush_buffer(rcv_buf, MID_SIZE + UID_SIZE + strlen(text_size) + 3);
		write_to_buffer(rcv_buf, MAX(0, 1 + atoi(text_size) - rcv_buf->tail), rcv_message_tcp);
	
		if (!parse_regex(rcv_buf->buf, "^ .{0,240}")) {
			destroy_buffer(rcv_buf);
			free_list(*list, 3);
			exit(EXIT_FAILURE);
		}
		
		if (((*list)[i][0] = (char *) malloc(sizeof(char) * (atoi(text_size) + 1))) == NULL) {
			printf("Error : malloc");
			exit(EXIT_FAILURE);
		}
		
		memcpy((*list)[i][0], rcv_buf->buf + 1, atoi(text_size) * sizeof(char));
		(*list)[i][0][atoi(text_size)] = '\0';
		flush_buffer(rcv_buf, 1 + atoi(text_size));
		write_to_buffer(rcv_buf, MAX(0, 2 - rcv_buf->tail), rcv_message_tcp);
		/* Check the existence of a file in the message */
		if (!parse_regex(rcv_buf->buf, "^ /")) {
			write_to_buffer(rcv_buf, MAX(0, 3 + MID_SIZE + UID_SIZE + 3 - rcv_buf->tail), rcv_message_tcp);
			continue;
		}

		flush_buffer(rcv_buf, 2);
		write_to_buffer(rcv_buf, MAX(0, 3 + MAX_FNAME + MAX_FSIZE - rcv_buf->tail), rcv_message_tcp);
	
		/* parse [Fname Fsize data] */
		if (!parse_regex(rcv_buf->buf, "^ [a-zA-Z0-9._-]{1,21}.[a-zA-Z0-9]{3} [0-9]{1,10} ")) {
			destroy_buffer(rcv_buf);
			free_list(*list, 3);
			exit(EXIT_FAILURE);
		}
	
		if ((((*list)[i][1] = (char *) malloc(sizeof(char) * (FILENAME_MAX + 1))) == NULL) ||
			(((*list)[i][2] = (char *) malloc(sizeof(char) * (MAX_FSIZE + 1))) == NULL)) {
			printf("f\n");
			destroy_buffer(rcv_buf);
			free_list(*list, 3);
			exit(EXIT_FAILURE);
		}

		if (atoi((*list)[i][2]) >= pow(10, MAX_FSIZE)) {
			destroy_buffer(rcv_buf);
			free_list(*list, 3);
			exit(EXIT_FAILURE);
		}

		sscanf(rcv_buf->buf, " %s %s ", (*list)[i][1], (*list)[i][2]);
	
		flush_buffer(rcv_buf, 3 + strlen((*list)[i][1]) + strlen((*list)[i][2]));
	
		if ((file = fopen((*list)[i][1], "wb"))) {

			int file_size = atoi((*list)[i][2]);
			int bytes_to_write = MIN(file_size, rcv_buf->tail);
			
			if (fwrite(rcv_buf->buf, sizeof(char), bytes_to_write, file) != bytes_to_write) {
				destroy_buffer(rcv_buf);
				free_list(*list, 3);
				exit(EXIT_FAILURE);
			}
			
			file_size -= bytes_to_write;
			flush_buffer(rcv_buf, bytes_to_write);

			while (file_size != 0) {
				bytes_to_write = MIN(file_size, rcv_buf->size);

				write_to_buffer(rcv_buf, bytes_to_write, rcv_message_tcp);	// NOTE: check this

				if (fwrite(rcv_buf->buf, sizeof(char), bytes_to_write, file) != bytes_to_write) {
					destroy_buffer(rcv_buf);
					free_list(*list, 3);
					exit(EXIT_FAILURE);
				}
				
				reset_buffer(rcv_buf);
				file_size -= bytes_to_write;
			}

			if (fclose(file) != 0) {
				destroy_buffer(rcv_buf);
				free_list(*list, 3);
				exit(EXIT_FAILURE);
			}
		
		} 
		write_to_buffer(rcv_buf, MAX(0, 3 + MID_SIZE + UID_SIZE + 3 - rcv_buf->tail), rcv_message_tcp);
		//printf("Buffer \"%s\"  Tail: %d\n", rcv_buf->buf, rcv_buf->tail);
	}
	
	/* Ensure that the response ended */
	if (!(parse_regex(rcv_buf->buf, "^\\\n$") && (write_to_buffer(rcv_buf, 1, rcv_message_tcp) == 0))) {
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(res_tcp);
	
	if (close(tcp_socket) == -1) {
		exit(EXIT_FAILURE);
	}
	destroy_buffer(rcv_buf);

	return STATUS_OK;
}

/*	Frees a list of elements composed of num_elements strings
	Input: 
	- list: the list
	- num_elements: number of strings in each list element
	Output: None
*/
void free_list(char ***list, int num_elements) {
	
	for (int i = 0; list[i] != NULL; i++) {
		for (int j = 0; j < num_elements; j++) {
			if (list[i][j]) {
				free(list[i][j]);
			}
		}
		free(list[i]);
	}
	free(list);
}


// NOTE: implement a timer!!!
/* The message in buf to the server through the UDP socket 
	and puts a response of size max_rcv_size in buf 
	Input:
	- buf: a buffer that contains the message to be sent and that will
	contained the received message
	- max_rcv_size: maximum size of the response
*/
void exchange_messages_udp(char *buf, ssize_t max_rcv_size) {

	int num_bytes;
	
	
	if (sendto(udp_socket, buf, strlen(buf), 0, res_udp->ai_addr, res_udp->ai_addrlen) != strlen(buf) * sizeof(char)) {
		printf("Error: Failed to send message.\n");
		exit(EXIT_FAILURE);
	}
	
	
	memset(buf, 0, sizeof(buf) * sizeof(char));
	//start_timer(udp_socket);
	if ((num_bytes = recvfrom(udp_socket, buf, MAX_BUF_SIZE, 0, (struct sockaddr*) &addr, &addrlen)) <= 0){
		printf("Error: Failed to receive message.\n");
		exit(EXIT_FAILURE);
	}
	//stop_timer(udp_socket);

	buf[num_bytes] = '\0';

	// DEBUG :
	//printf("Received: %s\n", buf);
	//NOTE : must the client close the socket? or the server?
	
}

/*	Sends the message in buf to the server through the UDP socket 
	and puts a response of size max_rcv_size in buf 
	Input:
	- buf: a buffer that contains the message to be sent and that will
	contained the received message
	- max_rcv_size: maximum size of the response
*/
void send_message_tcp(char *buf, ssize_t num_bytes) {

	//setup_tcp();

	ssize_t num_bytes_left = num_bytes;
	ssize_t num_bytes_written, num_bytes_read, base_bytes, curr_size;
	char *aux = buf;

	while (num_bytes_left > 0) {
		num_bytes_written = write(tcp_socket, aux, num_bytes_left);
		if (num_bytes_written < 0) {
			printf("Error: Failed to write message to TCP socket. Why: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		num_bytes_left -= num_bytes_written;
		aux += num_bytes_written;
	}

	// Debug
	//printf("Sent: %s\n", buf);

}

int rcv_message_tcp(char *buf, int num_bytes) {

	ssize_t num_bytes_read, num_bytes_left;
	char *aux = buf;
	
	num_bytes_left = num_bytes;

	while (num_bytes_left != 0) {
		//start_timer(tcp_socket);
		num_bytes_read = read(tcp_socket, aux, num_bytes_left);
		//stop_timer(tcp_socket);

		if (num_bytes_read == 0) {
			break;
		}
		
		if (num_bytes_read == -1) {
			if (errno == EWOULDBLOCK || errno == EAGAIN || errno == ECONNRESET) {
				break;
			}
			exit(EXIT_FAILURE);
		}
		
		aux += num_bytes_read;
		num_bytes_left -= num_bytes_read;
	}
	return num_bytes - num_bytes_left;
}

void end_session(int status) {
	close(udp_socket);
	close(tcp_socket);

	freeaddrinfo(res_udp);
	if (server_ip != NULL) {
		free(server_ip);
	}
	
	printf("Ending session with status %s\n", status == STATUS_OK ? "SUCCESS" : "FAIL");
	exit(status);
}

int is_logged_in () {
	return logged_in;
}

int start_timer(int fd) {
    struct timeval timeout;

    memset((char *) &timeout, 0, sizeof(timeout)); 
    timeout.tv_sec = 1;

    return (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &timeout, sizeof(struct timeval)));
}

int stop_timer(int fd) {
    struct timeval timeout;
    memset((char *)&timeout, 0, sizeof(timeout)); 
    return (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &timeout, sizeof(struct timeval)));
}