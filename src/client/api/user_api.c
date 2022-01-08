#include "user_api.h"
#include "../../constants.h"

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

// NOTE check malloc syscall return code
// NOTE check if every response ends with /n
// NOTE check extra token on response
// NOTE check filesize
// NOTE pass error string to end session
// NOTE regex instead of atoi
// NOTE freeing server_ip and server_port when they are not altered can be a source of trouble

/* Default server ip and port */
char *server_ip = NULL;
char *server_port = "58043";

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
	hints_udp.ai_family = AF_INET; 	/* IPv4 */
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
	} else if (!strcmp(status, "ERR")) {
		return STATUS_ERR;
	} else {
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
	} else if (!strcmp(status, "ERR")) {
		return STATUS_ERR;
	} else {
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
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "LOG", user, pass);

	exchange_messages_udp(buf, MAX_LINE_SIZE);
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "RLO") != 0) {
		end_session(EXIT_FAILURE);
	}

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

	exchange_messages_udp(buf, MAX_LINE_SIZE);
	
	int num_tokens = sscanf(buf, "%s %s\n", command, status);
	if (num_tokens != 2 || strcmp(command, "ROU") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		logged_in = FALSE;
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
	char buf[MAX_BUF_SIZE];
	char command[COMMAND_SIZE + 2], num_groups[GID_SIZE + 2];
	int num_tokens;
	char *aux;

	sprintf(buf, "%s %s\n", "GLS", UID);
	exchange_messages_udp(buf, MAX_BUF_SIZE);

	num_tokens = sscanf(buf, "%" STR(5) "s %" STR(4) "s ", command, num_groups);

	if (num_tokens < 2) {
		end_session(EXIT_FAILURE);
	}
								 // NOTE: use isnumber()
	if (strcmp(command, "RGL") || (atoi(num_groups) == 0 && strcmp(num_groups, "0"))) {
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
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];

	/* add a zero on the left if gid = 0 for new group creation */
	if (!strcmp(gid, "0")) {
		char *aux = gid;
		gid = (char *) malloc(sizeof(char) * (strlen(aux) + 1));
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
	- E_GNAME: if the provided group name is invalid
	- NOK: if another error occurs
*/
int unsubscribe_group(char *gid) {
	char buf[MAX_LINE_SIZE], status[MAX_ARG_SIZE], command[MAX_ARG_SIZE];
	sprintf(buf, "%s %s %s\n", "GUR", UID, gid);

	exchange_messages_udp(buf, MAX_LINE_SIZE);

	int num_tokens = sscanf(buf, "%s %s\n", command, status); //NOTE: Check this
	if (num_tokens != 2 || strcmp(command, "RGU") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "OK")) {
		if (!strcmp(gid, GID)) {
			memset(GID, 0, sizeof(GID));
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
	char buf[MAX_BUF_SIZE], command[COMMAND_SIZE + 2], num_groups[GID_SIZE + 2];
	int num_tokens;
	char *aux;

	sprintf(buf, "%s %s\n", "GLM", UID);	
	exchange_messages_udp(buf, MAX_BUF_SIZE);

	num_tokens = sscanf(buf, "%" STR(4) "s %" STR(3) "s ", command, num_groups);

	if (num_tokens < 2) {
		end_session(EXIT_FAILURE);
	}

	if (strcmp(command, "RGM")) { 
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(num_groups, "E_USR")) {
		return STATUS_USR_INVALID;
	} else if (!strcmp(num_groups, "ERR")) {
		return STATUS_ERR;
	}

	/* NOTE: use a regex for this, somethings like 123aaa will pass through */
	if ((atoi(num_groups) == 0) && strcmp(num_groups, "0")) {
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
	char ***response = (char***) malloc(sizeof(char**) * (num_groups + 1));
	char mid[MID_SIZE + 1];
	int num_tokens;

	for (int i = 0; i < num_groups; i++) {
		response[i] = (char **) malloc(sizeof(char*) * (GID_SIZE + 1));
		for (int j = 0; j < 2; j++) {
			response[i][j] = (char *) malloc(sizeof(char) * (MAX_FNAME + 1));
		}
	}
	for (int i = 0; i < num_groups; i++) {
		num_tokens = sscanf(buf, " %s %s %s", response[i][0], response[i][1], mid);
		if (num_tokens != 3) {
			end_session(EXIT_FAILURE);
		}
		/* advance buf pointer 3 tokens */
		buf += (strlen(response[i][0]) + strlen(response[i][1]) + strlen(mid) + 3) * sizeof(char);
	}
	
	/* Ensure that there are exactly num_messages messages  */
	if (*(buf) != '\n') {
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
	- list: the list to be filled with the UID's
	Output: None
*/
int get_uids_group(char ***list) {

	char *buf = (char *) malloc(sizeof(char) * MAX_BUF_SIZE);
	char command[COMMAND_SIZE + 1], status[MAX_STATUS_SIZE + 1], group_name[MAX_GNAME + 1];
	char *aux;
	int num_tokens;

	sprintf(buf, "%s %s\n", "ULS", GID);
	exchange_messages_tcp(&buf, strlen(buf) * sizeof(char));
	num_tokens = sscanf(buf, "%" STR(4) "s %" STR(4) "s %" STR(25) "s ", command, status, group_name);
	
	if (num_tokens < 3) {
		free(buf);
		end_session(EXIT_FAILURE);
	}

	if (strcmp(command, "RUL")) {
		free(buf);
		end_session(EXIT_FAILURE);
	} 

	if (!strcmp(status, "NOK")) {
		free(buf);
		return STATUS_NOK;
	} else if (!strcmp(status, "ERR")) {
		free(buf);
		return STATUS_ERR;
	} else if (strcmp(status, "OK")) {
		free(buf);
		end_session(EXIT_FAILURE);
	}

	//NOTE: check group_name??

	/* Advance pointer to UID section of server response */
	aux = buf + (strlen(command) + strlen(status) + strlen(group_name) + 3) * sizeof(char);
	*list = parse_uids(aux);

	free(buf);
	
	return STATUS_OK;
}

/*	Parses a response from the server regarding listing
	users from a group.
	Input: 
	- buf: the buffer with the response of the form [GName [UID ]*]
	Output:
	- the array of {UID} elements whose last element is NULL.
*/
char **parse_uids(char *buf) {
	char **response = NULL;
	ssize_t base_size = 100;
	int parsed_tokens = 0;
	char *token, *ptr = buf;
	
	/* Allocate and fill response entries with each UID */
	response = (char **) malloc(sizeof(char*) * base_size);

	while ((token = strtok_r(ptr, " ", &ptr)) != NULL) {
		response[parsed_tokens] = (char *) malloc(sizeof(char*) * (UID_SIZE + 1));
		strcpy(response[parsed_tokens++], token);
		
		if (parsed_tokens % base_size == 0) {
			response = (char **) realloc(response, (sizeof(response) + base_size) * sizeof(char *));
		}
	}

	/* Deal with '\n' at the end */
	if (parsed_tokens > 0) {
		response[parsed_tokens - 1][strlen(response[parsed_tokens - 1]) - 1] = '\0';
	}

	response[parsed_tokens] = NULL;

	return response;
}

/* Frees a list of UID's */
void free_uids (char **uids) {
	for (int i = 0; uids[i] != NULL; i++) {
		free(uids[i]);
	}
	free(uids);
}

/*	Post a message with text (and possibly a file with name filename),
	saving its MID to mid 
	Input: 
	- text: the text to be posted
	- mid: will save the message MID
	- filename: name of the file to be posted
	Output:
	- STATUS_OK: if the retrieving was succesful
	- STATUS_NOK: if there was an error
	- STATUS_ERR: if the message did not arrive correctly at the server
*/
int post(char* text, char *mid, char *filename) {

	char *buf, *data, *ptr;
	char command[MAX_ARG_SIZE], status[MAX_ARG_SIZE];
	FILE *file;
	ssize_t message_size, filesize;
	
	if (filename == NULL) { // no filename provided
		buf = (char *) malloc(sizeof(char) * MAX_BUF_SIZE); 						// NOTE only the size up until text
		sprintf(buf, "%s %s %s %ld %s\n", "PST", UID, GID, strlen(text), text); // NOTE size delimiters
		message_size = strlen(buf) * sizeof(char);

	} else if ((file = fopen(filename, "rb"))) { // filename provided

		/* Get size of file data */
		fseek(file, 0, SEEK_END);
		filesize = ftell(file);
		fseek(file, 0, SEEK_SET);

		if ((data = (char *) malloc (filesize * sizeof(char)))) {
			fread(data, sizeof(char), filesize, file);
		} else {
			end_session(EXIT_FAILURE);
		}

		fclose(file);

		// NOTE: check filesize??

		buf = (char *) malloc((MAX_BUF_SIZE + filesize) * sizeof(char));									  
		sprintf(buf, "%s %s %s %ld %s %s %ld ", "PST", UID, GID, strlen(text), text, filename, filesize); 

		/* point to beginning of file data */
		ptr = buf + strlen(buf) * sizeof(char);

		/* print data to buffer byte by byte */
		for (int i = 0; i < filesize; i++) {
			sprintf(ptr + i, "%c", data[i]);
		}
		
		ptr[filesize] = '\n';
		message_size = ptr - buf + filesize + 1;
		free(data);

	} else {	
		end_session(EXIT_FAILURE);
	}

	exchange_messages_tcp(&buf, message_size);

	int num_tokens = sscanf(buf, "%s %s\n", command, status);	// NOTE: token size
	if (num_tokens != 2 || strcmp(command, "RPT") != 0) {
		end_session(EXIT_FAILURE);
	}

	if (!strcmp(status, "NOK")) {
		return STATUS_NOK;
	} else if (!strcmp(status, "ERR")) {
		return STATUS_ERR;
	}

	if (atoi(status) == 0 || strlen(status) != MID_SIZE) {
		exit(EXIT_SUCCESS);
	}

	strcpy(mid, status);
	free(buf);
	return STATUS_OK;
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

	char *buf = (char *) malloc(sizeof(char) * MAX_BUF_SIZE);
	char command[COMMAND_SIZE + 2], status[MAX_STATUS_SIZE + 2];
	char *saveptr;
	char *num_messages;
	int num_tokens;

	sprintf(buf, "%s %s %s %s\n", "RTV", UID, GID, mid);
	exchange_messages_tcp(&buf, strlen(buf) * sizeof(char));
	num_tokens = sscanf(buf, "%" STR(5) "s %" STR(4) "s ", command, status);

	if (num_tokens < 2) {			
		end_session(EXIT_FAILURE);
	}

	if (strcmp(command, "RRT")) {
		end_session(EXIT_FAILURE);
	} 

	if (!strcmp(status, "NOK")) { // not logged in, invalid uid and gid, not subscribed to group
		return STATUS_NOK;
	} else if (!strcmp(status, "EOF")) {
		return STATUS_EOF;
	} else if (!strcmp(status, "ERR")) {
		return STATUS_ERR;
	} else if (strcmp(status, "OK")) {	
		end_session(EXIT_FAILURE);
	}
	
	/* Advance pointer two tokens and two whitespaces */
	num_messages = strtok_r(buf + 2 + strlen(command) + strlen(status), " ", &saveptr);
	
	if (num_messages == NULL || atoi(num_messages) == 0) {
		end_session(EXIT_FAILURE);
	} 

	*list = parse_messages(saveptr, atoi(num_messages));
	free(buf);

	return STATUS_OK;
}

/*	Parses a list of num_messages messages received from 
	the server with entries of the type 
		[MID UID Tsize text[ 
		 / Fname Fsize data]]
	and fills a NULL entry terminated list with entries 
	of the type [text [Fname]].
	Input:
	- buf: the buffer with messages received from the server
	- num_messages: number of messages in the server
*/ //NOTE: make this function more concise
char ***parse_messages(char *buf, int num_messages) {

	char ***response = NULL;
	char *saveptr, *ptr = buf;
	char *file_size, *text_size, *filename, *content;
	FILE *file;
	
	/* Allocate and fill response entries  */
	response = (char***) malloc(sizeof(char**) * (num_messages + 1));

	for (int i = 0; i < num_messages; i++) {
		response[i] = (char **) malloc(sizeof(char*) * 3); 
	
		if (strtok_r(ptr, " ", &saveptr) == NULL) {	/* Ignore MID */
			end_session(EXIT_FAILURE);
		}
		//printf("Parsing %s\n", strtok_r(ptr, " ", &saveptr));

		if (strtok_r(NULL, " ", &saveptr) == NULL) {	/* Ignore UID */
			end_session(EXIT_FAILURE);
		}
		//printf("Parsing %s\n", strtok_r(NULL, " ", &saveptr));

		char* text_size = strtok_r(NULL, " ", &saveptr);	
		//printf("Parsing %d\n", atoi(text_size));
		if (atoi(text_size) <= 0) {
			exit(EXIT_FAILURE);
		}

		/* Allocate entry in list for text and copy text from buffer */
		ptr = text_size + strlen(text_size) + 1;
		response[i][0] = (char *) malloc(sizeof(char) * (atoi(text_size) + 1));
		for (int j = 0; j < atoi(text_size); j++) {
			if (*(ptr + j) == '\0') {
				end_session(EXIT_FAILURE);
			}
			response[i][0][j] = *(ptr + j);
		}
		response[i][0][atoi(text_size)] = '\0';

		//printf("Parsing %s\n", response[i][0]);

		ptr += atoi(text_size) + 1;

		/* Check if message has a file, i.e., if there is a / after the space following the text */
		if (*ptr != '/') {
			//printf("Skip!\n");
			response[i][1] = NULL;
			response[i][2] = NULL;
			continue;
		}

		if (strtok_r(ptr, " ", &saveptr) == NULL) {	/* Ignore the / */
			end_session(EXIT_FAILURE);
		}
		//printf("Parsing %s\n", strtok_r(ptr, " ", &saveptr));

		/* Allocate entry in list for Fname and copy Fname from buffer */
		if ((filename = strtok_r(NULL, " ", &saveptr)) == NULL) {
			end_session(EXIT_FAILURE);
		}

		response[i][1] = (char *) malloc(sizeof(char) * (strlen(filename) + 1));
		strcpy(response[i][1], filename);
		//printf("Parsing %s\n", response[i][1]);

		if ((file_size = strtok_r(NULL, " ", &saveptr)) == NULL) {
			end_session(EXIT_FAILURE);
		}

		response[i][2] = (char *) malloc(sizeof(char) * (strlen(file_size) + 1));
		strcpy(response[i][2], file_size);
		//printf("Parsing %s\n", response[i][2]);
									
		if (atoi(file_size) <= 0) {
			exit(EXIT_FAILURE);
		}

		file = fopen(response[i][1], "wb");

		if (file == NULL){
			exit(EXIT_FAILURE);
		}

		content = file_size + strlen(file_size) + 1;

		if (fwrite(content, sizeof(char), atoi(file_size), file) != atoi(file_size)) {
			end_session(EXIT_FAILURE);
		} 

		if (fclose(file) != 0) {
			end_session(EXIT_FAILURE);
		}
		
		ptr = content + atoi(file_size);

	}

	response[num_messages] = NULL;
	return response;
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

/* The message in buf to the server through the UDP socket 
	and puts a response of size max_rcv_size in buf 
	Input:
	- buf: a buffer that contains the message to be sent and that will
	contained the received message
	- max_rcv_size: maximum size of the response
*/
void exchange_messages_udp(char *buf, ssize_t max_rcv_size) {

	int num_bytes;
	
	if (sendto(udp_socket, buf, strlen(buf) + 1, 0, res_udp->ai_addr, res_udp->ai_addrlen) != (strlen(buf) + 1) * sizeof(char)) {
		exit(EXIT_FAILURE);
	}
	
	memset(buf, 0, strlen(buf) * sizeof(char));
	
	if ((num_bytes = recvfrom(udp_socket, buf, max_rcv_size, 0, (struct sockaddr*) &addr, &addrlen)) <= 0){
		exit(EXIT_FAILURE);
	}
	
	buf[num_bytes] = '\0';

	// DEBUG :
	// printf("Received: %s\n", buf);
	//NOTE : must the client close the socket? or the server?
	
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
	ssize_t num_bytes_written, num_bytes_read, base_bytes, curr_size;
	char *aux = *buf;
	int i = 0;

	while (num_bytes_left > 0) {
		num_bytes_written = write(tcp_socket, aux, num_bytes_left);
		if (num_bytes_written < 0) {
			exit(EXIT_FAILURE);
		}
		num_bytes_left -= num_bytes_written;
		aux += num_bytes_written;
	}

	// Debug
	//printf("Sent: %s\n", *buf);

	memset(*buf, '\0', num_bytes * sizeof(char));

	num_bytes_left = num_bytes;  
	base_bytes = num_bytes;
	curr_size = num_bytes;
	aux = *buf;

	while (1) {
		num_bytes_read = read(tcp_socket, aux, num_bytes_left);
		
		if (num_bytes_read == -1) {
			printf("Error: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		
		if (num_bytes_read == 0) {
			*aux = '\0';
			break;
		}
		
		aux += num_bytes_read;
		num_bytes_left -= num_bytes_read;
		if (num_bytes_left == 0) {
			ssize_t offset = aux - (*buf);
			*buf = (char *) realloc(*buf, curr_size + base_bytes);
			curr_size += base_bytes;
			aux = (*buf) + offset;
			num_bytes_left = base_bytes;
		}
	}

	freeaddrinfo(res_tcp);
	close(tcp_socket);

	// Debug
	//if (**buf != '\0') {
	//	printf("Received: %s", *buf);
	//	printf("With length: %d\n", strlen(*buf));
	//}
}

// NOTE: leave at least some kind of message??
void end_session(int status) {
	close(udp_socket);
	close(tcp_socket);

	freeaddrinfo(res_udp);
	free(server_ip);
	free(server_port);
	exit(status);
}

int is_logged_in () {
	return logged_in;
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
		return TRUE;
	}
	return FALSE;
}