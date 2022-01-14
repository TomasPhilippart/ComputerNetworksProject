#include "../constants.h"
#include "backend/state.h"
#include "../aux_functions.h"

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


/* variables needed for UDP connection */
char *port;
int verbose;

int fd; 
struct addrinfo *res;
struct addrinfo hints;
socklen_t addrlen;
struct sockaddr_in addr;

char host[NI_MAXHOST] = "";
char service[NI_MAXSERV] = "";

int start_timer(int fd);
int stop_timer(int fd);

/* Setup the UDP server */
void setup() {
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
        printf("Error: Failed to create UDP socket.\n");
		exit(EXIT_FAILURE);
	}
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; 	        /* IPv4 */
	hints.ai_socktype = SOCK_DGRAM;     /* UDP socket */
    hints.ai_flags = AI_PASSIVE;
	addrlen = sizeof(addr);             /* for receiving messages */

	if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        printf("Error: DNS couldn't resolve server's IP address for UDP connection.\n");
		exit(EXIT_FAILURE);
	}
    if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
		printf("Error: Binding socket.\n");
		exit(EXIT_FAILURE);
	}

    setup_state();

}

void process_requests() {

    char receiving_buf[MAX_LINE_SIZE] = "";
    char *sending_buf;
    char command[MAX_ARG_SIZE] = "";
    char arg1[MAX_ARG_SIZE] = "";
    char arg2[MAX_ARG_SIZE] = ""; 
    char arg3[MAX_ARG_SIZE] = "";
    char arg4[MAX_ARG_SIZE] = "";

    int num_bytes, num_tokens, status;

    while (1) {
        
        /* TODO where to start/stop timer? */
        if ((num_bytes = recvfrom(fd, receiving_buf, MAX_LINE_SIZE - 1, 0, (struct sockaddr*) &addr, &addrlen)) <= 0) {
            printf("Error: ");
            exit(EXIT_FAILURE);
        }

        receiving_buf[num_bytes] = '\0';
        
        if (verbose) {
            if ((getnameinfo((struct sockaddr *)&addr, addrlen, host, sizeof(host), service, sizeof (service), 0)) != 0) {
                printf("Error getting user address information.\n");
                exit(EXIT_FAILURE);
            } else {
                printf("(UDP) %s@%s: %s", host, service, receiving_buf); /* /n missing because buf already contains it */ 
            }
        }

        num_tokens = sscanf(receiving_buf, "%" STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s %" 
									 STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s %"
                                     STR(MAX_ARG_SIZE) "s ", command, arg1, arg2, arg3, arg4);

        /* ====== REGISTER ====== */
        if (!strcmp(command, "REG")) {
            
            if (parse_regex(receiving_buf, "^REG [0-9]{5} [a-zA-Z0-9]{8}\\\n$") == FALSE) {
                printf("(UDP) Bad message format in command %s", command);
                exit(EXIT_FAILURE);
            }
           
            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }

            status = register_user(arg1, arg2);
    
            if ((sending_buf = (char *) malloc(sizeof(char) * 9)) == NULL) {
                printf("Error: Couldn't allocate memory for sending_buf\n");
            }

            memset(sending_buf, 0, sizeof(sending_buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(sending_buf, "RRG OK\n");
                    break;
                case STATUS_DUP:
                    sprintf(sending_buf, "RRG DUP\n");
                    break;
                case STATUS_NOK:
                    sprintf(sending_buf, "RRG NOK\n");
                    break;
                case STATUS_FAIL:
                    exit(STATUS_FAIL);
            }
        
        /* ====== UNREGISTER ====== */
        } else if (!strcmp(command, "UNR")) {
            
            if (parse_regex(receiving_buf, "^UNR [0-9]{5} [a-zA-Z0-9]{8}\\\n$") == FALSE) {
                printf("(UDP) Bad message format in command %s", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }

            status = unregister_user(arg1, arg2);

            if ((sending_buf = (char *) malloc(sizeof(char) * 9)) == NULL) {
                printf("Error: Couldn't allocate memory for sending_buf\n");
            }

            memset(sending_buf, 0, sizeof(sending_buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(sending_buf, "RUN OK\n");
                    break;
                case STATUS_NOK:
                    sprintf(sending_buf, "RUN NOK\n");
                    break;
                case STATUS_FAIL:
                    exit(STATUS_FAIL);
            }

        /* ====== LOGIN ====== */
        } else if (!strcmp(command, "LOG")) {

            if (parse_regex(receiving_buf, "^LOG [0-9]{5} [a-zA-Z0-9]{8}\\\n$") == FALSE) {
                printf("(UDP) Bad message format in command %s\n", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }

            status = login_user(arg1, arg2);

            if ((sending_buf = (char *) malloc(sizeof(char) * 9)) == NULL) {
                printf("Error: Couldn't allocate memory for sending_buf\n");
            }

            memset(sending_buf, 0, sizeof(sending_buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(sending_buf, "RLO OK\n");
                    break;
                case STATUS_NOK:
                    sprintf(sending_buf, "RLO NOK\n");
                    break;
                case STATUS_FAIL:
                    exit(STATUS_FAIL);
            }

        /* ====== LOGOUT ====== */
        } else if (!strcmp(command, "OUT")) {

            if (parse_regex(receiving_buf, "^OUT [0-9]{5} [a-zA-Z0-9]{8}\\\n$") == FALSE) {
                printf("(UDP) Bad message format in command %s\n", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }
            
            status = logout_user(arg1, arg2);

            if ((sending_buf = (char *) malloc(sizeof(char) * 9)) == NULL) {
                printf("Error: Couldn't allocate memory for sending_buf\n");
            }
            memset(sending_buf, 0, sizeof(sending_buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(sending_buf, "ROU OK\n");
                    break;
                case STATUS_NOK:
                    sprintf(sending_buf, "ROU NOK\n");
                    break;
                case STATUS_FAIL:
                    exit(STATUS_FAIL);
            }

        /* ====== GROUPS ====== */
        } else if (!strcmp(command, "GLS")) {

            char ***groups;
            char *aux;
            size_t sending_buf_size;

            int num_groups = 0;
            
            if (parse_regex(receiving_buf, "^GLS\\\n$") == FALSE) {
                printf("(UDP) Bad message format in command %s\n", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 1) {
                exit(EXIT_FAILURE);
            }
            
            status = all_groups(&num_groups, &groups);

            sending_buf_size =  num_groups * (GID_SIZE + MAX_GNAME + MID_SIZE + 3) + 7;
            if ((sending_buf = (char *) malloc(sizeof(char) * sending_buf_size)) == NULL) {
                printf("Error: Couldn't allocate memory for sending_buf\n");
            }

            memset(sending_buf, 0, sending_buf_size * sizeof(char));

            switch (status) {
                case STATUS_OK:
                    // REVIEW 
                    aux = sending_buf;
                    
                    sprintf(aux, "RGL %d", num_groups);
                    aux += (strlen(aux) * sizeof(char));

                    for (int i = 0; i < num_groups; i++) {
                        sprintf(aux, " %s %s %s", groups[i][0], groups[i][1], groups[i][2]);
                        // printf("Got %s %s %s\n", groups[i][0], groups[i][1], groups[i][2]);
                        aux += (strlen(aux) * sizeof(char));
                    }

                    free_groups(groups, num_groups);
                    sprintf(aux, "\n");
                    break;
                case STATUS_FAIL:
                    exit(STATUS_FAIL);
            }

        /* ====== SUBSCRIBE ====== */
        } else if (!strcmp(command, "GSR")) {
            
            char gid[GID_SIZE + 1] = "";
            if (parse_regex(receiving_buf, "^GSR .{5} .{2} .{1,24}\\\n$") == FALSE) {
                printf("(UDP) Bad message format in command %s\n", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 4) {
                exit(EXIT_FAILURE);
            }

            status = subscribe_group(arg1, arg2, arg3, gid);

            if ((sending_buf = (char *) malloc(sizeof(char) * 13)) == NULL) {
                printf("Error: Couldn't allocate memory for sending_buf\n");
            }

            memset(sending_buf, 0, sizeof(sending_buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(sending_buf, "RGS OK\n");
                    break;
                case STATUS_NEW_GROUP:
                    sprintf(sending_buf, "RGS NEW %s\n", gid);
                    break;
                case STATUS_USR_INVALID:
                    sprintf(sending_buf, "RGS E_USR\n");
                    break;
                case STATUS_GID_INVALID:
                    sprintf(sending_buf, "RGS E_GRP\n");
                    break;
                case STATUS_GNAME_INVALID:
                    sprintf(sending_buf, "RGS E_GNAME\n");
                    break;
                case STATUS_GROUPS_FULL:
                    sprintf(sending_buf, "RGS E_FULL\n");
                    break;
                case STATUS_NOK:
                    sprintf(sending_buf, "RGS NOK\n");
                    break;
                case STATUS_FAIL:
                    exit(STATUS_FAIL);
            }


        /* ====== UNSUBSCRIBE ====== */
        } else if (!strcmp(command, "GUR")) {

            if (parse_regex(receiving_buf, "^GUR .{5} .{2}\\\n$") == FALSE) {
                printf("(UDP) Bad message format in command %s\n", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }

            status = unsubscribe_user(arg1, arg2);

            if ((sending_buf = (char *) malloc(sizeof(char) * 11)) == NULL) {
                printf("Error: Couldn't allocate memory for sending_buf\n");
            }

            memset(sending_buf, 0, sizeof(sending_buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(sending_buf, "RGU OK\n");
                    break;
                case STATUS_USR_INVALID:
                    sprintf(sending_buf, "RGU E_USR\n");
                    break;
                case STATUS_GID_INVALID:
                    sprintf(sending_buf, "RGU E_GRP\n");
                    break;
                case STATUS_NOK:
                    sprintf(sending_buf, "RGU NOK\n");
                    break;
                case STATUS_FAIL:
                    exit(STATUS_FAIL);
            }

        /* ====== MY GROUPS ====== */
        } else if (!strcmp(command, "GLM")) {
            
            char ***groups;
            char *aux;
            size_t sending_buf_size;

            int num_groups = 0;

            if (!parse_regex(receiving_buf, "^GLM [0-9]{" STR(UID_SIZE) "}\\\n$")) {
                printf("(UDP) Bad message format in command %s\n", command);
                sprintf(sending_buf, "ERR\n");
                continue;
            }

            if (num_tokens != 2) {
                exit(EXIT_FAILURE);
            }

            status = user_subscribed_groups(arg1, &num_groups, &groups);

            sending_buf_size =  num_groups * (GID_SIZE + MAX_GNAME + MID_SIZE + 3) + 12;
            if ((sending_buf = (char *) malloc(sizeof(char) * sending_buf_size)) == NULL) {
                printf("Error: Couldn't allocate memory for sending_buf\n");
            }

            memset(sending_buf, 0, sending_buf_size * sizeof(char));

            switch (status) {
                case STATUS_OK:
                    // REVIEW 
                    aux = sending_buf;

                    sprintf(aux, "RGM %d", num_groups);
                    aux += (strlen(aux) * sizeof(char));

                    for (int i = 0; i < num_groups; i++) {
                        sprintf(aux, " %s %s %s", groups[i][0], groups[i][1], groups[i][2]);
                        aux += (strlen(aux) * sizeof(char));
                    }

                    free_groups(groups, num_groups);
                    sprintf(aux, "\n");
                    break;
                case STATUS_USR_INVALID:
                    sprintf(sending_buf, "RGM E_USR\n");
                    break;
                case STATUS_FAIL:
                    exit(STATUS_FAIL);
            }

        /* ====== UNEXPECTED MESSAGE ====== */
        } else {
            sprintf(receiving_buf, "ERR\n");
        }

        //printf("Sending: <%s>\n", sending_buf);
        if (sendto(fd, sending_buf, strlen(sending_buf) * sizeof(char), 0, (struct sockaddr*) &addr, addrlen) < strlen(sending_buf)) {
		    exit(EXIT_FAILURE);
        }

        free(sending_buf);
        memset(receiving_buf, 0, MAX_LINE_SIZE * sizeof(char));
	} 
}

int start_timer(int fd) {
    struct timeval timeout;

    memset((char *) &timeout, 0, sizeof(timeout)); 
    timeout.tv_sec = 0;
	timeout.tv_usec = 50000;

    return (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &timeout, sizeof(struct timeval)));
}

int stop_timer(int fd){
    struct timeval timeout;
    memset((char *)&timeout, 0, sizeof(timeout)); 
    return (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &timeout, sizeof(struct timeval)));
}

int main(int argc, char **argv) {

	/* No need to validate port since it was already validated*/
    port = strdup(argv[1]);
    verbose = atoi(argv[2]);
    setup();
    process_requests();

    return 0;
}

