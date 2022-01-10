#include "../constants.h"
#include "backend/state.h"

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
#include <regex.h>

/* variables needed for UDP connection */
char *port;
int verbose;

int fd; 
struct addrinfo *res;
struct addrinfo hints;
socklen_t addrlen;
struct sockaddr_in addr;

char host[NI_MAXHOST], service[NI_MAXSERV];

/* functions */
int parse_regex(char *str, char *regex);

/* Setup the UDP server */
void setup() {

    fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; 	        /* IPv4 */
	hints.ai_socktype = SOCK_DGRAM;     /* UDP socket */

	addrlen = sizeof(addr);             /* for receiving messages */

	if (getaddrinfo(NULL, port, &hints, &res) != 0) {
		exit(EXIT_FAILURE);
	}
	
    if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
		printf("Error binding.\n");
		exit(EXIT_FAILURE);
	}
}

void process_requests() {

    char buf[MAX_LINE_SIZE];
    char command[MAX_ARG_SIZE], arg1[MAX_ARG_SIZE], arg2[MAX_ARG_SIZE], arg3[MAX_ARG_SIZE], arg4[MAX_ARG_SIZE]; 
    int num_bytes, num_tokens, status;
    regex_t regex;

    while (1) {

        if ((num_bytes = recvfrom(fd, buf, MAX_LINE_SIZE - 1, 0, (struct sockaddr*) &addr, &addrlen)) <= 0) {
            exit(EXIT_FAILURE);
        }

        buf[MAX_LINE_SIZE - 1] = '\0';
        
        if (verbose) {
            if ((getnameinfo((struct sockaddr *)&addr, addrlen, host, sizeof(host), service, sizeof (service), 0)) != 0) {
                printf("Error getting user address information.\n");
                // REVIEW should this end session? Yes!
                exit(EXIT_FAILURE);
            } else {
                printf("(UDP) %s@%s: %s", host, service, buf); /* /n missing because buf already contains it */ 
            }
        }
    
        num_tokens = sscanf(buf, "%" STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s %" 
									 STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s %"
                                     STR(MAX_ARG_SIZE) "s ", command, arg1, arg2, arg3, arg4);

        /* ====== REGISTER ====== */
        if (!strcmp(command, "REG")) {
            //buf[strlen(buf) - 1] = '\0';
            if (!parse_regex(buf, "^REG [0-9]{5} [a-zA-Z0-9]{8}\\\n$")) {
                printf("(UDP) Bad message format in command %s", command);
                exit(EXIT_FAILURE);
            }
           
            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }
          
            status = register_user(arg1, arg2);
            memset(buf, '\0', strlen(buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(buf, "RRG OK\n");
                    break;
                case STATUS_DUP:
                    sprintf(buf, "RRG DUP\n");
                    break;
                case STATUS_NOK:
                    sprintf(buf, "RRG NOK\n");
                    break;
            }
        
        /* ====== UNREGISTER ====== */
        } else if (!strcmp(command, "UNR")) {
            
            if (!parse_regex(buf, "^UNR [0-9]{5} [a-zA-Z0-9]{8}\\\n$")) {
                printf("(UDP) Bad message format in command %s", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }

            status = unregister_user(arg1, arg2);
            memset(buf, '\0', strlen(buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(buf, "RUN OK\n");
                    break;
                case STATUS_NOK:
                    sprintf(buf, "RUN NOK\n");
                    break;
            }

        /* ====== LOGIN ====== */
        } else if (!strcmp(command, "LOG")) {

            if (!parse_regex(buf, "^LOG [0-9]{5} [a-zA-Z0-9]{8}\\\n$")) {
                printf("(UDP) Bad message format in command %s", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }

            status = login_user(arg1, arg2);
            memset(buf, '\0', strlen(buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(buf, "RLO OK\n");
                    break;
                case STATUS_NOK:
                    sprintf(buf, "RLO NOK\n");
                    break;
            }

        /* ====== LOGOUT ====== */
        } else if (!strcmp(command, "OUT")) {

            if (!parse_regex(buf, "^OUT [0-9]{5} [a-zA-Z0-9]{8}\\\n$")) {
                printf("(UDP) Bad message format in command %s", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 3) {
                exit(EXIT_FAILURE);
            }

            status = logout_user(arg1, arg2);
            memset(buf, '\0', strlen(buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(buf, "ROU OK\n");
                    break;
                case STATUS_NOK:
                    sprintf(buf, "ROU NOK\n");
                    break;
            }

        /* ====== GROUPS ====== */
        } else if (!strcmp(command, "GLS")) {
            // TODO

        /* ====== SUBSCRIBE ====== */
        } else if (!strcmp(command, "GSR")) {
            
            char gid[GID_SIZE + 1];
            // NOTE GName, limited to a total of 24 alphanumerical characters (plus ‘-‘, and ‘_’).
            if (!parse_regex(buf, "^GLS .{5} .{2} .{24}\\\n$")) {
                printf("(UDP) Bad message format in command %s", command);
                exit(EXIT_FAILURE);
            }

            if (num_tokens != 4) {
                exit(EXIT_FAILURE);
            }

            status = subscribe_group(arg1, arg2, arg3, gid);
            memset(buf, '\0', strlen(buf) * sizeof(char));
            switch (status) {
                case STATUS_OK:
                    sprintf(buf, "RGS OK\n");
                    break;
                case STATUS_NEW_GROUP:
                    sprintf(buf, "RGS NEW %s\n", gid);
                    break;
                case STATUS_USR_INVALID:
                    sprintf(buf, "RGS E_USR\n");
                    break;
                case STATUS_GID_INVALID:
                    sprintf(buf, "RGS E_GRP\n");
                    break;
                case STATUS_GNAME_INVALID:
                    sprintf(buf, "RGS E_GNAME\n");
                    break;
                case STATUS_GROUPS_FULL:
                    sprintf(buf, "RGS E_FULL\n");
                    break;
                case STATUS_NOK:
                    sprintf(buf, "RGS NOK\n");
                    break;
            }


        /* ====== UNSUBSCRIBE ====== */
        } else if (!strcmp(command, "GUR")) {
            // TODO

        /* ====== MY GROUPS ====== */
        } else if (!strcmp(command, "GLM")) {
            // TODO

        /* ====== UNEXPECTED MESSAGE ====== */
        } else {
            sprintf(buf, "ERR\n");
        }


        /* DEBUG */
        // printf("Reply: %s\n", buf);

        if (sendto(fd, buf, strlen(buf) * sizeof(char), 0, (struct sockaddr*) &addr, addrlen) < strlen(buf)) {
		    exit(EXIT_FAILURE);
        }

	} 
}

int parse_regex(char *str, char *regex) {
    regex_t aux;
    int res;
   
    if (regcomp(&aux, regex, REG_EXTENDED)) {
        exit(EXIT_FAILURE);
    }

    res = regexec(&aux, str, 0, NULL, 0);
    printf("This is the string: %s  and this is the regex %s\n", str, regex);
    printf("Result %d\n", res);
    if (!res) {
        return TRUE;
    } else if (res == REG_NOMATCH) {
        return FALSE;
    } else {
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv) {

	/* No need to validate port since it was already validated*/
    port = strdup(argv[1]);
    verbose = atoi(argv[2]);

    setup();
    process_requests();

    return TRUE;
}