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

/* variables needed for UDP connection */
char *port;
int fd; 
struct addrinfo *res;
struct addrinfo hints;
socklen_t addrlen;
struct sockaddr_in addr;

int verbose;

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
	
    if(bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
		printf("Error binding\n");
		exit(EXIT_FAILURE);
	}
}

void process_requests() {

    char buf[MAX_LINE_SIZE];
    char command[MAX_ARG_SIZE], arg1[MAX_ARG_SIZE], arg2[MAX_ARG_SIZE], arg3[MAX_ARG_SIZE]; 
    int num_bytes, num_tokens, status;

    while (1) {

        if ((num_bytes = recvfrom(fd, buf, MAX_LINE_SIZE, 0, (struct sockaddr*) &addr, &addrlen)) <= 0) {
            exit(EXIT_FAILURE);
        }

        printf("Received: %s\n", buf);
    

        // NOTE: make this match exactly one space
        num_tokens = sscanf(buf, "%" STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s %" 
									 STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s " , command, arg1, arg2, arg3);

        // NOTE: use a regex to check spaces??
        /* ====== REGISTER ====== */
        if (!strcmp(command, "REG")) {
            if (num_tokens != 3) {
                //
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
            // TODO

        /* ====== LOGIN ====== */
        } else if (!strcmp(command, "LOG")) {
            // TODO

        /* ====== LOGOUT ====== */
        } else if (!strcmp(command, "OUT")) {
            // TODO

        /* ====== GROUPS ====== */
        } else if (!strcmp(command, "GLS")) {
            // TODO

        /* ====== SUBSCRIBE ====== */
        } else if (!strcmp(command, "GSR")) {
            // TODO

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

        printf("Sent: %s\n", buf);
        if (sendto(fd, buf, strlen(buf), 0, res->ai_addr, res->ai_addrlen) != strlen(buf) * sizeof(char)) {
		    exit(EXIT_FAILURE);
        }

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

