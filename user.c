#include "./api/user_api.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <ctype.h>

char *server_ip;
int server_port;

static void parse_args(int argc, char **argv);

int main(int argc, char **argv) {
	startup();
	parse_args(argc, argv);
	printf("server ip: %s, server port: %d\n", server_ip, server_port);
	return 0;
}


// ./user [-n DSIP] [-p DSport]
static void parse_args(int argc, char **argv) {
    int opt;

    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
        switch (opt) {
			
			case 'n':
				if (validate_ip(optarg)) {
					server_ip = strdup(optarg);
					break;
				} else if(validate_dns(optarg)) {
					server_ip = strdup(optarg);
				} else {
					fprintf(stderr, "Invalid format: -n must be followed by a valid IPv4 address or hostname.\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'p':
				if (validate_port(atoi(optarg))) {
					server_port = atoi(strdup(optarg));
				} else {
					fprintf(stderr, "Invalid format: -p must be followed by a valid port number.\n");
					exit(EXIT_FAILURE);
				}
				break;
			}
    }
}