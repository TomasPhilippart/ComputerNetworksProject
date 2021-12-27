#include "./api/user_api.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <ctype.h>

#define MAX_LINE_SIZE 300
#define MAX_ARG_SIZE 250
#define TRUE 1

static void parse_args(int argc, char **argv);
void process_input();

int main(int argc, char **argv) {
	startup();
	parse_args(argc, argv);
	printf("Arguments parsed successfully.\n");
	create_connection();
	process_input();
	return 0;
}

// ./user [-n DSIP] [-p DSport]
static void parse_args(int argc, char **argv) {
    int opt;

    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
        switch (opt) {
			
			case 'n':
				if (!(validate_ip(optarg) || validate_dns(optarg))) {
					fprintf(stderr, "Invalid format: -n must be followed by a valid IPv4 address or hostname.\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'p':
				if (!validate_port(optarg)) {
					fprintf(stderr, "Invalid format: -p must be followed by a valid port number.\n");
					exit(EXIT_FAILURE);
				}
				break;
			}
    }
}

void process_input() {
	char line[MAX_LINE_SIZE];

	while (TRUE) {
		fgets(line, sizeof(line)/sizeof(char), stdin);
		
		char *command;
		char arg1[MAX_ARG_SIZE], arg2[MAX_ARG_SIZE];
		int res;

		int numTokens = sscanf(line, "%s %s %s", command, arg1, arg2);

		/* perform minimal validation */
		if (numTokens < 1) {
			continue;
		}
		
		if (!strcmp(command, "reg")) {
			if (numTokens != 3) {
				fprintf(stderr, "Invalid. Format: reg UID pass\n");
			}
			
			//register_user(arg1, arg2);

			continue;
		}


		if (!strcmp(command, "unregister") || !strcmp(command, "unr")) {
			continue;
		}
		

		if (!strcmp(command, "login")) {
			continue;
		}

		if (!strcmp(command, "logout")) {
			continue;
		}
		
		if (!strcmp(command, "showuid") || !strcmp(command, "su")) {
			continue;
		}

		if (!strcmp(command, "exit")) {
			continue;
		}

		if (!strcmp(command, "groups") || !strcmp(command, "gl")) {
			continue;
		}

		if (!strcmp(command, "subscribe") || !strcmp(command, "s")) {
			continue;
		}

		if (!strcmp(command, "unsubscribe") || !strcmp(command, "u")) {
			continue;
		}

		if (!strcmp(command, "my_groups") || !strcmp(command, "mgl")) {
			continue;
		}

		if (!strcmp(command, "select") || !strcmp(command, "sag")) {
			continue;
		}

		if (!strcmp(command, "showgid") || !strcmp(command, "sg")) {
			continue;
		}

		if (!strcmp(command, "ulist") || !strcmp(command, "ul")) {
			continue;
		}

		if (!strcmp(command, "post")) {
			continue;
		}

		if (!strcmp(command, "retrieve") || !strcmp(command, "r")) {
			continue;
		}

	}

}