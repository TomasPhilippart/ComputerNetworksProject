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

int validate_number(char *str);
int validate_ip(char *ip);
static void parseArgs(int argc, char *const argv[]);

int main(int argc, char **argv) {
	startup();
	return 0;
}

// ./user [-n DSIP] [-p DSport]
static void parseArgs(int argc, char *const argv[]) {
    int opt;

    // put ':' in the starting of the
    // string so that program can
    //distinguish between '?' and ':'
    while ((opt = getopt(argc, argv, ":if:lrx")) != -1)
    {
        switch (opt) {
        case 'n':
			if (validate_ip(optarg)) {
				server_ip = optarg;
			} else if (validate_dns(optarg)) {
				server_ip = optarg;
			}
            break;
        case 'p':
            break;
        }
    }
}

int validate_number(char *str) {
	while (*str) {
		if (!isdigit(*str)) { 
			return 0;
		}

		str++; //point to next character
	}
	return 1;
}

//check whether the IP is valid or not
int validate_ip(char *ip) {
	int i, num, dots = 0;
	char *ptr;

	if (ip == NULL) {
		return 0;
	}
	ptr = strtok(ip, "."); //cut the string using dor delimiter

	if (ptr == NULL) {
		return 0;
	}

	while (ptr) {
		if (!validate_number(ptr)) {
			num = atoi(ptr); //convert substring to number
		}

		if (num >= 0 && num <= 255) {
			ptr = strtok(NULL, "."); //cut the next part of the string
			if (ptr != NULL) {
				dots++;
			}
		} else {
			return 0;
		}
	}

	if (dots != 3) {
		return 0;
	}

	return 1;
}

