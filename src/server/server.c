#include "../constants.h"
#include "backend/state.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include<sys/wait.h>
#include<signal.h>

/* Default port */
char port[6] = "58043";

/* Verbose mode flag */
int verbose = FALSE;

pid_t pid_tcp;
pid_t pid_udp;

struct sigaction old_action;


static void parse_args(int argc, char **argv);
void process_input();
int validate_port(char *port);

void ctrlC_handler (int sig_no);
void end_session();

int main(int argc, char **argv) {
    pid_t aux;
	int finished = 0;
	int status;
	struct sigaction action;

	parse_args(argc, argv);

	printf("Running server on port %s and %s\n", port, verbose ? "Verbose" : "Non-Verbose");

    if ((pid_udp = fork()) == 0) {
		execl("./server_udp", "./server_udp", port, verbose ? "1" : "0", NULL);
        printf("Error: Executing \"./server_udp %s %s\"", port, verbose ? "1" : "0");
		exit(EXIT_FAILURE);
	} else if (pid_udp == -1) {
		exit(EXIT_FAILURE);
    }
       
    if ((pid_tcp = fork()) == 0) {
		execl("./server_tcp", "./server_tcp", port, verbose ? "1" : "0", NULL);
        printf("Error: Executing \"./server_tcp %s %s\"", port, verbose ? "1" : "0");
        exit(EXIT_FAILURE);
	} else if (pid_tcp == -1) {
		exit(EXIT_FAILURE);
    }

	/* Setup ctrl-c new action */
    memset(&action, 0, sizeof(action));
    action.sa_handler = &ctrlC_handler;
    sigaction(SIGINT, &action, &old_action);

	while (finished != 2) {
		aux = wait(&status);
		finished++;
	}
   
	if (status == EXIT_FAILURE) {
		if (aux == pid_udp) {
			kill(pid_tcp, SIGTERM);
		} else {
			kill(pid_udp, SIGTERM);
		}
	}
	
    end_session(SUCCESS);
}

/*	Parse arguments from the command line according to 
	format  ./server [-p DSport] [-v]\n" */	
static void parse_args(int argc, char **argv) {

    int opt;
	int opt_counter = 0;
	
    while (TRUE) {

		if (argv[optind] == NULL) {
			break;
		}

		/* Check for wrong non-argument words in the middle of argv[] or
		   existence of more than 2 options */
		if (argv[optind][0] != '-' || opt_counter >= 2) {
			printf("Invalid format. Usage: ./server [-p DSport] [-v]\n");
			exit(EXIT_FAILURE);
		}

		/* parse option/argument tuples */
		opt = getopt(argc, argv, "p:v");
        switch (opt) {

			case 'p':
				if (!validate_port(optarg)) {
					printf("Invalid format: -p must be followed by a valid port number.\n");
					exit(EXIT_FAILURE);
				}
				opt_counter++;
				break;
            
            case 'v':
                verbose = TRUE;
				opt_counter++;
				break;

			default:
				printf("Invalid format. Usage: ./server [-p DSport] [-v]\n");
				exit(EXIT_FAILURE);
		}	
    }
}

int validate_port(char *port_to_validate) {
	int port_number = atoi(port_to_validate);
	if (port_number > 0 && port_number <= 65535 && (strlen(port_to_validate) < 7)) {
		strcpy(port, port_to_validate);
		return TRUE;
	}
	return FALSE;
}

void ctrlC_handler (int sig_no) {

	kill(pid_tcp, SIGINT);
	kill(pid_udp, SIGINT);

    sigaction(SIGINT, &old_action, NULL);
    kill(0, SIGINT);
}

void end_session () {
	// TODO
}