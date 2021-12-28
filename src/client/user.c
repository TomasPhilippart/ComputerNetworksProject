#include "./api/user_api.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <ctype.h>

static void parse_args(int argc, char **argv);
void process_input();
int check_pass(char *pass);
int check_uid(char *uid);

int main(int argc, char **argv) {
	parse_args(argc, argv);
	setup();
	process_input();
	end_session();
	return 0;
}

// ./user [-n DSIP] [-p DSport]
static void parse_args(int argc, char **argv) {
    int opt;

    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
        switch (opt) {
			case 'n':
				if (!(validate_ip(optarg) || validate_hostname(optarg))) {
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

	while (1) {
		fgets(line, sizeof(line)/sizeof(char), stdin);
		char command[MAX_ARG_SIZE], arg1[MAX_ARG_SIZE], arg2[MAX_ARG_SIZE];
		int res;
		int numTokens = sscanf(line, "%s %s %s", command, arg1, arg2);
		
		// ===== REGISTER =====
		if (!strcmp(command, "reg")) {
			if (numTokens != 3) {
				fprintf(stderr, "Invalid. Format: reg UID pass\n");
				continue;
			}
			// Check "UID" and "pass" arguments 
			if (check_uid(arg1) && check_pass(arg2)) {
				res = register_user(arg1, arg2);
				switch(res) {
					case STATUS_OK:
						printf("User registration successful with UID %s.\n", arg1);
						break;
					case STATUS_DUP:
						printf("Error. UID %s is duplicated.\n", arg1);
						break;
					case STATUS_NOK:
						printf("Error registering user.\n");
						break;
				}
			} else {
				fprintf(stderr, "Invalid. UID must be 5 digits and pass must be 8 alphanumeric digits.\n");
			}
			continue;
		}

		// ===== UNREGISTER =====
		if (!strcmp(command, "unregister") || !strcmp(command, "unr")) {
			if (numTokens != 3) {
				fprintf(stderr, "Invalid. Format: %s UID pass\n", command);
				continue;
			}
			
			// Check "UID" and "pass" arguments 
			if (check_uid(arg1) && check_pass(arg2)) {
				res = unregister_user(arg1, arg2);
				switch(res) {
					case STATUS_OK:
						printf("User %s unregistered sucessfully.\n", arg1);
						break;
					case STATUS_NOK:
						printf("Error unregistering user.\n");
						break;
				}
			} else {
				fprintf(stderr, "Invalid. UID must be 5 digits and pass must be 8 alphanumeric digits.\n");
			}
			continue;
		}
		
		// ===== LOGIN =====
		if (!strcmp(command, "login")) {
			if (numTokens != 3) {
				fprintf(stderr, "Invalid. Format: %s UID pass\n", command);
				continue;
			}
			
			// Check "UID" and "pass" arguments 
			if (check_uid(arg1) && check_pass(arg2)) {
				res = login(arg1, arg2);
				switch(res) {
					case STATUS_OK:
						printf("User %s logged in sucessfully.\n", arg1);
						break;
					case STATUS_NOK:
						printf("Error logging in.\n");
						break;
				}

			} else {
				fprintf(stderr, "Invalid. UID must be 5 digits and pass must be 8 alphanumeric digits.\n");
			}
			continue;
		}

		// ===== LOGOUT =====
		if (!strcmp(command, "logout")) {
			
			if (!is_logged_in()) {
				printf("Error: No user is logged in.\n");
				continue;
			}

			res = logout();
			switch(res) {
				case STATUS_OK:
					printf("User %s logged out sucessfully.\n", get_uid());
					break;
				case STATUS_NOK:
					printf("Error logging out.\n");
					break;
			}

			continue;
		}
		
		// ===== SHOW UID =====
		if (!strcmp(command, "showuid") || !strcmp(command, "su")) {
			char* UID = get_uid();

			if (!is_logged_in()) {
				printf("Error: User not be logged in.\n");
			} else {
				printf("UID: %s\n", get_uid());
			}
			continue;
		}

		// ===== EXIT =====
		if (!strcmp(command, "exit")) {
			break;
		}

		// ===== GROUPS =====
		if (!strcmp(command, "groups") || !strcmp(command, "gl")) {
			char ***groups = get_all_groups();

			if (!strcmp(groups[0][0], "")) {
				printf("No groups are available.\n");
			} else {				
				for (int i = 0; strcmp(groups[i][0], ""); i++) {
					printf("%s %s\n", groups[i][0], groups[i][1]);
				}
			}

			continue;
		}

		// NOTE The following group management commands can only be issued after a user has logged in
		// ===== SUBSCRIBE =====
		if (!strcmp(command, "subscribe") || !strcmp(command, "s")) {
			if (numTokens != 3) {
				fprintf(stderr, "Invalid. Format: %s GID GName\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not be logged in.\n");
				continue;
			}

			res = subscribe_group(arg1, arg2);
			switch(res) {
				case STATUS_OK:
					// TODO
					break;
				case STATUS_NEW_GROUP:
					// TODO
					break;
				case STATUS_USR_INVALID:
					// TODO
					break;
				case STATUS_GID_INVALID:
					// TODO
					break;
				case STATUS_GNAME_INVALID:
					// TODO
					break;
				case STATUS_GROUPS_FULL:
					// TODO
					break;
				case STATUS_NOK:
					// TODO
					break;
			}
			continue;
		}

		// ===== UNSUBSCRIBE =====
		if (!strcmp(command, "unsubscribe") || !strcmp(command, "u")) {
			continue;
		}

		// ===== MY GROUPS =====
		if (!strcmp(command, "my_groups") || !strcmp(command, "mgl")) {
			continue;
		}

		// ===== SELECT =====
		if (!strcmp(command, "select") || !strcmp(command, "sag")) {
			continue;
		}

		// ===== SHOW GID =====
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

// Check if UID must be 5 digits and not 0000
int check_uid(char *uid) {
	return strlen(uid) == 5 &&((atoi(uid) > 0) || !strcmp(uid, "00000"));
}

// Check if password is alphanumeric and has 8 characters
int check_pass(char *pass) {
	if (strlen(pass) != 8) {
		return 0;
	}

	for (int i = 0; i < strlen(pass); i++) {
		if (!isalnum(pass[i])) {
			return 0;
		}
	}
	return 1;
}