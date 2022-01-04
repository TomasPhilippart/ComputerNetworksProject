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
int check_gid(char *gid);
int get_text(char *buf, char *group);
int check_filename(char *filename);

int main(int argc, char **argv) {
	parse_args(argc, argv);
	setup_udp();
	process_input();
	end_session(EXIT_SUCCESS);
}

// NOTE: make error messages uniform

/*	Parse arguments from the command line according to 
	format ./user [-n DSIP] [-p DSport] */
static void parse_args(int argc, char **argv) {

    int opt;
	int opt_counter = 0;
	
    while (1) {

		if (argv[optind] == NULL) {
			break;
		}

		/* Check for wrong non-argument words in the middle of argv[] or
		   existence of more than 2 options */
		if (argv[optind][0] != '-' || opt_counter >= 2) {
			fprintf(stderr, "Invalid format. Usage: ./user [-n DSIP] [-p DSport]\n");
			exit(EXIT_FAILURE);
		}

		/* parse option-argument tuples */
		opt = getopt(argc, argv, "n:p:");
        switch (opt) {
			case 'n':
				if (!(validate_ip(optarg) || validate_hostname(optarg))) {
					fprintf(stderr, "Invalid format: -n must be followed by a valid IPv4 address or hostname.\n");
					exit(EXIT_FAILURE);
				}
				opt_counter ++;
				break;

			case 'p':
				if (!validate_port(optarg)) {
					fprintf(stderr, "Invalid format: -p must be followed by a valid port number.\n");
					exit(EXIT_FAILURE);
				}
				opt_counter ++;
				break;

			default:
				fprintf(stderr, "Invalid format. Usage: ./user [-n DSIP] [-p DSport]\n");
				exit(EXIT_FAILURE);
			}
			
    }

}

void process_input() {
	char line[MAX_LINE_SIZE];

	while (1) {
		fgets(line, sizeof(line)/sizeof(char), stdin);
		char command[MAX_ARG_SIZE], arg1[MAX_ARG_SIZE], arg2[MAX_ARG_SIZE], arg3[MAX_ARG_SIZE];
		int status;
		int num_tokens = sscanf(line, "%s %s %s %s", command, arg1, arg2, arg3);
		
		// ===== REGISTER =====
		if (!strcmp(command, "reg")) {
			if (num_tokens != 3) {
				fprintf(stderr, "Invalid. Format: reg UID pass\n");
				continue;
			}
			// Check "UID" and "pass" arguments 
			if (check_uid(arg1) && check_pass(arg2)) {
				status = register_user(arg1, arg2);
				switch(status) {
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
				printf("Invalid. UID must be 5 digits and pass must be 8 alphanumeric digits.\n");
			}
			continue;
		}

		// ===== UNREGISTER =====
		if (!strcmp(command, "unregister") || !strcmp(command, "unr")) {
			if (num_tokens != 3) {
				fprintf(stderr, "Invalid. Format: %s UID pass\n", command);
				continue;
			}
			
			// Check "UID" and "pass" arguments 
			if (check_uid(arg1) && check_pass(arg2)) {
				status = unregister_user(arg1, arg2);
				switch(status) {
					case STATUS_OK:
						printf("User %s unregistered sucessfully.\n", arg1);
						break;
					case STATUS_NOK:
						printf("Error unregistering user.\n");
						break;
				}
			} else {
				printf("Invalid. UID must be 5 digits and pass must be 8 alphanumeric digits.\n");
			}
			continue;
		}
		
		// ===== LOGIN =====
		if (!strcmp(command, "login")) {
			if (num_tokens != 3) {
				fprintf(stderr, "Invalid. Format: %s UID pass\n", command);
				continue;
			}

			// NOTE: check is user already logged in?
			
			// Check "UID" and "pass" arguments 
			if (check_uid(arg1) && check_pass(arg2)) {
				status = login(arg1, arg2);
				switch(status) {
					case STATUS_OK:
						printf("User %s logged in sucessfully.\n", arg1);
						break;
					case STATUS_NOK:
						printf("Error logging in.\n");
						break;
				}

			} else {
				printf("Invalid. UID must be 5 digits and pass must be 8 alphanumeric digits.\n");
			}
			continue;
		}

		// ===== LOGOUT =====
		if (!strcmp(command, "logout")) {
			
			if (!is_logged_in()) {
				printf("Error: No user is logged in.\n");
				continue;
			}

			status = logout();
			switch(status) {
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

			/* NOTE: it would make more sense for this verification to be made inside get_uid.
			   If the user is not logged in, then it returns NULL or something. Otherwise we are
			   forcing ourselves to make a verification to guarantee that the UID is not garbled */
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
			char ***groups;

			get_all_groups(&groups);
			if (!strcmp(groups[0][0], "")) {
				printf("No groups are available.\n");
			} else {				
				for (int i = 0; strcmp(groups[i][0], ""); i++) {
					printf("%s %s\n", groups[i][0], groups[i][1]);
				}
			}

			free(groups);
			continue;
		}

		// NOTE The following group management commands can only be issued after a user has logged in
		// ===== SUBSCRIBE =====
		if (!strcmp(command, "subscribe") || !strcmp(command, "s")) {
			if (num_tokens != 3) {
				fprintf(stderr, "Invalid. Format: %s GID GName\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not be logged in.\n");
				continue;
			}

			status = subscribe_group(arg1, arg2);
			switch(status) {
				case STATUS_OK:
					printf("User with UID %s subscribed successfully to group %s with GID %s\n", get_uid(), arg2, arg1);
					break;
				case STATUS_NEW_GROUP:
					printf("Created new group %s\n", arg2);
					break;
				case STATUS_USR_INVALID: // TODO: see this
					printf("UID : %s is not valid\n", get_uid());
					break;
				case STATUS_GID_INVALID: 
					printf("GID : %s is not valid\n", arg1);
					break;
				case STATUS_GNAME_INVALID:
					printf("Group name : %s is not valid\n", arg2);
					break;
				case STATUS_GROUPS_FULL:
					printf("Error : \n");
					break;
				case STATUS_NOK:
					printf("Error subscribing to group %s with GID %s\n", arg2, arg1);
					break;
			}
			continue;
		}

		// ===== UNSUBSCRIBE =====
		if (!strcmp(command, "unsubscribe") || !strcmp(command, "u")) {
			if (num_tokens != 2) {
				fprintf(stderr, "Invalid. Format: %s GID\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			status = unsubscribe_group(arg1);
			switch(status) {
				case STATUS_OK:
					printf("User with UID %s unsubscribed successfully from group with GID %s\n", get_uid(), arg1);
					break;
				case STATUS_USR_INVALID: // TODO: see this
					printf("UID : %s is not valid\n", get_uid());
					break;
				case STATUS_GID_INVALID: 
					printf("GID : %s is not valid\n", arg1);
					break;
				case STATUS_NOK:
					printf("Error unsubscribing from group with GID %s\n", arg1);
					break;
			}
			continue;
		}

		// ===== MY GROUPS =====
		if (!strcmp(command, "my_groups") || !strcmp(command, "mgl")) {
			if (num_tokens != 1) {
				fprintf(stderr, "Invalid. Format: %s\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			char ***groups;

			status = get_subscribed_groups(&groups);
			if (status == STATUS_USR_INVALID) {
				printf("Error: Invalid UID.\n");
			} else {			
				for (int i = 0; strcmp(groups[i][0], ""); i++) {
					printf("%s %s\n", groups[i][0], groups[i][1]);
				}
			}
			free(groups);
			continue;
		}

		// ===== SELECT =====
		if (!strcmp(command, "select") || !strcmp(command, "sag")) {
			if (num_tokens != 2) {
				fprintf(stderr, "Invalid. Format: %s GID\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
			} else if (check_gid(arg1)) {
				set_gid(arg1);
				printf("GID %s selected.\n", arg1);
			} else {
				printf("Error: GID %s is invalid.\n", arg1);
			}
			
			continue;
		}

		// ===== SHOW GID =====
		if (!strcmp(command, "showgid") || !strcmp(command, "sg")) {
			if (num_tokens != 1) {
				fprintf(stderr, "Invalid. Format: %s\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
			} else if (strcmp(get_gid(), "")) {
				printf("Selected GID: %s\n", get_gid());
			} else {
				printf("Error: No GID selected.\n");
			}
			
			continue;
		}

		// ===== LIST UIDS IN CURRENT GROUP =====
		if (!strcmp(command, "ulist") || !strcmp(command, "ul")) {
		
			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			if (!strcmp(get_gid(), "")) {
				printf("Error: no group is currently selected.\n");
				continue;
			}
			char **uids;
			status = get_uids_group(&uids);
			if (!strcmp(uids[0], "")) {
				printf("Group %s is not subscribed by any user.\n", get_gid());
			} else if (!strcmp(get_gid(), "")) {
				printf("User %s has not selected any group.\n", get_uid());
			} else {		
				for (int i = 0; strcmp(uids[i], ""); i++) {
					printf("%s\n", uids[i]);
				}
			}
			free(uids);
			continue;
		}

		// ===== POST A MESSAGE =====
		if (!strcmp(command, "post")) {
			
			char *rest = line + (strlen(command) * sizeof(char)) + 1;
			char buf[250];

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}
			
			if (get_text(buf, rest) == FAIL) {
				printf("Invalid format. Usage: post \"text\" [Fname].\n");
				continue;
			}
		
			char mid[5];	

			// NOTE: check if we are subscribed to group
			if (*(rest + strlen(buf) + 2) == '\n') { // no Fname
				status = post(buf, mid, NULL);
			} else if (*(rest + strlen(buf) + 2) == ' ') {
				num_tokens = sscanf(rest + strlen(buf) + 2, " %s %s", arg2, arg3);
				
				if (num_tokens != 1) {
					printf("Invalid format. Usage: post \"text\" [Fname].\n");
					continue;
				}

				if (!check_filename(arg2)) {
					printf("Invalid filename.\n");
					continue;
				}
				
				status = post(buf, mid, arg2);
			} else {
				printf("Invalid format. Usage: post \"text\" [Fname].\n");
				continue;
			}

			switch (status) {
				case STATUS_OK: 
					printf("Message successfully sent with MID %s.\n", mid);
					continue;
				case STATUS_NOK:
					// TODO error message
					printf("Error\n");
					continue;

			}
			
			continue;
		}

		if (!strcmp(command, "retrieve") || !strcmp(command, "r")) {

			//f (num_tokens != 2) {
			//	fprintf(stderr, "Invalid. Format: %s\n", command);
			//	continue;
			//

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			char *** list; 
			status = retrieve(arg1, &list);

			switch (status) {
				case STATUS_OK:
					// TODO display new messages
					for (int i = 0; list[i] != NULL; i++) {
						printf("%04d %s ", atoi(arg1) + i, list[i][0]);
						if (list[i][1] != NULL) {
							printf("%s", list[i][1]);
						}
						putchar('\n');
					}
					continue;
				case STATUS_NOK:
					printf("Error with something man idk\n");
					continue;
				case STATUS_EOF:
					printf("There are no new messages to read\n");
					continue;
			}

			
			continue;
		}
	}
}

// Check if UID is 5 digits and not 0000
int check_uid(char *uid) {
	return strlen(uid) == 5 && atoi(uid) > 0;
}

// Check if GID is 2 digits
int check_gid(char *gid) {
	return strlen(gid) == 2 && atoi(gid) > 0;
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

int get_text(char *buf, char *str) {

	char c;
	int i = 0;

	if (str[i++] != '\"') {
		return FAIL;
	}

	while ((buf[i - 1] = str[i]) != '\"') {
		if (str[i++] == '\n') {
			return FAIL;
		}
	}

	buf[i - 1] ='\0';

	return SUCCESS;
}

int check_filename(char *filename) {

	if (!((strlen(filename) < 24) && (strlen(filename) > 5))) {
		return FAIL;
	}

	for (int i = 0; i < strlen(filename); i++) {
		if (!(filename[i] == '_' || filename[i] == '.' || filename[i] == '-'|| isalnum(filename[i]))) {
			return FAIL;
		}
	}

	// Check extension separating dot
	if (!(filename[strlen(filename) - 4] == '.')) {
		return FAIL;
	}

	// Check extension is 3 letters
	for (int i = strlen(filename) - 3; i < strlen(filename); i++) {
		if (!(isalpha(filename[i]))) {
			return FAIL;
		}
	}
	
	// Check if file exists
	if (access(filename, F_OK ) != 0 ) {
		return FAIL;
	}

	return SUCCESS;
}
