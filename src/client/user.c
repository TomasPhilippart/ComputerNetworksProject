#include "./api/user_api.h"
#include "../constants.h"
#include "../aux_functions.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <ctype.h>

// NOTE: Make this function a wrapper of a regex validator 
// NOTE: Check one-argument commands

static void parse_args(int argc, char **argv);
void process_input();

int check_if_subscribed(char *gid);
int get_text(char *buf, char *group);

int main(int argc, char **argv) {
	parse_args(argc, argv);
	setup_udp();
	process_input();
	end_session(EXIT_SUCCESS);
}

/*	Parse arguments from the command line according to 
	format ./user [-n DSIP] [-p DSport] */
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
			fprintf(stderr, "Invalid format. Usage: ./user [-n DSIP] [-p DSport].\n");
			exit(EXIT_FAILURE);
		}

		/* parse option/argument tuples */
		opt = getopt(argc, argv, "n:p:");
        switch (opt) {
			case 'n':
				if (!(validate_ip(optarg) || validate_hostname(optarg))) {
					fprintf(stderr, "Invalid format: -n must be followed by a valid IPv4 address or hostname.\n");
					exit(EXIT_FAILURE);
				}

				opt_counter++;
				break;

			case 'p':
				if (!validate_port(optarg)) {
					fprintf(stderr, "Invalid format: -p must be followed by a valid port number.\n");
					exit(EXIT_FAILURE);
				}
				opt_counter++;
				break;

			default:
				fprintf(stderr, "Invalid format. Usage: ./user [-n DSIP] [-p DSport].\n");
				exit(EXIT_FAILURE);
		}	
    }
}

void process_input() {
	char line[MAX_LINE_SIZE];

	while (1) {

		fflush(stdin);
		printf(">> ");
		fgets(line, sizeof(line)/sizeof(char), stdin);

		/* arg3 ensures that the user does not insert more than 3 tokens */
		char command[MAX_ARG_SIZE], arg1[MAX_ARG_SIZE], arg2[MAX_ARG_SIZE], arg3[MAX_ARG_SIZE]; 
		int status;
		int num_tokens = sscanf(line, "%" STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s %" 
										  STR(MAX_ARG_SIZE) "s %" STR(MAX_ARG_SIZE) "s " , command, arg1, arg2, arg3);

		/* If the user presses Enter */
		if (num_tokens < 1) {
			continue;
		}
		
		/* ===== REGISTER ===== */
		if (!strcmp(command, "reg")) {

			if (num_tokens != 3) {
				fprintf(stderr, "Invalid format. Usage: reg UID pass\n");
				continue;
			}

			if (!(check_uid(arg1) && check_pass(arg2))) {
				printf("Error: UID must have 5 digits and pass must have 8 alphanumeric characters.\n");
				continue;
			}

			status = register_user(arg1, arg2);
			switch(status) {
				case STATUS_OK:
					printf("User registered successfully with UID %s.\n", arg1);
					continue;
				case STATUS_DUP:
					printf("Error: UID %s is duplicated.\n", arg1);
					continue;
				case STATUS_NOK:
					printf("Error registering user.\n");
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
		}

		/* ===== UNREGISTER ===== */
		if (!strcmp(command, "unregister") || !strcmp(command, "unr")) {

			if (num_tokens != 3) {
				fprintf(stderr, "Invalid format. Format: %s UID pass\n", command);
				continue;
			}
			
			if (!(check_uid(arg1) && check_pass(arg2))) {
				printf("Error: UID must have 5 digits and pass must have 8 alphanumeric digits.\n");
				continue;
			}

			status = unregister_user(arg1, arg2);
			switch(status) {
				case STATUS_OK:
					printf("User %s unregistered successfully.\n", arg1);
					continue;
				case STATUS_NOK:
					printf("Error unregistering user.\n");
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
		}
		
		/* ===== LOGIN ===== */
		if (!strcmp(command, "login")) {

			if (num_tokens != 3) {
				fprintf(stderr, "Invalid format. Usage: %s UID pass\n", command);
				continue;
			}

			if (is_logged_in()) {
				printf("Error: User is already logged in. Please logout in order to change User.\n");
				continue;
			}			
			
			if (!(check_uid(arg1) && check_pass(arg2))) {
				printf("Error: UID must have 5 digits and pass must have 8 alphanumeric characters.\n");
				continue;
			}

			status = login(arg1, arg2);
			switch(status) {
				case STATUS_OK:
					printf("User %s logged in successfully.\n", arg1);
					continue;
				case STATUS_NOK:
					printf("Error logging in.\n");
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
		}

		/* ===== LOGOUT ===== */
		if (!strcmp(command, "logout")) {
			
			if (num_tokens != 1) {
				fprintf(stderr, "Invalid format. Usage: %s\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			status = logout();
			switch(status) {
				case STATUS_OK:
					printf("User logged out successfully.\n");
					continue;
				case STATUS_NOK:
					printf("Error logging out.\n");
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
		}
		
		/* ===== SHOW UID ===== */
		if (!strcmp(command, "showuid") || !strcmp(command, "su")) {
			char* UID = get_uid();
			
			if (num_tokens != 1) {
				fprintf(stderr, "Invalid format. Usage: %s\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			printf("UID: %s\n", get_uid());
			continue;
		}

		/* ===== EXIT ===== */
		if (!strcmp(command, "exit")) {

			if (num_tokens != 1) {
				fprintf(stderr, "Invalid format. Usage: %s\n", command);
				continue;
			}

			break;
		}

		/* ===== GROUPS ===== */
		if (!strcmp(command, "groups") || !strcmp(command, "gl")) {
			char ***groups;

			if (num_tokens != 1) {
				fprintf(stderr, "Invalid format. Usage: %s\n", command);
				continue;
			}

			get_all_groups(&groups);
			if (groups[0] == NULL) {
				printf("No groups are available.\n");
				free_list(groups, 2);
				continue;
			}

			for (int i = 0; groups[i] != NULL; i++) {
				printf("%s %s\n", groups[i][0], groups[i][1]);
			}

			free_list(groups, 2);
			continue;
		}
		// ===== SUBSCRIBE =====
		if (!strcmp(command, "subscribe") || !strcmp(command, "s")) {
			if (num_tokens != 3) {
				fprintf(stderr, "Invalid format. Usage: subscribe %s GID GName\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: user not logged in.\n");
				continue;
			}

			//if (!check_gid(arg1)) {
			//	printf("Error: GID %s is invalid.\n", arg1);
			//	continue;
			//} 

			status = subscribe_group(arg1, arg2);
			switch(status) {
				case STATUS_OK:
					printf("User with UID %s subscribed successfully to group %s with GID %s\n", get_uid(), arg2, arg1);
					continue;
				case STATUS_NEW_GROUP:
					printf("Created new group %s\n", arg2);
					continue;
				case STATUS_USR_INVALID: 
					printf("Error: UID %s is not valid\n", get_uid());
					continue;
				case STATUS_GID_INVALID: 
					printf("Error: GID %s is not valid\n", arg1);
					continue;
				case STATUS_GNAME_INVALID:
					printf("Error: Group name %s is not valid\n", arg2);
					continue;
				case STATUS_GROUPS_FULL:
					printf("Error: maximum number of groups reached (99)\n");
					continue;
				case STATUS_NOK:
					printf("Error subscribing to group %s with GID %s\n", arg2, arg1);
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
		}

		/* ===== UNSUBSCRIBE ===== */
		if (!strcmp(command, "unsubscribe") || !strcmp(command, "u")) {
			if (num_tokens != 2) {
				fprintf(stderr, "Invalid. Format: %s GID\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			if (!check_gid(arg1)) {
				printf("Error: GID %s is invalid.\n", arg1);
				continue;
			} 

			if (!check_if_subscribed(arg1)) {
				printf("Error: User is not subscribed to the group with GID %s.\n", arg1);
				continue;
			}

			status = unsubscribe_group(arg1);
			switch(status) {
				case STATUS_OK:
					printf("User with UID %s unsubscribed successfully from group with GID %s\n", get_uid(), arg1);
					continue;
				case STATUS_USR_INVALID: // TODO: see this
					printf("Error: UID %s is not valid\n", get_uid());
					continue;
				case STATUS_GID_INVALID: 
					printf("Error: Group name %s is not valid\n", arg1);
					continue;
				case STATUS_NOK:
					printf("Error unsubscribing from group with GID %s\n", arg1);
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
		}

		/* ===== MY GROUPS ===== */
		if (!strcmp(command, "my_groups") || !strcmp(command, "mgl")) {

			char ***groups;

			if (num_tokens != 1) {
				fprintf(stderr, "Invalid. Format: %s\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			status = get_subscribed_groups(&groups);
			switch (status) {
				case STATUS_OK:
					for (int i = 0; groups[i] != NULL; i++) {
						printf("%s %s\n", groups[i][0], groups[i][1]);
					}
					free_list(groups, 2);
					continue;
				case STATUS_USR_INVALID:
					printf("Error: Invalid UID.\n");
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
			continue;
		}

		/* ===== SELECT ===== */
		if (!strcmp(command, "select") || !strcmp(command, "sag")) {
			if (num_tokens != 2) {
				fprintf(stderr, "Invalid. Format: %s GID\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			if (!check_gid(arg1)) {
				printf("Error: GID %s is invalid.\n", arg1);
				continue;
			} 	
			
			if (!check_if_subscribed(arg1)) {
				printf("Error: User is not subscribed to the group with GID %s.\n", arg1);
				continue;
			}

			set_gid(arg1);
			printf("GID %s selected.\n", arg1);
			continue;
		}

		/* ===== SHOW GID ===== */
		if (!strcmp(command, "showgid") || !strcmp(command, "sg")) {
			if (num_tokens != 1) {
				fprintf(stderr, "Invalid. Format: %s\n", command);
				continue;
			}

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			} 

			if (!strcmp(get_gid(), "")) {
				printf("Error: no group is currently selected.\n");
				continue;
			}

			printf("Selected GID: %s\n", get_gid());
			continue;
		}

		/* ===== LIST UIDS IN CURRENT GROUP ===== */
		if (!strcmp(command, "ulist") || !strcmp(command, "ul")) {

			char ***uids;
		
			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			if (!strcmp(get_gid(), "")) {
				printf("Error: no group is currently selected.\n");
				continue;
			}

			status = get_uids_group(&uids);
			switch (status) {
				case STATUS_OK: 
					if (uids[0] == NULL) {
						printf("Group %s is not subscribed by any user.\n", get_gid());
						free_list(uids, 1);
						continue;
					}
					for (int i = 0; uids[i] != NULL; i++) {
						printf("%s\n", uids[i][0]);
					}
					free_list(uids, 1);
					continue;
				case STATUS_NOK:
					printf("Error: group %s does not exist.\n", get_gid());
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
		}

		/* ===== POST A MESSAGE ===== */
		if (!strcmp(command, "post")) {
			
			char *rest;
			char buf[MAX_TSIZE + 1];
			char mid[MID_SIZE + 1];	

			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			if (!strcmp(get_gid(), "")) {
				printf("Error: no group is currently selected.\n");
				continue;
			}

			if (num_tokens < 2) {
				printf("Error. Usage: post \"text\" [Fname].\n");
				continue;
			}

			/* rest points to message text */
			rest = line + (strlen(command) + 1) * sizeof(char);
			
			if (get_text(buf, rest) == FALSE) {
				printf("Invalid format. Usage: post \"text\" [Fname], where text has no more than 240 characters.\n");
				continue;
			}

			/* Check next character after text to see if there is a file 
			   Note that buf does not contain the 2 pairs of quotes */
			if (*(rest + strlen(buf) + 2) == '\n') { 
				status = post(buf, mid, NULL);

			} else if (*(rest + strlen(buf) + 2) == ' ') { 
				num_tokens = sscanf(rest + strlen(buf) + 2, " %" STR(MAX_ARG_SIZE) "s %" 
																 STR(MAX_ARG_SIZE) "s", arg2, arg3); 
				
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
					printf("Error during post.\n");
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
			
			continue;
		}

		/* ===== RETRIEVE UP TO 20 MESSAGES ===== */
		if (!strcmp(command, "retrieve") || !strcmp(command, "r")) {

			char *** list; 

			if (num_tokens != 2) {
				fprintf(stderr, "Invalid. Format: %s\n", command);
				continue;
			}
			
			if (!is_logged_in()) {
				printf("Error: User not logged in.\n");
				continue;
			}

			if (!strcmp(get_gid(), "")) {
				printf("Error: no group is currently selected.\n");
				continue;
			}

			if (!check_mid(arg1)) {
				printf("Error: invalid MID.\n");
				continue;
			}

			status = retrieve(arg1, &list);
			switch (status) {
				case STATUS_OK:
					for (int i = 0; list[i] != NULL; i++) {
						printf("%04d %s ", atoi(arg1) + i, list[i][0]);
						if (list[i][1] != NULL && list[i][2] != NULL) {
							printf("%s %s Bytes", list[i][1], list[i][2]);
						}
						putchar('\n');
					}
					free_list(list, 3);
					continue;
				case STATUS_NOK:
					printf("Error while retrieving messages.\n");
					continue;
				case STATUS_EOF:
					printf("There are no new messages to read.\n");
					continue;
				case STATUS_ERR:
					printf("Error during message reception by the server. Try again.\n");
					continue;
			}
		}

		if (!strcmp(command, "debug")) {
			char buf[MAX_TSIZE + 1];
			get_text(buf, line + strlen(command) + 1);
			buf[strlen(buf) + 1] = '\0';
			buf[strlen(buf)] = '\n';
			debug(buf);
			continue;
		}

		/* If another command token is received */
		printf("Invalid command.\n");

	}
}

/* Check if the user is subscribed to the group with GID gid */
int check_if_subscribed(char *gid) {
	char ***subscribed_groups;
	int status = get_subscribed_groups(&subscribed_groups);
	
	if (status != STATUS_OK) {
		return FALSE;
	}

	for (int i = 0; subscribed_groups[i] != NULL; i++) {
		if (!strcmp(subscribed_groups[i][0], gid)) {
			free_list(subscribed_groups, 2);
			return TRUE;
		}
	}

	free_list(subscribed_groups, 2);
	return FALSE;
}

/*	Parse text between quotes from buf and put it on str
	Input:
	- buf: the buffer with text
	- str: the string that will hold the unquoted text 
	Output
*/
int get_text(char *buf, char *str) {

	int i = 0;

	if (str[i++] != '\"') {
		return FALSE;
	}

	while ((buf[i - 1] = str[i]) != '\"') {
		if (str[i++] == '\n') {
			return FALSE;
		}
		if (i == MAX_TSIZE) {	
			return FALSE;
		}
	}

	buf[i - 1] ='\0';
	return TRUE;
}
