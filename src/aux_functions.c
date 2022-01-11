#include "aux_functions.h"
#include "constants.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <regex.h>

// Check if UID is 5 digits and not 0000
int check_uid(char *uid) {
	if (parse_regex(uid, "^[0-9]{5}$") == FALSE || (atoi(uid) <= 0)) {
		return FALSE;
	}

	return TRUE;
}

// Check if GID is 2 digits and the user is subscribed to it
int check_gid(char *gid) {
	if (parse_regex(gid, "^[0-9]{2}$") == FALSE) {
		return FALSE;
	}

	return TRUE;
}

int check_mid(char *mid) {
	if (parse_regex(mid, "^[0-9]{4}$") == FALSE || atoi(mid) <= 0) {
		return FALSE;
	}

	return TRUE;
}


int check_pass(char *pass) {
	
	if (!parse_regex(pass, "^[a-zA-Z0-9]{8}$")) {
		return FALSE;
	}

	return TRUE;
}

int check_filename(char *filename) {
	// filename[i] == '_' || filename[i] == '.' || filename[i] == '-'
	if (parse_regex(filename, "^[a-zA-Z0-9_.-]{1,20}.[a-z0-9]{3}$") == FALSE) {
		return FALSE;
	}
	
	// Check if file exists
	if ( access(filename, F_OK) != 0 ) {
		return FALSE;
	}

	return TRUE;
}

int check_group_name(char *group_name) {
	if (parse_regex(group_name, "^[a-zA-Z0-9_-]{1,24}$") == FALSE) {
		return FALSE;
	}

	return TRUE;
}

int parse_regex(char *str, char *regex) {
    regex_t aux;
    int res;
   
    if (regcomp(&aux, regex, REG_EXTENDED)) {
		printf("Error: Compiling the following regex expression %s.\n", regex);
        exit(EXIT_FAILURE);
    }

    res = regexec(&aux, str, 0, NULL, 0);
    if (!res) {
        return TRUE;
    } else if (res == REG_NOMATCH) {
        return FALSE;
    } else {
		printf("Error : Executing the following regex expression %s.\n", regex);
        exit(EXIT_FAILURE);
    }
}