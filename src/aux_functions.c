#include "aux_functions.h"
#include "constants.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

// Check if UID is 5 digits and not 0000
int check_uid(char *uid) {
	return strlen(uid) == 5 && atoi(uid) > 0;
}

// Check if GID is 2 digits and the user is subscribed to it
int check_gid(char *gid) {
	return strlen(gid) == 2 && atoi(gid) > 0;
}

int check_mid(char *mid) {
	return strlen(mid) == 4 && atoi(mid) > 0;
}


// NOTE: Make this function a wrapper of a regex validator 
// Check if password is alphanumeric and has 8 characters
int check_pass(char *pass) {
	if (strlen(pass) != PASSWORD_SIZE) {
		return FALSE;
	}

	for (int i = 0; i < strlen(pass); i++) {
		if (!isalnum(pass[i])) {
			return FALSE;
		}
	}
	return TRUE;
}

int check_filename(char *filename) {

	if (!((strlen(filename) < MAX_FNAME) && (strlen(filename) > EXTENSION_SIZE + 2))) {
		return FALSE;
	}

	for (int i = 0; i < strlen(filename); i++) {
		if (!(filename[i] == '_' || filename[i] == '.' || filename[i] == '-'|| isalnum(filename[i]))) {
			return FALSE;
		}
	}

	// Check extension separating dot
	if (!(filename[strlen(filename) - EXTENSION_SIZE - 1] == '.')) {
		return FALSE;
	}

	// Check extension is 3 letters
	for (int i = strlen(filename) - 3; i < strlen(filename); i++) {
		if (!(isalpha(filename[i]))) {
			return FALSE;
		}
	}
	
	// Check if file exists
	if (access(filename, F_OK ) != 0 ) {
		return FALSE;
	}

	return TRUE;
}