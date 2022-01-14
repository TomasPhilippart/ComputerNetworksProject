#include "aux_functions.h"
#include "constants.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <regex.h>
#include <string.h>
#include <ftw.h>

#define __USE_XOPEN_EXTENDED 500


// Check if UID is 5 digits and not 0000
int check_uid(char *uid) {
	return parse_regex(uid, "^[0-9]{5}$") && (atoi(uid) > 0);
}

// Check if GID is 2 digits and the user is subscribed to it
int check_gid(char *gid) {
	return parse_regex(gid, "^[0-9]{2}$");

}

int check_mid(char *mid) {
	return parse_regex(mid, "^[0-9]{4}$") && (atoi(mid) > 0);
}

int check_pass(char *pass) {
	return parse_regex(pass, "^[a-zA-Z0-9]{8}$");
}

int check_filename(char *filename) {

	if (!parse_regex(filename, "^[a-zA-Z0-9_.-]{1,20}.[a-zA-Z]{3}$")) {
		return FALSE;
	}
	
	// Check if file exists
	if ( access(filename, F_OK) != 0 ) {
		return FALSE;
	}

	return TRUE;
}

int check_group_name(char *group_name) {
	return parse_regex(group_name, "^[a-zA-Z0-9_-]{1,24}$");
}

/*	Check if a given expression is present in str 
	Input:
	- str: the string in which the expression is searched
	- regex: the regular expression to be matched 
	Output:
	- TRUE: if a match was found
	- FALSE: if a match was not found or an error ocurred 
	while matching regular expression
*/
int parse_regex(char *str, char *regex) {
    regex_t aux;
    int res;
   
    if (regcomp(&aux, regex, REG_EXTENDED)) {
        return FALSE;
    }

    res = regexec(&aux, str, 0, NULL, 0);
    if (!res) {
		regfree(&aux);
        return TRUE;
    }
	
	regfree(&aux);
	return FALSE;
}

/*	Flushable buffer constructor 
	Input: size of the buffer
	Output: the buffer
*/
Buffer new_buffer(int size) {
	Buffer new_buffer = (Buffer) malloc(sizeof(struct stru_Buffer));
	if (new_buffer == NULL) {
		return NULL;
	}
	if ((new_buffer->buf = (char *) malloc(sizeof(char) * (size + 1))) == NULL) {
		free(new_buffer);
		return NULL;
	}
	new_buffer->tail = 0;
	new_buffer->size = size;
	(new_buffer->buf)[new_buffer->tail] = '\0';	/* add this to make the contents printable */
	return new_buffer;
}

/*	Flush a buffer a given number of positions 
	Input: 
	positions: number of positions from the beginning to flush
	Output: None
*/
void flush_buffer(Buffer buffer, int positions) {
	int to_flush = MIN(positions, buffer->size);
	memcpy(buffer->buf, buffer->buf + to_flush, buffer->tail - to_flush);
	buffer->tail -= to_flush;
	(buffer->buf)[buffer->tail] = '\0';
}

/*	Append content to the end of the buffer, possibility truncanting the content
	Input: 
	- buffer: the buffer to which content is written
	- num_bytes: number of bytes to write
	- write_function: a write function 
	Return:
	- res: the result of the write function (normally the number of bytes)
*/
int write_to_buffer(Buffer buffer, int num_bytes, int (*write_function)(char *, int)) {

	int to_write = MIN(num_bytes,  (buffer->size - buffer->tail));
	int res = write_function(buffer->buf + buffer->tail, to_write);
	
	if (res > 0) {
		buffer->tail += res;
		(buffer->buf)[buffer->tail] = '\0';
	}
	return res;
}

/* Reset the buffer */
void reset_buffer(Buffer buffer) {
	buffer->tail = 0;
	(buffer->buf)[buffer->tail] = '\0';
}

/* Free buffer memory that was allocated */
void destroy_buffer(Buffer buffer) {
	free(buffer->buf);
	free(buffer);
}

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    int rv = remove(fpath);

    if (rv)
        perror(fpath);

    return rv;
}

/* Removes a path emulating a rf -rf command*/
int rmrf(char *path) {
    return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}