#include "../../constants.h"
#include "../../aux_functions.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
// NOTE remove just for debug
#include <errno.h>
#include <dirent.h>

int register_user(char *uid, char *pass) {

    DIR* dir;
    char userdir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];
    FILE *file;

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    sprintf(userdir, "../USERS/%s", uid);
    dir = opendir(userdir);

    /* Check if user is already registred */
    if (dir) {
        return STATUS_DUP;
    }

    if (mkdir(userdir, 0700) == -1) {
        exit(EXIT_FAILURE);
    }
    sprintf(password_file, "%s/%s_pass.txt", userdir, uid);

    if (!(file = fopen(password_file, "w"))) {
        exit(EXIT_FAILURE);
    }

    if (fwrite(pass, sizeof(char), strlen(pass), file) != strlen(pass)) {
        exit(EXIT_FAILURE);
    }

    if (fclose(file) != 0) {
        exit(EXIT_FAILURE);
    }

    return STATUS_OK;
}


