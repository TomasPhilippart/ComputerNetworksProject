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

    // NOTE should do closedir(dir); ?
    closedir(dir);

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

int unregister_user(char *uid, char *pass) {
    
    DIR* dir;
    char userdir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];
    FILE *file;

    char true_pass[PASSWORD_SIZE + 2];

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    sprintf(userdir, "../USERS/%s", uid);
    dir = opendir(userdir);

    if (!(dir)) {
        return STATUS_NOK;
    }

    // NOTE should do closedir(dir); ?
    closedir(dir);

    /* Check if the password is correct */
    sprintf(password_file, "%s/%s_pass.txt", userdir, uid);

    if (!(file = fopen(password_file, "r"))) {
        exit(EXIT_FAILURE);
    }

    fread(true_pass, sizeof(char), PASSWORD_SIZE, file);

    if (strcmp(true_pass, pass)) {
        return STATUS_NOK;
    }

    if (fclose(file) != 0) {
        exit(EXIT_FAILURE);
    }

    /* Remove UID_pass.txt file from USERS/UID */
    if (unlink(password_file) != 0) {
        exit(EXIT_FAILURE);
    }

    /* Remove remove the directory USERS/UID */
    if (rmdir(userdir) != 0) {
        exit(EXIT_FAILURE);
    }

    return STATUS_OK;
}


