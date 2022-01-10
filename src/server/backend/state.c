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


int check_user_registered(char *uid, char *userdir);
int check_correct_password(char* uid, char *pass, char* userdir, char *password_file);

int register_user(char *uid, char *pass) {

    char userdir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];
    FILE *file;

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid, userdir) == TRUE) {
        return STATUS_NOK;
    }

    /* Create user directory */
    if (mkdir(userdir, 0700) == -1) {
        exit(EXIT_FAILURE);
    }

    sprintf(password_file, "%s/%s_pass.txt", userdir, uid);

    /* Create user password file */
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
    
    char userdir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid, userdir) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass, userdir, password_file) == FALSE) {
        return STATUS_NOK;
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

int login_user(char *uid, char *pass) {
    
    FILE *file;
    char userdir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];  
    char login_file[10 + UID_SIZE + UID_SIZE + 12];

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid, userdir) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass, userdir, password_file) == FALSE) {
        return STATUS_NOK;
    }

    /* Create login file */
    sprintf(login_file, "%s/%s_login.txt", userdir, uid);
    if (!(file = fopen(login_file, "w"))) {
        exit(EXIT_FAILURE);
    }

    return STATUS_OK;
}

int logout_user(char *uid, char *pass) {

    char userdir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];  
    char login_file[10 + UID_SIZE + UID_SIZE + 12];

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid, userdir) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass, userdir, password_file) == FALSE) {
        return STATUS_NOK;
    }

    /* Remove login file */
    sprintf(login_file, "%s/%s_login.txt", userdir, uid);

    // NOTE check if UID_login.txt (user is logged in) before removing it?
    if (check_user_logged(uid, login_file) == FALSE) {
        return STATUS_NOK;
    }

    if (unlink(login_file) != 0) {
        exit(EXIT_FAILURE);
    }

    return STATUS_OK;
}

int subscribe_group(char *uid, char *gid, char *gName, char *newGID) {

    char gGID[GID_SIZE + 1];

    /* Check UID */
    if (!((check_user_logged(uid, login_file) == TRUE) && !check_uid(uid))) {
        return STATUS_USR_INVALID;
    }

    /* Check GID */
    // GID valido + grupo existe ou GID = 00

    /* Check GNAME */
    // verificar se o group name esta bem formatado
    // NOTE isto nunca vai dar erro pois estamos a verificar a boa formatação
    // com o regex

    /* Check Full */
    // iterar pelos grupos e verificar se o grupo 99 já foi criado
    if (strcmp(gGID, "99")) {
        return STATUS_GROUPS_FULL;
    }
    
    /* Verificar se é para criar novo grupo ou subscrever a um existente */
    if (strcpy(gid, "00")) {
        /* criar grupo : criar a diretoria GROUPS/GID + GROUPS/GID/GID_name.txt + GROUPS/GID/MSG */
        // guardar novo gid (gGID + 1) na variavel newGID 
        return STATUS_NEW_GROUP;
    }

    /* subscrever a um grupo existente : criar o ficheiro GROUPS/GID/UID.txt */
    return STATUS_OK;
}


int check_user_registered(char *uid, char *userdir) {
    
    DIR* dir;

    sprintf(userdir, "../USERS/%s", uid);
    dir = opendir(userdir);

    if (!(dir)) {
        return FALSE;
    }

    // NOTE should do closedir(dir); ?
    closedir(dir);

    return TRUE;
}

int check_correct_password(char* uid, char *pass, char* userdir, char *password_file) {
    
    FILE *file;
    char true_pass[PASSWORD_SIZE + 2];

    sprintf(password_file, "%s/%s_pass.txt", userdir, uid);

    if (!(file = fopen(password_file, "r"))) {
        exit(EXIT_FAILURE);
    }

    fread(true_pass, sizeof(char), PASSWORD_SIZE, file);

    if (strcmp(true_pass, pass)) {
        return FALSE;
    }

    if (fclose(file) != 0) {
        exit(EXIT_FAILURE);
    }

    return TRUE;
}

int check_user_logged (char *uid, char *login_file) {
    // TODO
    return TRUE;
}