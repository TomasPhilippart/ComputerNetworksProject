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


int next_available_gid;

int check_user_registered(char *uid, char *user_dir);
int check_correct_password(char* uid, char *pass, char* user_dir, char *password_file);
int check_user_logged (char *uid, char *login_file);
int check_group_exists(char *gid, char *group_dir);
void create_group(char *group_name, char *group_dir, char *new_gid);

void setup_state() {
    /* Check for the next available GID */
    /* Iterate through dir directory and get the latest */
    char group_dir[11 + GID_SIZE];
    char gid[4];
    for (next_available_gid = 1; next_available_gid <= 99; next_available_gid++) {
        sprintf(gid, "%02d", next_available_gid);
        /* if group GID doesn't exist, it is now the next available one */
        if(check_group_exists(gid, group_dir) == FALSE) {
            break;
        }
    }
}

int register_user(char *uid, char *pass) {

    char user_dir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];
    FILE *file;

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid, user_dir) == TRUE) {
        return STATUS_NOK;
    }

    /* Create user directory */
    if (mkdir(user_dir, 0700) == -1) {
        printf("(REG) Error : Couldnt create new dir with path %s\n", user_dir);
        exit(EXIT_FAILURE);
    }

    sprintf(password_file, "%s/%s_pass.txt", user_dir, uid);

    /* Create user password file */
    if (!(file = fopen(password_file, "w"))) {
        printf("(REG) Error : Couldnt open file with path %s\n", password_file);
        exit(EXIT_FAILURE);
    }

    if (fwrite(pass, sizeof(char), strlen(pass), file) != strlen(pass)) {
        printf("(REG) Error : Couldnt write to file with path %s\n", password_file);
        exit(EXIT_FAILURE);
    }

    if (fclose(file) != 0) {
        printf("(REG) Error : Couldnt close file with path %s\n", password_file);
        exit(EXIT_FAILURE);
    }

    return STATUS_OK;
}

int unregister_user(char *uid, char *pass) {
    
    char user_dir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid, user_dir) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass, user_dir, password_file) == FALSE) {
        return STATUS_NOK;
    }

    /* Remove UID_pass.txt file from USERS/UID */
    if (unlink(password_file) != 0) {
        printf("(UNR) Error : removing password file from directory.\n");
        exit(EXIT_FAILURE);
    }

    /* Remove remove the directory USERS/UID */
    if (rmdir(user_dir) != 0) {
        printf("(UNR) Error : removing user directory with path %s.\n", user_dir);
        exit(EXIT_FAILURE);
    }

    return STATUS_OK;
}

int login_user(char *uid, char *pass) {
    
    FILE *file;
    char user_dir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];  
    char login_file[10 + UID_SIZE + UID_SIZE + 12];

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid, user_dir) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass, user_dir, password_file) == FALSE) {
        return STATUS_NOK;
    }

    /* Create login file */
    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);
    if (!(file = fopen(login_file, "w"))) {
        printf("(LOG) Error : creating login file.\n");
        exit(EXIT_FAILURE);
    }

    return STATUS_OK;
}

int logout_user(char *uid, char *pass) {

    char user_dir[10 + UID_SIZE], password_file[10 + UID_SIZE + UID_SIZE + 11];  
    char login_file[10 + UID_SIZE + UID_SIZE + 12];

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid, user_dir) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass, user_dir, password_file) == FALSE) {
        return STATUS_NOK;
    }

    /* Remove login file */
    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);

    if (check_user_logged(uid, login_file) == FALSE) {
        return STATUS_NOK;
    }

    if (unlink(login_file) != 0) {
        printf(" (OUT) Error removing login file\n");
        exit(EXIT_FAILURE);
    }

    return STATUS_OK;
}

int subscribe_group(char *uid, char *gid, char *group_name, char *new_gid) {

    // REVIEW which cases should return STATUS_NOK
    char user_dir[10 + UID_SIZE], group_dir[11 + GID_SIZE];
    char password_file[10 + UID_SIZE + UID_SIZE + 11], login_file[10 + UID_SIZE + UID_SIZE + 12];
    char group_uid_file[11 + GID_SIZE + UID_SIZE + 6];
    FILE *file;    

    /* Check UID */
    if (!check_uid(uid) || check_user_registered(uid, user_dir) == FALSE) {
        return STATUS_USR_INVALID;
    }

    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);
    if (check_user_logged(uid, login_file) == FALSE) {
        return STATUS_USR_INVALID;
    }

    /* Check GID: GID invalid OR group doesn't exist and isn't 00 */
    if ( (!check_gid(gid) && strcmp(gid, "00")) || (check_group_exists(gid, group_dir) == FALSE && strcmp(gid, "00"))) {
        return STATUS_GID_INVALID;
    } 
    
    /* Check GNAME */
    if (check_group_name(group_name) == FALSE ) {
        return STATUS_GNAME_INVALID;
    }


    /* Check if full */
    if (next_available_gid > 99) {
        return STATUS_GROUPS_FULL;
    }
    
    /* If GID = 00, create a new group with the next available GID */ 
    if (!strcmp(gid, "00")) {
        create_group(group_name, group_dir, new_gid);
    } 

    /* Subscribe existing group and create GROUPS/GID/uid.txt */
    sprintf(group_uid_file, "%s/%s.txt", group_dir, uid);
    
    if (!(file = fopen(group_uid_file, "w"))) {
        printf("Error creating group uid file.\n");
        exit(EXIT_FAILURE);
    }

    if (fclose(file) != 0) {
        printf("Error closing group uid file.\n");
        exit(EXIT_FAILURE);
    }
    
    /* REVIEW If a new group was created - this is meh */
    if (!strcmp(gid, "00")) {
        return STATUS_NEW_GROUP;
    }
    return STATUS_OK;
}   


int check_user_registered(char *uid, char *user_dir) {
    
    DIR* dir;

    sprintf(user_dir, "../USERS/%s", uid);
    dir = opendir(user_dir);

    if (!(dir)) {
        return FALSE;
    }

    // NOTE should do closedir(dir); ?
    closedir(dir);

    return TRUE;
}

int check_correct_password(char* uid, char *pass, char* user_dir, char *password_file) {
    
    FILE *file;
    char true_pass[PASSWORD_SIZE + 2];

    sprintf(password_file, "%s/%s_pass.txt", user_dir, uid);

    if (!(file = fopen(password_file, "r"))) {
        printf("Error opening password file with path %s.\n", password_file);
        exit(EXIT_FAILURE);
    }

    fread(true_pass, sizeof(char), PASSWORD_SIZE, file);

    if (strcmp(true_pass, pass)) {
        return FALSE;
    }

    if (fclose(file) != 0) {
        printf("Error closing password file.\n");
        exit(EXIT_FAILURE);
    }

    return TRUE;
}

    
int check_user_logged (char *uid, char *login_file) {
    FILE *file;

    if(access(login_file, F_OK) != 0 ) {
        return FALSE;
    }

    return TRUE;
}

int check_group_exists(char *gid, char *group_dir) {
    
    DIR* dir;

    sprintf(group_dir, "../GROUPS/%s", gid);
    dir = opendir(group_dir);

    if (!(dir)) {
        return FALSE;
    }

    // NOTE should do closedir(dir); ?
    closedir(dir);

    return TRUE; 
}

void create_group(char *group_name, char *group_dir, char *new_gid) {
    char group_name_file[10 + GID_SIZE + 1 + MAX_GNAME + 10];
    FILE *file;

    /* 1. Create GROUPS/GID*/
    sprintf(group_dir, "../GROUPS/%02d", next_available_gid);
    if (mkdir(group_dir, 0777) == -1) {
        printf("Error creating group directory.\n");
		exit(EXIT_FAILURE);
	}

    /* 2. Create GROUPS/GID/GID_name.txt with group name inside txt */
    sprintf(group_name_file, "%s/%02d_name.txt", group_dir, next_available_gid);

    if (!(file = fopen(group_name_file, "w"))) {
        printf("Error opening group name file.\n");
        exit(EXIT_FAILURE);
    }

    if (fwrite(group_name, sizeof(char), strlen(group_name), file) != strlen(group_name)) {
        printf("Error writing group name to file.\n");
        exit(EXIT_FAILURE);
    }

    if (fclose(file) != 0) {
        printf("Error closing group name file.\n");
        exit(EXIT_FAILURE);
    }

    /* 3. Create sub directory GROUPS/GID/MSG */
    sprintf(group_name_file, "%s/MSG", group_dir); /* Reusing group_name_file buffer*/
    if (mkdir(group_name_file, 0777) == -1) {
        printf("Error creating MSG sub directory.\n");
		exit(EXIT_FAILURE);
	}

    /* Increment next_available gid */
    sprintf(new_gid, "%02d", next_available_gid);
    next_available_gid++;
}