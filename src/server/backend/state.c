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
#include <dirent.h>


int next_available_gid;

int check_user_registered(char *uid, char *user_dir);
int check_user_subscribed(char *uid, char *gid);
int check_correct_password(char* uid, char *pass, char* user_dir, char *password_file);
int check_user_logged (char *uid, char *login_file);
int check_group_exists(char *gid, char *group_dir);
int check_message_exists(char *gid, char *mid, char *message_dir);
void create_group(char *group_name, char *group_dir, char *new_gid);

int get_group_name(char *gid, char *group_name);
int get_last_mid(char *gid, char *last_mid);

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
    if (mkdir(user_dir, 0700) == STATUS_FAIL) {
        printf("Error : Couldnt create new dir with path %s\n", user_dir);
        return STATUS_FAIL;
    }

    sprintf(password_file, "%s/%s_pass.txt", user_dir, uid);

    /* Create user password file */
    if (!(file = fopen(password_file, "w"))) {
        printf("Error : Couldnt open file with path %s\n", password_file);
        return STATUS_FAIL;
    }

    if (fwrite(pass, sizeof(char), strlen(pass), file) != strlen(pass)) {
        printf("Error : Couldnt write to file with path %s\n", password_file);
        return STATUS_FAIL;
    }

    if (fclose(file) != 0) {
        printf("Error : Couldnt close file with path %s\n", password_file);
        return STATUS_FAIL;
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
        printf("Error : removing password file from directory.\n");
        return STATUS_FAIL;
    }

    /* Remove remove the directory USERS/UID */
    if (rmdir(user_dir) != 0) {
        printf("Error : removing user directory with path %s.\n", user_dir);
        return STATUS_FAIL;
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
        printf("Error : creating login file.\n");
        return STATUS_FAIL;
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
        printf("Error : removing login file\n");
        return STATUS_FAIL;
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
        return STATUS_FAIL;
    }

    if (fclose(file) != 0) {
        printf("Error closing group uid file.\n");
        return STATUS_FAIL;
    }
    
    /* REVIEW If a new group was created - this is meh */
    if (!strcmp(gid, "00")) {
        return STATUS_NEW_GROUP;
    }
    return STATUS_OK;
}

int unsubscribe_user(char *uid, char *gid) {
    
    // TODO just can be tested before mgl implementation
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
    
    /* Check GID */
    if (!strcmp(gid, "00") || check_gid(gid) == FALSE || check_group_exists(gid, group_dir) == FALSE) {
        return STATUS_GID_INVALID;
    } 

    return STATUS_OK;
}

int user_subscribed_groups(char *uid, int *num_groups, char ****groups) {

    char user_dir[10 + UID_SIZE], login_file[10 + UID_SIZE + UID_SIZE + 12];
    char gid[GID_SIZE + 1];
    char last_mid[MID_SIZE + 1], group_name[MAX_GNAME + 1];

    // REVIEW 
    int max_groups = 1;
    (*groups) = (char ***) malloc(sizeof(char **) * max_groups);
    (*groups)[0] = (char **) malloc(sizeof(char *) * 3);
    // REVIEW esta nojento
    (*groups)[0][0] = (char *) malloc(sizeof(char) * (GID_SIZE + 1));
    (*groups)[0][1] = (char *) malloc(sizeof(char) * (MAX_GNAME + 1));
    (*groups)[0][2] = (char *) malloc(sizeof(char) * (MID_SIZE + 1));

    /* Check UID */
    if (!check_uid(uid) || check_user_registered(uid, user_dir) == FALSE) {
        return STATUS_USR_INVALID;
    }

    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);
    if (check_user_logged(uid, login_file) == FALSE) {
        return STATUS_USR_INVALID;
    }

    /* Loop through all created groups and verify is 
       UID is subscribed in that group 
    */

    for (int i = 1; i < next_available_gid; i++) {
        sprintf(gid, "%02d", i);
        if (check_user_subscribed(uid, gid)) {

            memset(group_name, '\0', strlen(group_name) * sizeof(char));
            memset(last_mid, '\0', strlen(last_mid) * sizeof(char));
        
            /* Get group name */
            if (get_group_name(gid, group_name) == STATUS_FAIL) {
                printf("Error : couldnt get gid = %s group_name", gid);
                return STATUS_FAIL;
            }

            if (get_last_mid(gid, last_mid) == STATUS_FAIL) {
                printf("Error : couldnt get last mid, from gid = %s", gid);
                return STATUS_FAIL;
            }

            if ((*num_groups) >= max_groups) {
                max_groups++;
                (*groups) = (char ***) realloc((*groups), sizeof(char **) * (max_groups));

                // REVIEW esta nojento
                (*groups)[max_groups - 1] = (char **) malloc(sizeof(char *) * 3);
                (*groups)[max_groups - 1][0] = (char *) malloc(sizeof(char) * (GID_SIZE + 1));
                (*groups)[max_groups - 1][1] = (char *) malloc(sizeof(char) * (MAX_GNAME + 1));
                (*groups)[max_groups - 1][2] = (char *) malloc(sizeof(char) * (MID_SIZE + 1));
            }

            strcpy((*groups)[max_groups - 1][0], gid);
            strcpy((*groups)[max_groups - 1][1], group_name);
            strcpy((*groups)[max_groups - 1][2], last_mid);


            (*num_groups)++;
        }
    }
    putchar('\n');

    return STATUS_OK;
}



/* ======== Auxiliary Functions ======== */
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

int check_user_subscribed(char *uid, char *gid) {

    char user_file[10 + GID_SIZE + UID_SIZE + 6];
    sprintf(user_file, "../GROUPS/%s/%s.txt", gid, uid);
    
    if(access(user_file, F_OK) != 0 ) {
        return FALSE;
    }

    return TRUE;
}

int check_correct_password(char* uid, char *pass, char* user_dir, char *password_file) {
    
    FILE *file;
    char true_pass[PASSWORD_SIZE + 2];

    sprintf(password_file, "%s/%s_pass.txt", user_dir, uid);

    if (!(file = fopen(password_file, "r"))) {
        printf("Error opening password file with path %s.\n", password_file);
        return STATUS_FAIL;
    }

    fread(true_pass, sizeof(char), PASSWORD_SIZE, file);

    if (strcmp(true_pass, pass)) {
        return FALSE;
    }

    if (fclose(file) != 0) {
        printf("Error closing password file.\n");
        return STATUS_FAIL;
    }

    return TRUE;
}

    
int check_user_logged (char *uid, char *login_file) {

    if(access(login_file, F_OK) != 0 ) {
        return FALSE;
    }

    return TRUE;
}

int check_group_exists(char *gid, char *group_dir) {
    // NOTE for the group to exist it needs to have a _name.txt file and a MSG folder
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

int check_message_exists(char *gid, char *mid, char *message_dir) {
    // NOTE for the message to exist it need to have a "T E X T.txt" e "A U T H O R.txt"
    DIR *dir;

    sprintf(message_dir, "../GROUPS/%s/MSG/%s/", gid, mid);
    dir = opendir(message_dir);

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
    if (mkdir(group_dir, 0777) == STATUS_FAIL) {
        printf("Error creating group directory.\n");
		return STATUS_FAIL;
	}

    /* 2. Create GROUPS/GID/GID_name.txt with group name inside txt */
    sprintf(group_name_file, "%s/%02d_name.txt", group_dir, next_available_gid);

    if (!(file = fopen(group_name_file, "w"))) {
        printf("Error opening group name file.\n");
        return STATUS_FAIL;
    }

    group_name[strlen(group_name)] = '\0';
    if (fwrite(group_name, sizeof(char), strlen(group_name), file) != strlen(group_name)) {
        printf("Error writing group name to file.\n");
        return STATUS_FAIL;
    }

    if (fclose(file) != 0) {
        printf("Error closing group name file.\n");
        return STATUS_FAIL;
    }

    /* 3. Create sub directory GROUPS/GID/MSG */
    sprintf(group_name_file, "%s/MSG", group_dir); /* Reusing group_name_file buffer*/
    if (mkdir(group_name_file, 0777) == STATUS_FAIL) {
        printf("Error creating MSG sub directory.\n");
		return STATUS_FAIL;
	}

    /* Increment next_available gid */
    sprintf(new_gid, "%02d", next_available_gid);
    next_available_gid++;
}

int get_group_name(char *gid, char *group_name) {

    FILE *file;
    char group_name_file[10 + GID_SIZE + GID_SIZE + 11];
    
    sprintf(group_name_file, "../GROUPS/%s/%s_name.txt", gid, gid);

    if (!(file = fopen(group_name_file, "r"))) {
        printf("Error opening group name file with path %s.\n", group_name_file);
        return STATUS_FAIL;
    }

    fread(group_name, sizeof(char), MAX_GNAME, file);

    if (fclose(file) != 0) {
        printf("Error closing group name file.\n");
        return STATUS_FAIL;
    }

    return SUCCESS;
}

int get_last_mid(char *gid, char *last_mid) {

    char message_dir[10 + GID_SIZE + 5 + MID_SIZE + 5];
    char mid[MID_SIZE + 1];

    for (int i = 1; i <= 9999; i++) {
        sprintf(mid, "%04d", i);

        if (check_message_exists(gid, mid, message_dir) == FALSE) {
            sprintf(last_mid, "%04d", i - 1);
            return SUCCESS;
        }
    }

    return STATUS_FAIL;
}