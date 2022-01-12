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
#include <math.h>

#define USERS_DIR "../USERS"
#define GROUPS_DIR "../GROUPS"

#define USER_DIR "../USERS/xxxxxx"

// NOTE defines for directories?
int next_available_gid;

int check_user_subscribed(char *uid, char *gid);
int check_user_registered(char *uid, char *userdir);
int check_correct_password(char* uid, char *pass, char* user_dir, char *password_file);
int check_user_logged (char *uid, char *login_file);
int check_group_exists(char *gid, char *group_dir);
int check_message_exists(char *gid, char *mid, char *message_dir);
int create_group(char *group_name, char *group_dir, char *new_gid);
void free_groups(char ***groups, int num_groups);

int get_group_name(char *gid, char *group_name);
int get_last_mid(char *gid, char *last_mid);

void setup_state() {

    /* Check for the next available GID */
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

    // NOTE is this 0700?
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

/*  Getter for all groups
    Input:
    - num_groups: to be filled with the total number of groups
    - groups: to be filled with entries of the format [GID, GNAME, MID]
*/
int all_groups(int *num_groups, char ****groups) {
    
    char gid[GID_SIZE + 1];
    char last_mid[MID_SIZE + 1], group_name[MAX_GNAME + 1];

    (*groups) = (char ***) malloc(sizeof(char **) * (next_available_gid - 1));

    for (int i = 1; i < next_available_gid; i++) {
        sprintf(gid, "%02d", i);

        if (get_group_name(gid, group_name) == STATUS_FAIL) {
            printf("Error : couldnt get gid = %s group_name", gid);
            return STATUS_FAIL;
        }

        if (get_last_mid(gid, last_mid) == STATUS_FAIL) {
            printf("Error : couldnt get last mid, from gid = %s", gid);
            return STATUS_FAIL;
        }

        (*groups)[i - 1] = (char **) malloc(sizeof(char *) * 3);
        (*groups)[i - 1][0] = (char *) malloc(sizeof(char) * (GID_SIZE + 1));
        (*groups)[i - 1][1] = (char *) malloc(sizeof(char) * (MAX_GNAME + 1));
        (*groups)[i - 1][2] = (char *) malloc(sizeof(char) * (MID_SIZE + 1));

        strcpy((*groups)[i - 1][0], gid);
        strcpy((*groups)[i - 1][1], group_name);
        strcpy((*groups)[i - 1][2], last_mid);

        (*num_groups)++;
    }

    return STATUS_OK;
}

int subscribe_group(char *uid, char *gid, char *group_name, char *new_gid) {

    // REVIEW which cases should return STATUS_NOK
    char user_dir[10 + UID_SIZE], group_dir[11 + GID_SIZE];
    char login_file[10 + UID_SIZE + UID_SIZE + 12];
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
        if (create_group(group_name, group_dir, new_gid) == STATUS_FAIL) {
            printf("Error creating group.\n");
            return STATUS_FAIL;
        }
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
    
    if (!strcmp(gid, "00")) {
        return STATUS_NEW_GROUP;
    }
    return STATUS_OK;
}

int unsubscribe_user(char *uid, char *gid) {
    
    char user_dir[10 + UID_SIZE], group_dir[11 + GID_SIZE];
    char login_file[10 + UID_SIZE + UID_SIZE + 12];
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
    if (check_group_exists(gid, group_dir) == FALSE || !strcmp(gid, "00") || check_gid(gid) == FALSE) {
        return STATUS_GID_INVALID;
    } 

    /* Remove UID.txt file from GROUPS/GID */
    sprintf(group_uid_file, "%s/%s.txt", group_dir, uid);    
    if (unlink(group_uid_file) != 0) {
        printf("Error : user uid file from GROUPS/%s.\n", gid);
        return STATUS_FAIL;
    }

    return STATUS_OK;
}

/*  Getter for all user subscribed groups 
    Input:
    - uid: the user ID
    - num_groups: to be filled with the number of subscribed groups 
    - groups: to be filled with entries of the type {GID GName MID}
    Ouput: None
*/
int user_subscribed_groups(char *uid, int *num_groups, char ****groups) {

    char user_dir[10 + UID_SIZE], login_file[10 + UID_SIZE + UID_SIZE + 12];
    char gid[GID_SIZE + 1];
    char last_mid[MID_SIZE + 1], group_name[MAX_GNAME + 1];
    int base_size = 100;

    *num_groups = 0;
    if (((*groups) = (char ***) malloc(sizeof(char **) * base_size)) == NULL) {
        return STATUS_USR_INVALID;
    }

    /* Check UID */
    if (!(check_uid(uid) && check_user_registered(uid, user_dir))) { // NOTE: this is stupid as fuck
        return STATUS_USR_INVALID;
    }

    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);
    if (check_user_logged(uid, login_file) == FALSE) {
        return STATUS_USR_INVALID;
    }

    /* Loop through all created groups and verify is 
       UID is subscribed in that group */
    for (int i = 1; i < next_available_gid; i++) {
   
        sprintf(gid, "%02d", i);
        if (check_user_subscribed(uid, gid)) {

            /* Get group name */
            if (get_group_name(gid, group_name) == STATUS_FAIL) {
                printf("Error : couldnt get gid = %s group_name", gid);
                return STATUS_FAIL;
            }

            if (get_last_mid(gid, last_mid) == STATUS_FAIL) {
                printf("Error : couldnt get last mid, from gid = %s", gid);
                return STATUS_FAIL;
            }

            if (((*groups)[*num_groups] = (char **) malloc(3 * sizeof(char *))) == NULL) {
                free_groups(*groups, *num_groups);
                return STATUS_USR_INVALID;
            }

            if ((((*groups)[*num_groups][0] = (char *) malloc((GID_SIZE  + 1) * sizeof(char))) == NULL) ||
                (((*groups)[*num_groups][1] = (char *) malloc((MAX_GNAME  + 1) * sizeof(char))) == NULL) ||
                (((*groups)[*num_groups][2] = (char *) malloc((MID_SIZE  + 1) * sizeof(char))) == NULL)) {
                free_groups(*groups, *num_groups + 1);
                return STATUS_USR_INVALID;
            }

            strcpy((*groups)[*num_groups][0], gid);
            strcpy((*groups)[*num_groups][1], group_name);
            strcpy((*groups)[*num_groups][2], last_mid);
            (*num_groups)++;

            if ((*num_groups) % base_size == 0) {
                char *** aux = (char ***) realloc((*groups), sizeof(char **) * ((*num_groups) + base_size));
                if (aux == NULL) {
                    free_groups(*groups, *num_groups);
                    return STATUS_FAIL;
                }
                *groups = aux;
            }            
        }
    }

    return STATUS_OK;
}



/* ======== Auxiliary Functions ======== */

/*  Check if user with UID uid is registered
    Input:
    - uid: the UID
    - user_dir: to be filled with corresponding user_dir
    Output: TRUE or FALSE
*/
int check_user_registered(char *uid, char *user_dir) {

    DIR* dir;

    sprintf(user_dir, USERS_DIR "/%s", uid);
    dir = opendir(user_dir);

    if (!(dir)) {
        return FALSE;
    }
    closedir(dir);
    return TRUE;
}

// NOTE: enforcee maximum input sizes???
/*  Check if user with UID uid is subscribed to group with
    GID gid
    Input:
    - uid: the UID
    - gid: the gid
    Output: TRUE or FALSE
*/
int check_user_subscribed(char uid[UID_SIZE + 1], char *gid) {

    char user_file[10 + GID_SIZE + UID_SIZE + 6];
    sprintf(user_file, "../GROUPS/%s/%s.txt", gid, uid);
    
    if(access(user_file, F_OK) != 0 ) {
        return FALSE;
    }

    return TRUE;
}

/*  Check if pass is correct
    Input:
    - uid: the UID
    - gid: the pass
    Output: TRUE or FALSE
*/
int check_correct_password(char* uid, char *pass, char* user_dir, char *password_file) {
    
    FILE *file;
    char true_pass[PASSWORD_SIZE + 2];
    int num_bytes;

    sprintf(password_file, "%s/%s_pass.txt", user_dir, uid);

    if (!(file = fopen(password_file, "r"))) {
        printf("Error opening password file with path %s.\n", password_file);
        return STATUS_FAIL;
    }

    // note check this
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
    if(access(login_file, F_OK) != 0) {
        return FALSE;
    }
    return TRUE;
}

int check_group_exists(char *gid, char *group_dir) {
    DIR* dir;
    char path[MAX_BUF_SIZE];

    sprintf(group_dir, GROUPS_DIR "/%s", gid);
    dir = opendir(group_dir);

    if (!(dir)) {
        return FALSE;
    }
    closedir(dir);
   
    /* Check GID_name.txt file exists */
    memset(path, '\0', MAX_BUF_SIZE);
    sprintf(path, "%s/%s_name.txt", group_dir, gid);
    if(access(path, F_OK) != 0 ) {
        return FALSE;
    }
    
    /* Check MSG folder exists */
    memset(path, '\0', MAX_BUF_SIZE);
    sprintf(path, "%s/MSG", group_dir);
    dir = opendir(path);

    if (!(dir)) {
        return FALSE;
    }
    closedir(dir);

    return TRUE; 
}

int check_message_exists(char *gid, char *mid, char *message_dir) {
    DIR *dir;
    char path[MAX_BUF_SIZE];

    sprintf(message_dir, GROUPS_DIR "/%." STR(GID_SIZE) "s/MSG/%." STR(MID_SIZE) "s/", gid, mid);
    dir = opendir(message_dir);

    if (!(dir)) {
        return FALSE;
    }
    closedir(dir);

    /* Check T E X T.txt file exists */
    memset(path, '\0', MAX_BUF_SIZE);
    sprintf(path, "%s/T E X T.txt", message_dir);
    if (access(path, F_OK) != 0) {
        return FALSE;
    }

    /* Check A U T H O R.txt file exists */
    memset(path, '\0', MAX_BUF_SIZE);
    sprintf(path, "%s/A U T H O R.txt", message_dir);
    if (access(path, F_OK) != 0) {
        return FALSE;
    }
    printf("There is message %s in group %s\n", mid, gid);
    return TRUE;
}

int create_group(char *group_name, char *group_dir, char *new_gid) {
    
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
    return SUCCESS;
}

/*  Getter for group name of group with a given gid
    Input: 
    - gid: the group id
    - group_name: buffer to hold the group name
    Output: None
*/
int get_group_name(char *gid, char *group_name) {

    FILE *file;
    char group_name_file[strlen("../GROUPS/") + GID_SIZE  + strlen("/") + GID_SIZE + strlen("_name.txt") + 1]; 
    int read_bytes;
    
    sprintf(group_name_file, "../GROUPS/%." STR(GID_SIZE) "s/%." STR(GID_SIZE) "s_name.txt", gid, gid);
   
    if (!(file = fopen(group_name_file, "r"))) {
        printf("Error opening group name file with path %s.\n", group_name_file);
        return STATUS_FAIL;
    }
  
    if ((read_bytes = fread(group_name, sizeof(char), MAX_GNAME, file)) == 0) {
        printf("Error reading group name file with path %s.\n", group_name_file);
        return STATUS_FAIL;
    }
  
    group_name[read_bytes] = '\0';

    if (fclose(file) != 0) {
        printf("Error closing group name file.\n");
        return STATUS_FAIL;
    }

    return SUCCESS;
}

/*  Getter for the last message id in the group with
    a given gid.
    Input: 
    - gid: the group id
    - last_mid: buffer to hold the message id
    Output: None
*/
int get_last_mid(char *gid, char *last_mid) {

    char message_dir[strlen(GROUPS_DIR) + strlen("/") + GID_SIZE + strlen("/MSG/") + MID_SIZE];
    char mid[MID_SIZE + 1];

    for (int i = 1; i < pow(10, strlen(STR(MID_SIZE))); i++) {
        sprintf(mid, "%0" STR(MID_SIZE) "d", i);
        if (check_message_exists(gid, mid, message_dir) == FALSE) {
            sprintf(last_mid, "%04d", i - 1);
            return SUCCESS;
        }
    }

    return STATUS_FAIL;
}

void free_groups(char ***groups, int num_groups) {
    for (int i = 0; i < num_groups; i++) {
        if (groups[i]) {
            for (int j = 0; j < 3; j++) {
                free(groups[i][j]);
            }
            free(groups[i]);
        }
    }
    free(groups);
}