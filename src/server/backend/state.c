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

#define USERS_DIR "../USERS/"
#define GROUPS_DIR "../GROUPS/"

/* User paths */
#define USER_DIR "../USERS/xxxxx/"
#define LOGIN_FILE "../USERS/xxxxx/xxxxx_login.txt"
#define PASSWORD_FILE "../USERS/xxxxx/xxxxx_pass.txt"

#define LOGIN_FILE_EXTENSION "_login.txt"
#define PASSWORD_FILE_EXTENSION "_pass.txt"


/* Group paths */
#define GROUP_DIR "../GROUPS/xx/"
#define MSG_DIR "../GROUPS/xx/MSG/"
#define USER_FILE "../GROUPS/xx/xxxxx.txt"
#define GNAME_FILE "../GROUPS/xx/xx_name.txt"
#define TEXT_FILE "../GROUPS/xx/MSG/T E X T.txt"
#define AUTHOR_FILE "../GROUPS/xx/MSG/A U T H O R.txt"

#define MSG_DIR_EXTENSION "MSG"
#define USER_FILE_EXTENSION ".txt"
#define GNAME_FILE_EXTENSION "_name.txt"
#define TEXT_FILE_EXTENSION "T E X T.txt"
#define AUTHOR_FILE_EXTENSION "A U T H O R.txt"

int next_available_gid;

int check_user_subscribed(char *uid, char *gid);
int check_user_registered(char *uid);
int check_correct_password(char* uid, char *pass);
int check_user_logged (char *uid);
int check_group_exists(char *gid);
int check_message_exists(char *gid, char *mid);
int create_group(char *group_name, char *new_gid);
void free_groups(char ***groups, int num_groups);
int logout_user(char *uid, char *pass);

int get_group_name(char *gid, char *group_name);
int get_last_mid(char *gid, char *last_mid);

char* generate_user_dir (char *uid); 
char* generate_group_dir (char *gid); 
char* generate_login_file (char *uid); 
char *generate_password_file (char *uid); 
char *generate_gname_file(char *gid);
char *generate_msg_dir(char *gid);
char *generate_user_file (char *gid, char *uid);
char* generate_text_file(char *gid);
char* generate_author_file(char *gid); 

// NOTE make connection on timer

void setup_state() {

    /* Check for the next available GID */
    char gid[GID_SIZE + 1] = "";

    for (next_available_gid = 1; next_available_gid <= 99; next_available_gid++) {
        sprintf(gid, "%02d", next_available_gid);
       
        /* if group GID doesn't exist, it is now the next available one */
        if(check_group_exists(gid) == FALSE) {
            break;
        }
    }
}

int register_user(char *uid, char *pass) {
    char *user_dir, *password_file;
    FILE *file;

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid) == TRUE) {
        return STATUS_DUP;
    }

    if ((user_dir = generate_user_dir(uid)) == NULL) {
        printf("Error: Couldn't generate user directory.\n");
        return STATUS_FAIL;
    }
    
    /* Create user directory */
    if (mkdir(user_dir, 0777) == STATUS_FAIL) {
        printf("Error : Couldn't create new dir with path %s\n", user_dir);
        free(user_dir);
        return STATUS_FAIL;
    }

    free(user_dir);

    if ((password_file = generate_password_file(uid)) == NULL) {
        return STATUS_FAIL;
    }

    /* Create user password file */
    if (!(file = fopen(password_file, "w"))) {
        printf("Error : Couldn't open file with path %s\n", password_file);
        free(password_file);
        return STATUS_FAIL;
    }

    if (fwrite(pass, sizeof(char), strlen(pass), file) != strlen(pass)) {
        printf("Error : Couldnt write to file with path %s\n", password_file);
        free(password_file);
        return STATUS_FAIL;
    }

    if (fclose(file) != 0) {
        printf("Error : Couldnt close file with path %s\n", password_file);
        free(password_file);
        return STATUS_FAIL;
    }

    free(password_file);
    return STATUS_OK;
}

int unregister_user(char *uid, char *pass) {
    
    char *user_dir, *password_file, *login_file;

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass) == FALSE) {
        return STATUS_NOK;
    }

    /* If unregistering a logged in user, force logout first */
    if (check_user_logged(uid)) {
        if (logout_user(uid, pass) != STATUS_OK) {
            printf("Error: Logging out when unregistering UID %s,\n", uid);
            return STATUS_FAIL;
        }
    }

    if ((password_file = generate_password_file(uid)) == NULL) {
        return STATUS_FAIL;
    }

    /* Remove UID_pass.txt file from USERS/UID */
    if (unlink(password_file) != 0) {
        printf("Error: Removing password file from directory.\n");
        free(password_file);
        return STATUS_FAIL;
    }

    free(password_file);

    if ((user_dir = generate_user_dir(uid)) == NULL) {
        return STATUS_FAIL;
    }

    /* Remove remove the directory USERS/UID */
    if (rmdir(user_dir) != 0) {
        printf("Error: Removing user directory with path %s.\n", user_dir);
        free(user_dir);
        return STATUS_FAIL;
    }

    free(user_dir);
    return STATUS_OK;
}

int login_user(char *uid, char *pass) {
    
    FILE *file;
    char *user_dir, *password_file;  
    char *login_file;

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass) == FALSE) {
        return STATUS_NOK;
    }

    /* Create login file */
    if ((login_file = generate_login_file(uid)) == NULL) {
        return STATUS_FAIL;
    }

    if (!(file = fopen(login_file, "w"))) {
        printf("Error: Creating login file.\n");
        free(login_file);
        return STATUS_FAIL;
    }

    free(login_file);
    return STATUS_OK;
}

int logout_user(char *uid, char *pass) {

    char *login_file;

    if (!(check_uid(uid) && check_pass(pass))) {
        return STATUS_NOK;
    }

    /* Check if the uid is registed */
    if (check_user_registered(uid) == FALSE) {
        return STATUS_NOK;
    }

    /* Check if the password is correct */
    if (check_correct_password(uid, pass) == FALSE) {
        return STATUS_NOK;
    }

    /* Remove login file */
    if (check_user_logged(uid) == FALSE) {
        return STATUS_NOK;
    }

    if ((login_file = generate_login_file(uid)) == NULL) {
        return STATUS_FAIL;
    }
    
    if (unlink(login_file) != 0) {
        printf("Error: Removing login file\n");
        free(login_file);
        return STATUS_FAIL;
    }

    free(login_file);
    return STATUS_OK;
}

/*  Getter for all groups
    Input:
    - num_groups: to be filled with the total number of groups
    - groups: to be filled with entries of the format [GID, GNAME, MID]
*/
int all_groups(int *num_groups, char ****groups) {
    
    char gid[GID_SIZE + 1] = "";
    char last_mid[MID_SIZE + 1] = "";
    char group_name[MAX_GNAME + 1] = "";

    (*num_groups) = 0;
    if (((*groups) = (char ***) malloc(sizeof(char **) * (next_available_gid - 1))) == NULL) {
        return STATUS_FAIL;
    }

    for (int i = 1; i < next_available_gid; i++) {
        
        sprintf(gid, "%02d", i);

        if (get_group_name(gid, group_name) == STATUS_FAIL) {
            printf("Error: Couldn't get GID %s's group name.\n", gid);
            return STATUS_FAIL;
        }

        if (get_last_mid(gid, last_mid) == STATUS_FAIL) {
            printf("Error: Couldn't get last MID from GID %s\n", gid);
            return STATUS_FAIL;
        }

        if (((*groups)[i - 1] = (char **) malloc(3 * sizeof(char *))) == NULL) {
            free_groups(*groups, *num_groups);
            return STATUS_USR_INVALID;
        }

        /*
        if ((((*groups)[i - 1][0] = (char *) malloc((GID_SIZE  + 1) * sizeof(char))) == NULL) ||
            (((*groups)[i - 1][1] = (char *) malloc((MAX_GNAME  + 1) * sizeof(char))) == NULL) ||
            (((*groups)[i - 1][2] = (char *) malloc((MID_SIZE  + 1) * sizeof(char))) == NULL)) {
            free_groups(*groups, *num_groups + 1);
            printf("error malloc\n");
            return STATUS_USR_INVALID;
        }
        */
        (*groups)[i - 1][0] = (char *) malloc((GID_SIZE  + 1) * sizeof(char));
        
        (*groups)[i - 1][1] = (char *) malloc((MAX_GNAME  + 1) * sizeof(char));

        (*groups)[i - 1][2] = (char *) malloc((MID_SIZE  + 1) * sizeof(char));
        
        strcpy((*groups)[i - 1][0], gid);
        memset((*groups)[i - 1][1], '\0', MAX_GNAME + 1);
        strcpy((*groups)[i - 1][1], group_name);
        strcpy((*groups)[i - 1][2], last_mid);

        (*num_groups)++;
    }

    return STATUS_OK;
}

int subscribe_group(char *uid, char *gid, char *group_name, char *new_gid) {

    // REVIEW which cases should return STATUS_NOK
    int new_group_created = FALSE;
    char *user_file;
    FILE *file;    

    /* Check UID */
    if (!check_uid(uid) || check_user_registered(uid) == FALSE) {
        return STATUS_USR_INVALID;
    }

    if (check_user_logged(uid) == FALSE) {
        return STATUS_USR_INVALID;
    }

    /* Check GID: GID invalid OR group doesn't exist and isn't 00 */
    if ( (!check_gid(gid) && strcmp(gid, "00")) || (check_group_exists(gid) == FALSE && strcmp(gid, "00"))) {
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
        if (create_group(group_name, new_gid) == STATUS_FAIL) {
            printf("Error creating group.\n");
            return STATUS_FAIL;
        }
        strcpy(gid, new_gid);
        new_group_created = TRUE;
    } 
   
    /* Subscribe existing group and create GROUPS/GID/uid.txt */
    if ((user_file = generate_user_file(gid, uid)) == NULL) {
        return STATUS_FAIL;
    }
    
    if (!(file = fopen(user_file, "w"))) {
        printf("Error creating group uid file.\n");
        free(user_file);
        return STATUS_FAIL;
    }
    
    free(user_file);

    if (fclose(file) != 0) {
        printf("Error closing group uid file.\n");
        return STATUS_FAIL;
    }
    
    if (new_group_created == TRUE) {
        return STATUS_NEW_GROUP;
    }

    return STATUS_OK;
}

int unsubscribe_user(char *uid, char *gid) {
    
    char *user_file;
    FILE *file;  

    /* Check UID */
    if (!check_uid(uid) || check_user_registered(uid) == FALSE) {
        return STATUS_USR_INVALID;
    }

    if (check_user_logged(uid) == FALSE) {
        return STATUS_USR_INVALID;
    }
    
    /* Check GID */
    if (check_group_exists(gid) == FALSE || !strcmp(gid, "00") || check_gid(gid) == FALSE) {
        return STATUS_GID_INVALID;
    } 

    if ((user_file = generate_user_file(gid, uid)) == NULL) {
        return STATUS_FAIL;
    }

    /* Remove UID.txt file from GROUPS/GID */
    if (unlink(user_file) != 0) {
        printf("Error : user uid file from GROUPS/%s.\n", gid);
        free(user_file);
        return STATUS_FAIL;
    }

    free(user_file);
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

    char gid[GID_SIZE + 1];
    char last_mid[MID_SIZE + 1], group_name[MAX_GNAME + 1];
    int base_size = 100;

    *num_groups = 0;
    if (((*groups) = (char ***) malloc(sizeof(char **) * base_size)) == NULL) {
        return STATUS_USR_INVALID;
    }

    /* Check UID */
    if (!(check_uid(uid) && check_user_registered(uid))) {
        return STATUS_USR_INVALID;
    }

    if (check_user_logged(uid) == FALSE) {
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

// NOTE some auxiliary funcions are returning STATUS_FAIL that isnt  
// been checked for when the same function is called by the server

/*  Check if user with UID uid is registered
    Input:
    - uid: the UID
    - user_dir: to be filled with corresponding user_dir
    Output: TRUE or FALSE
*/
int check_user_registered(char *uid) {

    DIR* dir;
    char *user_dir, *password_file;
    
    if ((user_dir = generate_user_dir(uid)) == NULL) {
        return STATUS_FAIL;
    }

    dir = opendir(user_dir);

    if (!(dir)) {
        free(user_dir);
        return FALSE;
    }

    free(user_dir);
    closedir(dir);

    if ((password_file = generate_password_file(uid)) == NULL) {
        return STATUS_FAIL;
    }

    if(access(password_file, F_OK) != 0 ) {
        free(password_file);
        return FALSE;
    }

    free(password_file);
    return TRUE;
}

/*  Check if user with UID uid is subscribed to group with
    GID gid
    Input:
    - uid: the UID
    - gid: the GID
    Output: TRUE or FALSE
*/
int check_user_subscribed(char *uid, char *gid) {

    char *user_file;

    if ((user_file = generate_user_file(gid, uid)) == NULL) {
        return STATUS_FAIL;
    }
    
    if(access(user_file, F_OK) != 0 ) {
        free(user_file);
        return FALSE;
    }

    free(user_file);
    return TRUE;
}

/*  Check if pass is correct
    Input:
    - uid: the UID
    - gid: the pass
    Output: TRUE or FALSE
*/
int check_correct_password(char* uid, char *pass) {
    
    FILE *file;
    char *password_file;
    char true_pass[PASSWORD_SIZE + 2] = "";
    int num_bytes;

    if ((password_file = generate_password_file(uid)) == NULL) {
        return STATUS_FAIL;
    }

    if (!(file = fopen(password_file, "r"))) {
        printf("Error opening password file with path %s.\n", password_file);
        free(password_file);
        return STATUS_FAIL;
    }

    if ((num_bytes = fread(true_pass, sizeof(char), PASSWORD_SIZE, file)) == 0) {
        printf("Error reading password file with path %s.\n", password_file);
        free(password_file);
        return STATUS_FAIL;
    }

    if (fclose(file) != 0) {
        printf("Error closing password file.\n");
        free(password_file);
        return STATUS_FAIL;
    }

    if (strcmp(true_pass, pass)) {
        free(password_file);
        return FALSE;
    }

    free(password_file);
    return TRUE;
}

/*  Check if the user with UID = uid is logged in
    Input:
    - uid: the UID
    Output: TRUE or FALSE
*/
int check_user_logged (char *uid) {

    char *login_file;

    if ((login_file = generate_login_file(uid)) == NULL) {
        return STATUS_FAIL;
    }

    if(access(login_file, F_OK) != 0) {
        free(login_file);
        return FALSE;
    }

    free(login_file);
    return TRUE;
}

int check_group_exists(char *gid) {
    DIR* dir;

    char *group_dir, *msg_dir, *gname_file;

    if ((group_dir = generate_group_dir(gid)) == NULL) {
        return STATUS_FAIL;
    }

    dir = opendir(group_dir);

    if (!(dir)) {
        free(group_dir);
        return FALSE;
    }
    closedir(dir);
    free(group_dir);
   
    /* Check GID_name.txt file exists */
    if ((gname_file = generate_gname_file(gid)) == NULL) {
        return STATUS_NOK;
    }

    if(access(gname_file, F_OK) != 0 ) {
        free(gname_file);
        return FALSE;
    }

    free(gname_file);

    /* Check MSG folder exists */
    if ((msg_dir = generate_msg_dir(gid)) == NULL) {
        return STATUS_FAIL;
    }

    dir = opendir(msg_dir);

    if (!(dir)) {
        free(msg_dir);
        return FALSE;
    }
    closedir(dir);
    free(msg_dir);

    return TRUE; 
}

int check_message_exists(char *gid, char *mid) {
    DIR *dir;
    char *msg_dir, *text_file, *author_file;

    if ((msg_dir = generate_msg_dir(gid)) == NULL) {
        return STATUS_FAIL;
    }

    dir = opendir(msg_dir);

    if (!(dir)) {
        free(msg_dir);
        return FALSE;
    }
    free(msg_dir);
    closedir(dir);

    /* Check T E X T.txt file exists */
    if ((text_file = generate_text_file(gid)) == NULL) {
        return STATUS_FAIL;
    }
    
    if (access(text_file, F_OK) != 0) {
        free(text_file);
        return FALSE;
    }
    free(text_file);

    /* Check A U T H O R.txt file exists */
    if ((author_file = generate_author_file(gid)) == NULL) {
        return STATUS_FAIL;
    }

    printf("author_file : %s\n", author_file);

    if (access(author_file, F_OK) != 0) {
        free(author_file);
        return FALSE;
    }

    free(author_file);
    return TRUE;
}

int create_group(char *group_name, char *new_gid) {
    
    // NOTE if in the middle of creating a group it fails need 
    // to delete all files crated before the bug occurred
    FILE *file;
    char *group_dir, *gname_file, *msg_dir;

    sprintf(new_gid, "%02d", next_available_gid);

    /* 1. Create GROUPS/GID*/
    if ((group_dir = generate_group_dir(new_gid)) == NULL) {
        return STATUS_FAIL;
    }
    
    if (mkdir(group_dir, 0777) == STATUS_FAIL) {
        printf("Error creating group directory.\n");
        free(group_dir);
		return STATUS_FAIL;
	}
    free(group_dir);

    /* 2. Create GROUPS/GID/GID_name.txt with group name inside txt */
    if ((gname_file = generate_gname_file(new_gid)) == NULL) {
        return STATUS_FAIL;
    }

    if (!(file = fopen(gname_file, "w"))) {
        printf("Error opening group name file.\n");
        free(gname_file);
        return STATUS_FAIL;
    }
    free(gname_file);

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
    if ((msg_dir = generate_msg_dir(new_gid)) == NULL) {
        return STATUS_FAIL;
    }

    if (mkdir(msg_dir, 0777) == STATUS_FAIL) {
        printf("Error creating MSG sub directory.\n");
		return STATUS_FAIL;
	}

    /* Increment next_available gid */
    next_available_gid++;
    return SUCCESS;
}

/*  Getter for group name of group with a given gid
    Input: 
    - gid: the group id
    - group_name: buffer to hold the path to the group name file
    Output: None
*/
int get_group_name(char *gid, char *group_name) {

    FILE *file;
    char *gname_file;
    int read_bytes;
    
    if ((gname_file = generate_gname_file(gid)) == NULL) {
        return STATUS_FAIL;
    }
   
    if (!(file = fopen(gname_file, "r"))) {
        printf("Error opening group name file with path %s.\n", gname_file);
        free(gname_file);
        return STATUS_FAIL;
    }
  
    if ((read_bytes = fread(group_name, sizeof(char), MAX_GNAME, file)) == 0) {
        printf("Error reading group name file with path %s.\n", gname_file);
        free(gname_file);
        return STATUS_FAIL;
    }
    free(gname_file);
  
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

    char mid[MID_SIZE + 1] = "";

    for (int i = 1; i < pow(10, strlen(STR(MID_SIZE))); i++) {
        sprintf(mid, "%0" STR(MID_SIZE) "d", i);

        if (check_message_exists(gid, mid) == FALSE) {
            sprintf(last_mid, "%0" STR(MID_SIZE) "d", i - 1);
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


/* Generate DS path files */
char *generate_user_dir (char *uid) {
    
    char *user_dir = NULL;

    if (strlen(uid) != UID_SIZE) {
        return NULL;
    }

    if ((user_dir = (char *) malloc((strlen(USER_DIR) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(user_dir, USERS_DIR "%." STR(UID_SIZE) "s/", uid);
    return user_dir;
}

char *generate_group_dir (char *gid) {
    
    char *group_dir = NULL;

    if (strlen(gid) != GID_SIZE) {
        return group_dir;
    }

    if ((group_dir = (char *) malloc((strlen(GROUP_DIR) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(group_dir, GROUPS_DIR "%." STR(GID_SIZE) "s/", gid);

    return group_dir;
}

char *generate_login_file (char *uid) {
    
    char *login_file = NULL;
    char *user_dir = generate_user_dir(uid);

    if (user_dir == NULL) {
        return login_file;
    }

    if ((login_file = (char *) malloc((strlen(LOGIN_FILE) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(login_file, "%s%." STR(UID_SIZE) "s" LOGIN_FILE_EXTENSION, user_dir, uid);

    free(user_dir);
    return login_file;
}

char *generate_password_file (char *uid) {
    
    char *password_file = NULL;
    char *user_dir = generate_user_dir(uid);

    if (user_dir == NULL) {
        return password_file;
    }

    if ((password_file = (char *) malloc((strlen(PASSWORD_FILE) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(password_file, "%s%." STR(UID_SIZE) "s" PASSWORD_FILE_EXTENSION, user_dir, uid);

    free(user_dir);
    return password_file;
}

char *generate_gname_file(char *gid) {

    char *gname_file = NULL;
    char *group_dir = generate_group_dir(gid);

    if (group_dir == NULL) {
        return gname_file;
    }

    if ((gname_file = (char *) malloc((strlen(GNAME_FILE) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(gname_file, "%s%." STR(GID_SIZE) "s" GNAME_FILE_EXTENSION, group_dir, gid);

    free(group_dir);
    return gname_file;
}

char *generate_msg_dir(char *gid) {

    char *msg_dir = NULL;
    char *group_dir = generate_group_dir(gid);

    if (group_dir == NULL) {
        return msg_dir;
    }

    if ((msg_dir = (char *) malloc((strlen(MSG_DIR) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(msg_dir, "%s" MSG_DIR_EXTENSION "/", group_dir);
    
    free(group_dir);
    return msg_dir;
}

char *generate_user_file (char *gid, char *uid) {
    
    char *user_file = NULL;
    char *group_dir = generate_group_dir(gid);

    if (group_dir == NULL) {
        return user_file;
    }

    if ((user_file = (char *) malloc((strlen(USER_FILE) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(user_file, "%s%." STR(UID_SIZE) "s" USER_FILE_EXTENSION , group_dir, uid);

    free(group_dir);
    return user_file;
}

char *generate_text_file(char *gid) {

    char *text_file = NULL;
    char *msg_dir = generate_msg_dir(gid);

    if (msg_dir == NULL) {
        return text_file;
    }

    if ((text_file = (char *) malloc((strlen(TEXT_FILE) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(text_file, "%s" TEXT_FILE_EXTENSION, msg_dir);
    
    free(msg_dir);
    return text_file;
}

char *generate_author_file(char *gid) {
    char *author_file = NULL;
    char *msg_dir = generate_msg_dir(gid);

    if (msg_dir == NULL) {
        return author_file;
    }

    if ((author_file = (char *) malloc((strlen(AUTHOR_FILE) + 1) * sizeof(char))) == NULL) {
        return NULL;
    }

    sprintf(author_file, "%s" AUTHOR_FILE_EXTENSION, msg_dir);

    free(msg_dir);
    return author_file;
}