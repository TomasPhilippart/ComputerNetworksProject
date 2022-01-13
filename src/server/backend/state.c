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
#define MSG_DIR "../GROUPS/xx/MSG"
#define USER_FILE "../GROUPS/xx/xxxxx.txt"
#define GNAME_FILE "../GROUPS/xx/xx_name.txt"
#define TEXT_FILE "../GROUPS/xx/MSG/T E X T.txt"
#define AUTHOR_FILE "../GROUPS/xx/MSG/A U T H O R.txt"

#define MSG_DIR_EXTENSION "MSG"
#define USER_FILE_EXTENSION ".txt"
#define GNAME_FILE_EXTENSION "_name.txt"
#define TEXT_FILE_EXTENSION "T E X T.txt"
#define AUTHOR_FILE_EXTENSION "A U T H O R.txt"

// NOTE full path or just file format?
// NOTE probably use full path so the declaration is
// login_file[strlen(LOGIN_FILE)] instead of login_file[strlen(USER_DIR) + strlen(LOGIN_FILE)]
// and have a separate macro that has "_login.txt" 

// NOTE defines for directories?
int next_available_gid;


// NOTE finish converting string declaration size to strLen(MACRO)
// NOTE comment shit
// NOTE check paths passed by argument

int check_user_subscribed(char *uid, char *gid);
int check_user_registered(char *uid);
int check_correct_password(char* uid, char *pass);
int check_user_logged (char *uid);
int check_group_exists(char *gid);
int check_message_exists(char *gid, char *mid);
int create_group(char *group_name, char *group_dir, char *new_gid);
void free_groups(char ***groups, int num_groups);

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

void setup_state() {

    // NOTE strlen(GROUP_DIR) or strlen(GROUP_DIR) + 1 ('\0')
    // or just add a space/(one more character) in the end of the
    // USERS_DIR and GROUPS_DIR to account for the '\0'

    /* Check for the next available GID */
    char group_dir[strlen(GROUP_DIR)];
    char gid[GID_SIZE + 1];

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
        return STATUS_NOK;
    }

    if ((user_dir = generate_user_dir(user_dir)) == NULL) {
        return STATUS_FAIL;
    }

    // NOTE is this 0700?
    /* Create user directory */
    if (mkdir(user_dir, 0700) == STATUS_FAIL) {
        printf("Error : Couldnt create new dir with path %s\n", user_dir);
        free(user_dir);
        return STATUS_FAIL;
    }

    free(user_dir);

    if ((password_file = generate_password_file(uid)) == NULL) {
        return STATUS_FAIL;
    }

    /* Create user password file */
    if (!(file = fopen(password_file, "w"))) {
        printf("Error : Couldnt open file with path %s\n", password_file);
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

// TODO initialize paths using new generate paths functions
int unregister_user(char *uid, char *pass) {
    
    char user_dir[strlen(USER_DIR)], password_file[strlen(PASSWORD_FILE)];

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
    char user_dir[strlen(USER_DIR)], password_file[strlen(PASSWORD_FILE)];  
    char login_file[strlen(LOGIN_FILE)];

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
    // NOTE _login.txt hardcode?
    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);
    if (!(file = fopen(login_file, "w"))) {
        printf("Error : creating login file with path %s.\n", login_file);
        return STATUS_FAIL;
    }

    return STATUS_OK;
}

int logout_user(char *uid, char *pass) {

    char user_dir[strlen(USER_DIR)], password_file[strlen(PASSWORD_FILE)];  
    char login_file[strlen(LOGIN_FILE)];

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
    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);

    if (check_user_logged(uid) == FALSE) {
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

    (*num_groups) = 0;
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

        memset((*groups)[*num_groups][1], '\0', MAX_GNAME + 1);
        strcpy((*groups)[*num_groups][1], group_name);
        strcpy((*groups)[*num_groups][2], last_mid);

        (*num_groups)++;
    }

    return STATUS_OK;
}

int subscribe_group(char *uid, char *gid, char *group_name, char *new_gid) {

    // REVIEW which cases should return STATUS_NOK
    char user_dir[strlen(USER_DIR)], group_dir[strlen(GROUP_DIR)];
    char login_file[strlen(LOGIN_FILE)];
    // NOTE change all group_uid_file to user_file
    char group_uid_file[strlen(USER_FILE)];
    FILE *file;    

    /* Check UID */
    if (!check_uid(uid) || check_user_registered(uid) == FALSE) {
        return STATUS_USR_INVALID;
    }

    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);
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
    
    char user_dir[strlen(USER_DIR)], group_dir[strlen(GROUP_DIR)];
    char login_file[strlen(LOGIN_FILE)];
    char group_uid_file[strlen(USER_FILE)];
    FILE *file;  

    /* Check UID */
    if (!check_uid(uid) || check_user_registered(uid) == FALSE) {
        return STATUS_USR_INVALID;
    }

    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);
    if (check_user_logged(uid) == FALSE) {
        return STATUS_USR_INVALID;
    }
    
    /* Check GID */
    if (check_group_exists(gid) == FALSE || !strcmp(gid, "00") || check_gid(gid) == FALSE) {
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

    char user_dir[strlen(USER_DIR)], login_file[strlen(LOGIN_FILE)];
    char gid[GID_SIZE + 1];
    char last_mid[MID_SIZE + 1], group_name[MAX_GNAME + 1];
    int base_size = 100;

    *num_groups = 0;
    if (((*groups) = (char ***) malloc(sizeof(char **) * base_size)) == NULL) {
        return STATUS_USR_INVALID;
    }

    /* Check UID */
    if (!(check_uid(uid) && check_user_registered(uid))) { // NOTE: this is stupid as fuck
        return STATUS_USR_INVALID;
    }

    sprintf(login_file, "%s/%s_login.txt", user_dir, uid);
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

    // NOTE check if the folder ../USERS/uid was a uid_pass.txt file
    DIR* dir;
    char *user_dir;
    
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
    return TRUE;
}

// NOTE: enforcee maximum input sizes???
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

// NOTE this function returns TRUE, FALSE and STATUS_FAIL, when calling it 
// need to check for STATUS_FAIL (and propagate it to server_udp) not only TRUE and FALSE 
/*  Check if pass is correct
    Input:
    - uid: the UID
    - gid: the pass
    Output: TRUE or FALSE
*/
int check_correct_password(char* uid, char *pass) {
    
    FILE *file;
    char *password_file;
    char true_pass[PASSWORD_SIZE + 2];
    int num_bytes;

    if ((password_file = generate_password_file(uid)) == NULL) {
        return STATUS_FAIL;
    }

    if (!(file = fopen(password_file, "r"))) {
        printf("Error opening password file with path %s.\n", password_file);
        free(password_file);
        return STATUS_FAIL;
    }

    // NOTE check this
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
    - login_file : path to the loggin file
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

    if (access(author_file, F_OK) != 0) {
        free(author_file);
        return FALSE;
    }

    free(author_file);
    return TRUE;
}

// REVIEW this for not needing to pass path?
int create_group(char *group_name, char *group_dir, char *new_gid) {
    
    char group_name_file[strlen(GNAME_FILE)];
    FILE *file;

    /* 1. Create GROUPS/GID*/
    sprintf(group_dir, GROUPS_DIR "%02d", next_available_gid);
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
    - group_name: buffer to hold the path to the group name file
    Output: None
*/
int get_group_name(char *gid, char *group_name) {

    FILE *file;
    char group_name_file[strlen(GNAME_FILE)]; 
    int read_bytes;
    
    sprintf(group_name_file, GROUPS_DIR "%." STR(GID_SIZE) "s/%." STR(GID_SIZE) "s_name.txt", gid, gid);
   
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

    char message_dir[strlen(MSG_DIR)];
    char mid[MID_SIZE + 1];

    for (int i = 1; i < pow(10, strlen(STR(MID_SIZE))); i++) {
        sprintf(mid, "%0" STR(MID_SIZE) "d", i);
        if (check_message_exists(gid, mid) == FALSE) {
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


/* Generate DS path files */
// NOTE check malloc error ((x = malloc) == NULL) => ERROR (just return NULL)
char* generate_user_dir (char *uid) {
    
    char *user_dir = NULL;


    if (strlen(uid) != UID_SIZE) {
        return user_dir;
    }

    user_dir = (char *) malloc(strlen(USER_DIR) * sizeof(char));
    sprintf(user_dir, USERS_DIR "%." STR(UID_SIZE), uid);

    return user_dir;
}

char* generate_group_dir (char *gid) {
    
    char *group_dir = NULL;

    if (strlen(gid) != GID_SIZE) {
        return group_dir;
    }

    group_dir = (char *) malloc(strlen(GROUP_DIR) * sizeof(char));
    sprintf(group_dir, GROUPS_DIR "%." STR(GID_SIZE), gid);

    return group_dir;
}

char* generate_login_file (char *uid) {
    
    char *login_file = NULL;
    char *user_dir = generate_user_dir(uid);

    if (user_dir == NULL) {
        return login_file;
    }

    login_file = (char *) malloc(strlen(LOGIN_FILE) * sizeof(char));
    sprintf(login_file, "%s/%." STR(UID_SIZE) LOGIN_FILE_EXTENSION, user_dir, uid);

    free(user_dir);
    return login_file;
}

char *generate_password_file (char *uid) {
    
    char *password_file = NULL;
    char *user_dir = generate_user_dir(uid);

    if (user_dir == NULL) {
        return password_file;
    }

    password_file = (char *) malloc(strlen(PASSWORD_FILE) * sizeof(char));
    sprintf(password_file, "%s/%." STR(UID_SIZE) PASSWORD_FILE_EXTENSION, user_dir, uid);

    free(user_dir);
    return password_file;
}

char *generate_gname_file(char *gid) {

    char *gname_file = NULL;
    char *group_dir = generate_group_dir(gid);

    if (group_dir == NULL) {
        return gname_file;
    }

    gname_file = (char *) malloc(strlen(GNAME_FILE) * sizeof(char));
    sprintf(gname_file, "%s/%." STR(GID_SIZE) GNAME_FILE_EXTENSION, group_dir, gid);

    free(group_dir);
    return gname_file;
}

char *generate_msg_dir(char *gid) {

    char *msg_dir = NULL;
    char *group_dir = generate_group_dir(gid);

    if (group_dir == NULL) {
        return msg_dir;
    }

    msg_dir = (char *) malloc(strlen(MSG_DIR) * sizeof(char));
    sprintf(msg_dir, "%s/" MSG_DIR, group_dir);

    free(group_dir);
    return msg_dir;
}

char *generate_user_file (char *gid, char *uid) {
    
    char *user_file = NULL;
    char *group_dir = generate_group_dir(gid);

    if (group_dir == NULL) {
        return user_file;
    }

    user_file = (char *) malloc(strlen(USER_FILE) * sizeof(char));
    sprintf(user_file, "%s/%." STR(UID_SIZE) USER_FILE_EXTENSION , group_dir);

    free(group_dir);
    return user_file;
}

char* generate_text_file(char *gid) {

    char *text_file = NULL;
    char *msg_dir = generate_msg_dir(gid);

    if (msg_dir == NULL) {
        return text_file;
    }

    text_file = (char *) malloc(sizeof(strlen(TEXT_FILE) * sizeof(char)));
    sprintf(text_file, "%s/" TEXT_FILE_EXTENSION, msg_dir);

    free(msg_dir);
    return text_file;
}

char* generate_author_file(char *gid) {
    
    char *author_file = NULL;
    char *msg_dir = generate_msg_dir(gid);

    if (msg_dir == NULL) {
        return author_file;
    }

    author_file = (char *) malloc(sizeof(strlen(AUTHOR_FILE) * sizeof(char)));
    sprintf(author_file, "%s/" AUTHOR_FILE_EXTENSION, msg_dir);

    free(msg_dir);
    return author_file;
}