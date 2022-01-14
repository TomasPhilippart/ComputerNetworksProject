#ifndef __STATE_H__
#define __STATE_H__

#include "../../aux_functions.h"

void setup_state();

/* User */
int register_user(char *uid, char *pass);
int unregister_user(char *uid, char *pass);
int login_user(char *uid, char *pass);
int logout_user(char *uid, char *pass);

/* Groups */
int all_groups(int *num_groups, char ****groups);
int subscribe_group(char *uid, char *gid, char *group_name, char *new_gid);
int unsubscribe_user(char *uid, char *gid);
int user_subscribed_groups(char *uid, int *num_groups, char ****groups);
int get_uids_group(char *gid, char *groupname, char ***uids,  int *num_groups);
int post_message(char *uid, char *gid, char *text, char *mid, char *file_name, int file_size, Buffer buf, int (*write)(char*, int));
int retrieve_messages(char *uid, char *gid, char *mid, char ***uids, char ***text_files, char ***files, int *num_messages);

/* Auxiliary */
void free_groups(char ***groups, int num_groups);
void free_uids(char **groups);

#endif
