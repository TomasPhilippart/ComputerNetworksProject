#ifndef __STATE_H__
#define __STATE_H__

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

/* Auxiliary */
void free_groups(char ***groups, int num_groups);

#endif
