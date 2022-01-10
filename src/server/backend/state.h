#ifndef __STATE_H__
#define __STATE_H__

/* User */
int register_user(char *uid, char *pass);
int unregister_user(char *uid, char *pass);
int login_user(char *uid, char *pass);
int logout_user(char *uid, char *pass);

/* Groups */
int subscribe_group(char *uid, char *gid, char *gName, char *newGID);


#endif
