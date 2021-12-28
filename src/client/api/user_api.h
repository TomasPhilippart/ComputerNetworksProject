#ifndef USER_API_H
#define USER_API_H

/* status codes */
#define STATUS_OK 2
#define STATUS_NOK 3
#define STATUS_DUP 4
#define STATUS_NOGROUPS 5
#define STATUS_NEW_GROUP 6
#define STATUS_USR_INVALID 7
#define STATUS_GID_INVALID 8
#define STATUS_GNAME_INVALID 9
#define STATUS_GROUPS_FULL 10

#define FAIL 0
#define SUCCESS 1

#define MAX_LINE_SIZE 300
#define MAX_ARG_SIZE 250


int setup();
int validate_hostname(char *name);
int validate_ip(char *ip_addr);
int validate_port(char *port);
void end_session();

// User registration management
int register_user(char *user, char *pass);
int unregister_user(char *user, char *pass);

// User access management
int login(char *user, char *pass);
int logout();
char* get_uid();

// Group management
char ***get_all_groups();
int subscribe_group(char *gid, char *gName);

// Auxiliary
int is_logged_in();


#endif
