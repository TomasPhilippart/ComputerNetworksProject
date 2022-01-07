#ifndef USER_API_H
#define USER_API_H

void setup_udp();
void setup_tcp();
int validate_hostname(char *name);
int validate_ip(char *ip_addr);
int validate_port(char *port);
void end_session(int status);

// User registration management
int register_user(char *user, char *pass);
int unregister_user(char *user, char *pass);

// User access management
int login(char *user, char *pass);
int logout();
char* get_uid();
void set_gid(char *gid);
char* get_gid();

// Group management
void get_all_groups(char ****list);
int get_subscribed_groups(char ****list);
int subscribe_group(char *gid, char *gName);
int unsubscribe_group(char *gid);
int get_uids_group(char ***list);

// Messaging
int post(char *text, char *mid, char *filename);
int retrieve(char *mid, char ****list);

// Auxiliary
int is_logged_in();

// memory management
void free_list(char ***list, int num_elements);
void free_uids(char **list);

#endif
