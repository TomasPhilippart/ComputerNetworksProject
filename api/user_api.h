#ifndef USER_API_H
#define USER_API_H

int startup();
int validate_hostname(char *name);
int validate_ip(char *ip_addr);
int validate_port(char *port);
int create_connection();

#endif
