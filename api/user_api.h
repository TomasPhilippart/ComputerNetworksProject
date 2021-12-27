#ifndef USER_API_H
#define USER_API_H

int startup();
int validate_dns(char *name);
int validate_ip(char *ip_addr);
int validate_port(char *port);

#endif
