#include "../constants.h"
#include "backend/state.h"
#include "../aux_functions.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <math.h>
#include <libgen.h>
#include<signal.h>

#define QUEUE_SIZE 10

struct sigaction old_action;

/* variables needed for TCP connection */
char *port;
int verbose;

int fd, new_fd;
struct addrinfo *res;
struct addrinfo hints;
socklen_t addrlen;
struct sockaddr_in addr;

char host[NI_MAXHOST] = "";
char service[NI_MAXSERV] = "";

void send_message_tcp(char *buf, ssize_t num_bytes);
int rcv_message_tcp(char *buf, int num_bytes);
int start_timer(int fd);
int stop_timer(int fd);

void ctrlC_handler (int sig_no);
void end_session();

/* Setup the UDP server */
void setup() {
	int option = 1;
	struct sigaction action;

    fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
        printf("(TCP) Error: Failed to create TCP socket.\n");
		exit(EXIT_FAILURE);
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; 	         /* IPv4 */
	hints.ai_socktype = SOCK_STREAM;     /* TCP socket */
    hints.ai_flags = AI_PASSIVE;

	addrlen = sizeof(addr);             /* for receiving messages */

	if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        printf("(TCP) Error: DNS couldn't resolve server's IP address for TCP connection.\n");
		exit(EXIT_FAILURE);
	}
	
    if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
		printf("(TCP) Error: Could not bind socket. Why: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

    if (listen(fd, QUEUE_SIZE) == -1) {
        printf("(TCP) Error: Could not perform listening\n");
		exit(EXIT_FAILURE);
    }

	/* Setup ctrl-c new action */
    memset(&action, 0, sizeof(action));
    action.sa_handler = &ctrlC_handler;
    sigaction(SIGINT, &action, &old_action);
}

// NOTE: mudar a implementação do buffer
void process_requests() {

    pid_t pid;
    Buffer rcv_buf = new_buffer(MAX_BUF_SIZE);

    if (rcv_buf == NULL) {
        exit(EXIT_FAILURE);
    }

    while (1) {
		int option = 1;

		new_fd = accept(fd, (struct sockaddr*)&addr, &addrlen);
		while ((new_fd == -1) && (errno == EINTR));
        if (new_fd == -1) {
			exit(EXIT_FAILURE);
		}
		
        if ((pid = fork()) < 0) {
            exit(EXIT_FAILURE);
        } else if (pid != 0) {
			int res = close(new_fd);
			while ((res == -1) && (errno == EINTR));
			if (res == -1) {
				printf("(TCP) Error closing the socket: %s\n", strerror(errno));
			}

			// NOTE what is the point of forking if the parent waits for
			// the child to end
			int status;
			int aux = wait(&status);
			if(WIFEXITED(status)) {
				/* The child process exited normally */
			} else if(WIFSIGNALED(status)) {
				/* The child process was killed by a signal. Note the use of strsignal
				to make the output human-readable. */
				printf("(TCP) Killed by %s\n", strsignal(WTERMSIG(status)));
			}
			continue;
        }

		close(fd);
		if (verbose) {
            if ((getnameinfo((struct sockaddr *)&addr, addrlen, host, sizeof(host), service, sizeof (service), 0)) != 0) {
                printf("(TCP) Error getting user address information.\n");
				close(new_fd);
                exit(EXIT_FAILURE);
			}
        }
		
		reset_buffer(rcv_buf);
        write_to_buffer(rcv_buf, rcv_buf->size, rcv_message_tcp);

		/* ====== ULIST ====== */
		if (parse_regex(rcv_buf->buf, "^ULS [0-9]{" STR(GID_SIZE) "}\\\n$") && rcv_buf->tail == strlen("ULS ") + GID_SIZE + 1) {

			char gid[UID_SIZE + 1], group_name[MAX_GNAME + 1];
			char ** uids;
			char send_buf[1000 * (UID_SIZE + 1) + 50];
			int num_uids, status;
			int pos = 0;

			memset(send_buf, 0, ((1000 * (UID_SIZE + 1)) + 50) * sizeof(char));
			sscanf(rcv_buf->buf, "%*s %s", gid);

			if (verbose) {
                printf("(TCP) %s@%s: %s", host, service, rcv_buf->buf); 
            }
			status = get_uids_group(gid, group_name, &uids, &num_uids);

			switch (status) {
				case STATUS_NOK:
					send_message_tcp("RUL NOK\n", strlen("RUL NOK\n"));
					break;

				case STATUS_OK:
					sprintf(send_buf, "RUL OK %s", group_name);
					pos += strlen(send_buf);
					for (int i = 0; i < num_uids; i++) {
						sprintf(send_buf + pos, " %s", uids[i]);
						pos += 1 + UID_SIZE;
					}
					sprintf(send_buf + pos, "\n");
					send_message_tcp(send_buf, strlen(send_buf));
 					break;
			
				case STATUS_FAIL:
					exit(EXIT_FAILURE);
			}

			break;

		/* ====== POST ====== */
		} else if (parse_regex(rcv_buf->buf, "^PST [0-9]{"STR(UID_SIZE)"} [0-9]{"STR(GID_SIZE)"} [0-9]{1,3} .{1,"STR(MAX_TSIZE)"}")) {
			int status;
			char uid[UID_SIZE + 1], gid[GID_SIZE + 1];
			char text[MAX_TSIZE + 1], mid[MID_SIZE + 1], text_size[4];
			char file_name[MAX_FNAME + 1], file_size[MAX_FSIZE + 1];
			char send_buf[strlen("RPT ") + MID_SIZE + 2];
			memset(send_buf, 0, (strlen("RPT ") + MID_SIZE + 2) * sizeof(char));
			
			sscanf(rcv_buf->buf, "%*s %s %s %s ", uid, gid, text_size);
			flush_buffer(rcv_buf, strlen("PST") + UID_SIZE + GID_SIZE + strlen(text_size) + 4);
			memcpy(text, rcv_buf->buf, atoi(text_size));
			text[atoi(text_size)] = '\0';
			
			flush_buffer(rcv_buf, atoi(text_size));
			if (!(parse_regex(rcv_buf->buf, "^\\\n") && rcv_buf->tail == 1)) {
				if (parse_regex(rcv_buf->buf, "^ [0-9a-zA-Z._-]{1,20}.[a-zA-Z]{3} [0-9]{1," STR(MAX_FSIZE)"} ")) {
					sscanf(rcv_buf->buf, " %s %s ", file_name, file_size);
					if (!atoi(file_size)) {
						exit(EXIT_FAILURE);
					}
					flush_buffer(rcv_buf, 3 + strlen(file_name) + strlen(file_size));
					if (verbose) {
                		printf("(TCP) %s@%s: PST %s %s %s\n", host, service, text, file_name, file_size); 
           			}
					status = post_message(uid, gid, text, mid, file_name, atoi(file_size), rcv_buf, rcv_message_tcp);
				} else {
					exit(EXIT_FAILURE);
				}
			} else {
				if (verbose) {
                	printf("(TCP) %s@%s: PST %s %s %s\n", host, service, uid, gid, text); 
           		}
				status = post_message(uid, gid, text, mid, NULL, 0, NULL, NULL);
			}
			switch (status) {
				case STATUS_OK:
					sprintf(send_buf, "RPT %s\n", mid);
					send_message_tcp(send_buf, strlen(send_buf));
					break;
				case STATUS_NOK:
					sprintf(send_buf, "RPT NOK\n");
					send_message_tcp(send_buf, strlen(send_buf));
					break;
				case STATUS_FAIL:
					exit(EXIT_FAILURE);
			}

			break;

			/* ====== RETRIEVE ====== */
		} else if (parse_regex(rcv_buf->buf, "^RTV [0-9]{" STR(UID_SIZE) "} [0-9]{" STR(GID_SIZE) "} [0-9]{" STR(MID_SIZE) "}\\\n$")) {
			char uid[UID_SIZE + 1], gid[GID_SIZE + 1], mid[MID_SIZE + 1];
			char **text_files, **content_files, **uids;
			int num_messages, status;
			char send_buf[MAX_BUF_SIZE];
			
			memset(send_buf, 0, MAX_BUF_SIZE * sizeof(char));
			sscanf(rcv_buf->buf, "%*s %s %s %s\n", uid, gid, mid);
			if (verbose) {
                	printf("(TCP) %s@%s: RTV %s %s %s\n", host, service, uid, gid, mid); 
           	}
			status = retrieve_messages(uid, gid, mid, &uids, &text_files, &content_files, &num_messages);;
		
			if (status == STATUS_OK) {

				int file_size, bytes_read, total;

				if (num_messages == 0) {
					sprintf(send_buf, "RRT EOF\n");
					send_message_tcp(send_buf, strlen(send_buf));
					break;
				}

				FILE *file;
				sprintf(send_buf, "RRT OK %d", num_messages);
				send_message_tcp(send_buf, strlen(send_buf));
				memset(send_buf, 0, strlen(send_buf) * sizeof(char));

				for (int i = 0; i < num_messages; i++) {
					/* Send text files */
					sprintf(send_buf, " %04d %s", atoi(mid) + i, uids[i]);
		
					if ((file = fopen(text_files[i], "r")) == NULL) {
						exit(EXIT_FAILURE);
					}
					/* Get size of file data */
					if ((fseek(file, 0, SEEK_END) != 0) || 
						((file_size = ftell(file)) == -1) ||
						(fseek(file, 0, SEEK_SET) != 0)) {
						exit(EXIT_FAILURE);
					}

					sprintf(send_buf + strlen(send_buf), " %d ", file_size);

					if (fread(send_buf + strlen(send_buf), sizeof(char), file_size, file) < 0) {
						exit(EXIT_FAILURE);
					}


					if (fclose(file) != 0) {
						exit(EXIT_FAILURE);
					}
					send_message_tcp(send_buf, strlen(send_buf));
					memset(send_buf, 0, (strlen(send_buf) * sizeof(char)));

					/* Send file content, if it exists */
					if (content_files[i] != NULL) {

						printf("Fetching content file %s\n", basename(content_files[i]));

						if ((file = fopen(content_files[i], "r")) == NULL) {
							exit(EXIT_FAILURE);
						}

						/* Get size of file data */
						if ((fseek(file, 0, SEEK_END) != 0) || 
							((file_size = ftell(file)) == -1) ||
							(fseek(file, 0, SEEK_SET) != 0)) {
							exit(EXIT_FAILURE);
						}
						sprintf(send_buf, " / %s %d ", basename(content_files[i]), file_size);
						send_message_tcp(send_buf, strlen(send_buf));
						memset(send_buf, 0, strlen(send_buf) * sizeof(char));

						/* Check maximum filesize */
						if (file_size >= pow(10, MAX_FSIZE)) {
							exit(EXIT_FAILURE);
						}

						while (1) {
							bytes_read = fread(send_buf, sizeof(char), MAX_BUF_SIZE - 1, file);
							send_message_tcp(send_buf, bytes_read);	// NOTE: check this
							memset(send_buf, 0, sizeof(char) * bytes_read);
							if (feof(file)) {
								break;
							} else if (ferror(file)) {
								exit(EXIT_FAILURE);
							}
						}
						
						if (fclose(file) != 0) {
							exit(EXIT_FAILURE);
						}
						memset(send_buf, 0, MAX_BUF_SIZE * sizeof(char));
					}
					
				}

				sprintf(send_buf, "\n");
				send_message_tcp(send_buf, 1);
				
			} else if (status == STATUS_NOK) {
				sprintf(send_buf, "RRT NOK\n");
				send_message_tcp(send_buf, strlen(send_buf));
			} else if (status == STATUS_ERR) {
				sprintf(send_buf, "ERR\n");
				send_message_tcp(send_buf, strlen(send_buf));
			}

			break;
			
		} else {
			char send_buf[MAX_BUF_SIZE];
			sprintf(send_buf, "ERR\n");
			send_message_tcp(send_buf, strlen(send_buf));
			break;

		}
    }

	if (shutdown(new_fd, SHUT_RDWR) == -1) {
			printf("Error closing socket: %s\n", strerror(errno));
	}
		
	if (close(new_fd) == -1) {
		printf("Error closing socket: %s\n", strerror(errno));
	}

	exit(EXIT_SUCCESS);
    
}

/*	Sends the message in buf to the server through the UDP socket 
	and puts a response of size max_rcv_size in buf 
	Input:
	- buf: a buffer that contains the message to be sent and that will
	contained the received message
	- max_rcv_size: maximum size of the response
*/
void send_message_tcp(char *buf, ssize_t num_bytes) {

	ssize_t num_bytes_left = num_bytes;
	ssize_t num_bytes_written, num_bytes_read, base_bytes, curr_size;
	char *aux = buf;

	while (num_bytes_left > 0) {
		num_bytes_written = write(new_fd, aux, num_bytes_left);
		if (num_bytes_written < 0) {
			printf("Error: Failed to write message to TCP socket.\n");
			exit(EXIT_FAILURE);
		}
		num_bytes_left -= num_bytes_written;
		aux += num_bytes_written;
	}

}

int rcv_message_tcp(char *buf, int num_bytes) {

	ssize_t num_bytes_read, num_bytes_left;
	char *aux = buf;
	
	num_bytes_left = num_bytes;

	while (num_bytes_left != 0) {
		start_timer(new_fd);
		num_bytes_read = read(new_fd, aux, num_bytes_left);
		stop_timer(new_fd);
		
		if (num_bytes_read == -1) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				break;
			}
			printf("Error: Failed to read message from TCP socket %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		
		aux += num_bytes_read;
		num_bytes_left -= num_bytes_read;

	}

	return num_bytes - num_bytes_left;
}

int main(int argc, char **argv) {

    port = strdup(argv[1]);
    verbose = atoi(argv[2]);
	
    setup();
    process_requests();
	
	end_session(SUCCESS);
    return SUCCESS;
}

int start_timer(int fd) {
    struct timeval timeout;

    memset((char *) &timeout, 0, sizeof(timeout)); 
    timeout.tv_sec = 0;
	timeout.tv_usec = 50000;

    return (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &timeout, sizeof(struct timeval)));
}

int stop_timer(int fd){
    struct timeval timeout;
    memset((char *)&timeout, 0, sizeof(timeout)); 
    return (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &timeout, sizeof(struct timeval)));
}

void ctrlC_handler (int sig_no) {
	printf("Closing TCP connection...\n");

	end_session(SUCCESS);

    sigaction(SIGINT, &old_action, NULL);
    kill(0, SIGINT);
}

void end_session (int status) {
	free(port);
	freeaddrinfo(res);
}