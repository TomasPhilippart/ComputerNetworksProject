#include "../constants.h"
#include "backend/state.h"
#include "../aux_functions.h"

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

#define QUEUE_SIZE 5

/* variables needed for TCP connection */
char *port;
int verbose;

int fd, new_fd;
struct addrinfo *res;
struct addrinfo hints;
socklen_t addrlen;
struct sockaddr_in addr;

char host[NI_MAXHOST], service[NI_MAXSERV];

void send_message_tcp(char *buf, ssize_t num_bytes);
int rcv_message_tcp(char *buf, int num_bytes);

/* Setup the UDP server */
void setup() {

    fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
        printf("Error: Failed to create UDP socket.\n");
		exit(EXIT_FAILURE);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; 	        /* IPv4 */
	hints.ai_socktype = SOCK_STREAM;     /* TCP socket */
    hints.ai_flags = AI_PASSIVE;

	addrlen = sizeof(addr);             /* for receiving messages */

    // NOTE: free structures on failure */
	if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        printf("Error: DNS couldn't resolve server's IP address for UDP connection.\n");
        printf("There?\n");
		exit(EXIT_FAILURE);
	}
	
    if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
		printf("Error: Binding socket.\n");
        printf("or there?\n");
		exit(EXIT_FAILURE);
	}

    // NOTE change this constant
    if (listen(fd, QUEUE_SIZE) == -1) {
        printf("Error: Binding socket.\n");
        printf("perhaps?\n");
		exit(EXIT_FAILURE);
    }

}

void process_requests() {

    pid_t pid;
    Buffer rcv_buf = new_buffer(MAX_BUF_SIZE);

    if (rcv_buf == NULL) {
        exit(EXIT_FAILURE);
    }

    while (1) {
        if ((new_fd = accept(fd,(struct sockaddr*)&addr,&addrlen)) == -1) {
            // NOTE: Free structures
            exit(EXIT_FAILURE);
        }
        if ((pid = fork()) == -1) {
            // NOTE
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            continue;
        }

        write_to_buffer(rcv_buf, rcv_buf->size, rcv_message_tcp);    //NOTE

        printf("Received: %s\n", rcv_buf->buf);

        //if (verbose) {
        //    if ((getnameinfo((struct sockaddr *)&addr, addrlen, host, sizeof(host), service, sizeof (service), 0)) != 0) {
        //        printf("Error getting user address information.\n");
        //        exit(EXIT_FAILURE);
        //    } else {
        //        printf("(TCP) %s@%s: %s", host, service, receiving_buf); /* /n missing because buf already contains it */ 
        //    }
        //}
        
    }
}

/*	Sends the message in buf to the server through the UDP socket 
	and puts a response of size max_rcv_size in buf 
	Input:
	- buf: a buffer that contains the message to be sent and that will
	contained the received message
	- max_rcv_size: maximum size of the response
*/
void send_message_tcp(char *buf, ssize_t num_bytes) {

	//setup_tcp();

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

	// Debug
	//printf("Sent: %s\n", buf);

}

int rcv_message_tcp(char *buf, int num_bytes) {

	ssize_t num_bytes_read, num_bytes_left;
	char *aux = buf;
	
	num_bytes_left = num_bytes;

	while (num_bytes_left != 0) {

		num_bytes_read = read(new_fd, aux, num_bytes_left);

		if (num_bytes_read == 0) {
			break;
		}
		
		if (num_bytes_read == -1) {
			printf("Error: Failed to read message from TCP socket.\n");
			exit(EXIT_FAILURE);
		}
		
		aux += num_bytes_read;
		num_bytes_left -= num_bytes_read;

	}

	// Debug
	//if (*buf != '\0') {
	//	printf("Received: %s\n", buf);
	//	printf("With length: %d\n", strlen(buf));
	//}

	return num_bytes - num_bytes_left;

}

int main(int argc, char **argv) {

	/* No need to validate port since it was already validated*/
    port = strdup(argv[1]);
    verbose = atoi(argv[2]);

    setup();
    process_requests();

    return TRUE;

}