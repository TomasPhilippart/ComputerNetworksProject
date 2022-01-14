
FLAGS = #-g3 -fsanitize=address	

.PHONY: all clean run

all: user DS server_udp server_tcp

# USER
user: client/user.o client/api/user_api.o aux_functions.o
	gcc $(FLAGS) -o user client/user.o client/api/user_api.o aux_functions.o
	
user.o: client/user.c client/api/user_api.h aux_functions.h
	gcc $(FLAGS) -o client/user.o -c client/user.c

api/user_api.o: client/api/user_api.c
	gcc $(FLAGS) -o client/api/user_api.o -c client/api/user_api.c

# SERVER
DS: server/server.o   server/backend/state.o
	gcc $(FLAGS) -o DS server/server.o
	
server_udp: server/server_udp.o aux_functions.o server/backend/state.o
	gcc $(FLAGS) -o server_udp server/server_udp.o aux_functions.o server/backend/state.o

server_tcp: server/server_tcp.o aux_functions.o server/backend/state.o
	gcc $(FLAGS) -o server_tcp server/server_tcp.o aux_functions.o server/backend/state.o

server/server.o: server/server.c server/backend/state.h
	gcc $(FLAGS) -o server/server.o -c server/server.c

backend/state.o: server/api/state.c
	gcc $(FLAGS) -o server/backend/state.o -c server/backend/state.c

server/server_udp.o: server/server_udp.c aux_functions.h server/backend/state.h
	gcc $(FLAGS) -o server/server_udp.o -c server/server_udp.c

server/server_tcp.o: server/server_tcp.c aux_functions.h server/backend/state.h
	gcc $(FLAGS) -o server/server_tcp.o -c server/server_tcp.c

# AUXILIARY
aux_functions.o: aux_functions.c
	gcc $(FLAGS) -o aux_functions.o -c aux_functions.c

clean:
	@echo Cleaning...
	rm -f client/api/*.o client/*.o server/*.o server/backend/*.o *.html *.o user DS server_tcp server_udp