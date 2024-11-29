# Targets
rebuild: clean all
all: ./bin/server ./bin/client

# Clean command
clean:
	clear
	rm -f bin/* obj/*

# Create obj and bin directories if they don't exist
./obj:
	mkdir -p obj
./bin:
	mkdir -p bin

# Object file rules
./obj/twmailer-client.o: twmailer-client.cpp | ./obj
	g++ -g -Wall -Wextra -Werror -O0 -std=c++20 -pthread -o obj/twmailer-client.o twmailer-client.cpp -c

./obj/twmailer-server.o: twmailer-server.cpp | ./obj
	g++ -g -Wall -Wextra -Werror -O0 -std=c++20 -pthread -o obj/twmailer-server.o twmailer-server.cpp -lldap -llber -c 

# Binary file rules
./bin/client: ./obj/twmailer-client.o | ./bin
	g++ -g -Wall -Wextra -Werror -O0 -std=c++20 -pthread -o bin/client obj/twmailer-client.o

./bin/server: ./obj/twmailer-server.o | ./bin
	g++ -g -Wall -Wextra -Werror -O0 -std=c++20 -pthread -o bin/server obj/twmailer-server.o -lldap -llber
	