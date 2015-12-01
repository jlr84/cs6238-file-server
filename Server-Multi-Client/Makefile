# the compiler: gcc for C program
CXX = gcc
RM = rm -rf

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
#  CFLAGS  = -g -Wall

# the build target executable:
SERVER = server
SOURCE_SERVER = server.c
CLIENT = client
SOURCE_CLIENT = client.c

all: $(SERVER) $(CLIENT)

$(SERVER):
	$(CXX) $(SOURCE_SERVER) -lssl -lcrypto -o $(SERVER)

$(CLIENT):
	$(CXX) $(SOURCE_CLIENT) -lssl -lcrypto -o $(CLIENT)

clean:
	$(RM) $(SERVER) $(CLIENT) 
