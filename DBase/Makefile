# the compiler: gcc for C program, define as g++ for C++
CC = gcc

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -g -std=c99
LIBS = `mysql_config --cflags --libs`  

# What I want:
# gcc -g createdb.c -o createdb -std=c99 `mysql_config --cflags --libs`

# the build target executable:
TARGET = checkoutFile initializedb createdb columnHeaders lastRow createTable retrieveData version

all: $(TARGET)

$(TARGET): % : %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)

clean:
	$(RM) $(TARGET)
