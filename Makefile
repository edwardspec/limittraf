CFLAGS += -Wall -Wextra -O0 -ggdb3
LDFLAGS = -lsqlite3 -lpcre

all: limittraf

limittraf: limittraf.o conf.o database.o actions.o legsearch.o

clean:
	rm -vf *.o
