
CC= gcc
ARGS= -Wall -O2
SRC= ./src
BUILD= ./build

default: pe_interface.o
	${CC} ${ARGS} -o perser ${BUILD}/pe_interface.o  ${BUILD}/misc.o  ${SRC}/main.c

pe_interface.o: misc.o
	${CC} ${ARGS} -c ${SRC}/pe_interface.c -o ${BUILD}/pe_interface.o

misc.o: 
	${CC} ${ARGS} -c ${SRC}/misc.c -o ${BUILD}/misc.o

format:
	astyle --style=allman --indent=spaces=2 ./src/*.c
	rm ./src/*.orig 

clean:
	rm -rf perser ${BUILD}/*.o