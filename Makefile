all : nfqnl_test

nfqnl_test: main.o
	gcc -g -o nfqnl_test main.o -lnetfilter_queue

main.o:
	gcc -g -c -o main.o nfqnl_test.c

clean:
	rm -f nfqnl_test
	rm -f *.o
