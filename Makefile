all: netfilter_block

netfilter_block: main.o
	gcc -g -o netfilter_block main.o -lnetfilter_queue

main.o:
	gcc -g -c -o main.o nfqnl_test.c

clean:
	rm -f netfilter_block
	rm -f *.o
