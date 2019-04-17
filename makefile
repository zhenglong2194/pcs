Net:main.c ethernet.h
	gcc -Wall -g -o Net main.c -lpcap -lnet -lsqlite3
clean:
	rm -irf *.o Net1
