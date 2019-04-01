Net:main.c ethernet.h
	gcc -Wall -g -o Net main.c -lpcap -lsqlite3
clean:
	rm -irf *.o Net
