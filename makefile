Net:main.c
	gcc -Wall -g -o Net main.c -lpcap
clean:
	rm -irf *.o Net
