app: main.o sha256.o
	gcc -o app -O3 main.o sha256.o

main.o: main.c
	gcc -c -O3 main.c

sha256.o: sha256.c sha256.h
	gcc -c -O3 sha256.c

clean: 
	rm -f app
	rm -f *.o