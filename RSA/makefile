LIBS = -lcrypto

all: rsa

rsa: rsa_정경재.o
	gcc -o rsa_정경재 rsa_정경재.o $(LIBS)

rsa_정경재.o: rsa_정경재.c

clean:
	rm -f rsa_정경재
	rm -f *.o

