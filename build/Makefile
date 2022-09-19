CC = gcc
CFLAGS = -fno-stack-protector -Wall -Wextra -Iutil -Iatm -Ibank -Irouter -I.


all: atm bank 

atm: auth-encrypt.o atm-main.o atm.o net.o -lcrypto -lssl
bank: auth-encrypt.o bank-main.o bank.o net.o -lcrypto -lssl

clean:
	rm -f atm bank *.o
	rm -f *.card
	rm -f *.auth