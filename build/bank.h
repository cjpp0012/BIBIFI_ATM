/*
 * The Bank takes commands from the ATM, handled by
 * bank_process_remote_command.
 *
 * You can add more functions as needed.
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <signal.h>
#include <auth-encrypt.h>

#define CARD_FILE_SIZE 512

// Struct for storing accounts (linked list)
typedef struct alist {
	struct alist *next;
	char account[123];
	unsigned char card[CARD_FILE_SIZE];
	float balance;
	unsigned long whole;
	unsigned int decimal;
} alist;

typedef struct _Bank {
	// Networking state
	int sockfd;
	int clientfd;
	struct sockaddr_in bank_addr;
	struct sockaddr_in remote_addr;
	char *auth_file; 
    
	// Protocol state
	// Specify struct for storing state of bank and acount holders
	struct alist *table[256];

} Bank;

Bank* bank_create(char *auth_file, char *ip, unsigned short port);
void bank_free(Bank *bank);
int bank_send(Bank *bank, const char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_remote_command(Bank *bank, char *command);
void failure(Bank *bank, char* session_number);

#endif
