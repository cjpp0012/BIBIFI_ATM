#include "bank.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#define ERROR_CODE 255
#define MAX_SIZE 4096
#define BUFFER_SIZE 650
#define SESSION_SIZE 32

int verify_name(char *name, int isFile){
	//Initialize regex
	regex_t name_reg;
	if (regcomp(&name_reg, "^(([a-z]|-|_|[.]|[0-9])+)$", REG_EXTENDED) != 0)
		return ERROR_CODE;
	
	if ((regexec(&name_reg, name, 0, NULL, 0) != 0))
		return ERROR_CODE;
    
	if  (isFile && (((strlen(name) == 1 && name[0] == '.') || (strlen(name) == 2 && name[0] == '.' && name[1] == '.')) || strlen(name) > 127))
		//filename
		return ERROR_CODE;
	else if (!isFile && strlen(name) > 122)
		//account
		return ERROR_CODE;

	regfree(&name_reg);
	return EXIT_SUCCESS;
}

int verify_port(char *port) {
	regex_t num_reg;
	if (regcomp(&num_reg, "^([0]|[1-9][0-9]{0,4})$", REG_EXTENDED) != 0)
		return ERROR_CODE;
    
	if ((regexec(&num_reg, port, 0, NULL, 0) != 0))
		return ERROR_CODE;
    
	int value = atoi(port);
	if (value < 1024 || value > 65535)
		return ERROR_CODE;
    
	regfree(&num_reg);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv){
	
	unsigned short port = 0;
	char *ip = "127.0.0.1";
	char *auth_file = NULL;

	// Check number of args
	if (argc > 5)
		return ERROR_CODE;

	// get options
	int i = 0;
	for (i = 1; i < argc; i++) {
		char* curr = argv[i];
		
		if (strlen(curr) > MAX_SIZE || strlen(curr) < 2 || curr[0] != '-')
			return ERROR_CODE;

		char* argument = NULL;
		char option = '\0';

		if ((i + 1 >= argc) || (argv[i + 1][0] == '-')) {
			//curr is together with argument
			if (strlen(curr) < 3)
				return ERROR_CODE;

			option = curr[1];
			argument = curr + 2;
		 } else {
			//curr is option, next is argument
			if (strlen(curr) != 2)
				return ERROR_CODE;
			
			option = curr[1];
			argument = argv[++i];
			
			if (strlen(argument) > MAX_SIZE)
				return ERROR_CODE;
		}
		
		// Option Handler
		switch(option) {
			case 's':
				if (auth_file != NULL || verify_name(argument, 1) != 0)
					return ERROR_CODE;
				auth_file = argument;
				break;
			case 'p':
				if (port != 0 || verify_port(argument) != 0)
					return ERROR_CODE;
				port = strtoul(argument, NULL, 10);
				break;
			default :
				return ERROR_CODE;
		}
	}

	// Defaults
	if (port == 0)
		port = 3000;
	
	if (auth_file == NULL)
		auth_file = "bank.auth";
	
	// Create bank
	Bank *b = bank_create(auth_file, ip, port);

	/* process each incoming client, one at a time, until complete */
	for(;;) {

		unsigned int len = sizeof(b->remote_addr);
		b->clientfd = accept(b->sockfd, (struct sockaddr*)&b->remote_addr, &len);
		if (b->clientfd < 0) {
			perror("error on accept call");
			exit(63);
		}

		/* okay, connected to bank/atm. Send/recv messages to/from the bank/atm. */

		// Get atms random number
		char e_atm_session_number[(SESSION_SIZE / 2) + 12 + 16];
		bank_recv(b, e_atm_session_number, (SESSION_SIZE / 2) + 12 + 16);
		
		// Decrypt
		char session_number[SESSION_SIZE];
		if (decrypt(session_number, (unsigned char *) (b->auth_file), e_atm_session_number, SESSION_SIZE / 2) != 0) {
			close(b->clientfd);
			b->clientfd = -1;
			continue;
		}

		// Generate banks random number
		if (1 != RAND_bytes((unsigned char *) session_number + (SESSION_SIZE / 2), SESSION_SIZE / 2)) {
			close(b->clientfd);
			b->clientfd = -1;
			continue;
		}

		// Encrypt both random numbers for this session
		char e_session_number[SESSION_SIZE + 12 + 16];
		if (encrypt(e_session_number, (unsigned char *) (b->auth_file), (unsigned char *) session_number, SESSION_SIZE) != 0) {
			close(b->clientfd);
			b->clientfd = -1;
			continue;
		}

		// Send back encrypted session random
		bank_send(b, e_session_number, SESSION_SIZE + 12 + 16);

		// Recieve session number and command
		char e_buffer[BUFFER_SIZE + SESSION_SIZE + 12 + 16];
		bank_recv(b, e_buffer, sizeof(e_buffer));

		// Decrypt
		char buffer[BUFFER_SIZE + SESSION_SIZE];
		if (decrypt(buffer, (unsigned char *) (b->auth_file), e_buffer, BUFFER_SIZE + SESSION_SIZE) != 0) {
			close(b->clientfd);
			b->clientfd = -1;
			continue;
		}

		// Verify recieved session number
		if (memcmp(buffer, session_number, SESSION_SIZE) != 0) {
			failure(b, session_number);
			close(b->clientfd);
			b->clientfd = -1;
			continue;
		}

		// Execute and send back response
		bank_process_remote_command(b, buffer);

		/* cleanup */
		close(b->clientfd);
		b->clientfd = -1;
	}

	return EXIT_SUCCESS;
}
