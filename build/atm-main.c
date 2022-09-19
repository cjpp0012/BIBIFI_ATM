#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <errno.h>
#include <openssl/rand.h> 
#include <unistd.h>

#define ERROR_CODE 255
#define PROTOCOL_ERROR 63
#define MAX_SIZE 4096
#define CARD_FILE_SIZE 512
#define BUFFER_SIZE 650 // 4 (mode) + 122 + 1 (account) + CARD_FILE_SIZE + 4 (float)
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

int verify_ip(char *ip) {
	regex_t ip_reg;
	if (regcomp(&ip_reg, "^((25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])[.]){3}(25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1-9][0-9]|[0-9])$", REG_EXTENDED) != 0)
		return ERROR_CODE;

	if ((regexec(&ip_reg, ip, 0, NULL, 0) != 0))
		return ERROR_CODE;

	regfree(&ip_reg);
	return EXIT_SUCCESS;
}

int verify_amount(char *amount) {
	regex_t decimal_reg;
	if (regcomp(&decimal_reg, "^([0]|[1-9][0-9]{0,9})[.]([0-9]{2})$", REG_EXTENDED) != 0)
		return ERROR_CODE;
    
	if ((regexec(&decimal_reg, amount, 0, NULL, 0) != 0))
		return ERROR_CODE;
    
	int end = strlen(amount) - 3;
	char *eptr = (amount + end);
	long left = strtol(amount, &eptr, 10);
	if (errno == ERANGE || errno == EINVAL || left > 4294967295)
		return ERROR_CODE;
    
	regfree(&decimal_reg);
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

// Sends back message so bank fails gracefully 
void early_fail(ATM *atm) {
	char *empty = calloc(1, BUFFER_SIZE + SESSION_SIZE + 12 + 16);
	if (!empty) return;
	atm_send(atm, empty, BUFFER_SIZE + SESSION_SIZE + 12 + 16);
}

int main(int argc, char** argv){

	// Input initialization
	enum mode{NONE, NEW, DEPOSIT, WITHDRAW, GET};
  	unsigned short port = 0;
	char *ipAddr = NULL;
	char *card_file = NULL;
	char *auth_file = NULL;
	char *account = NULL;
	
	unsigned int whole = 0;
	unsigned int decimal = 0;
	char* decimal_point = NULL;
	enum mode current_mode = NONE;

	// Check number of args
	if (argc < 2 || argc > 13)
		return ERROR_CODE;

	// Input Handling (POSIX)
	int i = 0;
	for (i = 1; i < argc; i++) {

		char* curr = argv[i];
		if (strlen(curr) > MAX_SIZE || strlen(curr) < 2 || curr[0] != '-')
			return ERROR_CODE;

		char* argument = NULL;
		char option = '\0';

		// Handle g (can be joined with other options)
		if (curr[1] == 'g') {
			if (current_mode == NONE)
				current_mode = GET;
			else
				return ERROR_CODE;
			if(strlen(curr) != 2) {
				curr[1] = curr[0];
				curr++;
			} else {
				continue;
			}
		}

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
			case 'i':
				if (ipAddr != NULL || verify_ip(argument) != 0)
					return ERROR_CODE;
				ipAddr = argument;
				break;
			case 'p':
				if (port != 0 || verify_port(argument) != 0)
					return ERROR_CODE;
				port = strtoul(argument, NULL, 10);
				break;
			case 'c':
				if (card_file != NULL || verify_name(argument, 1) != 0)
					return ERROR_CODE;
				card_file = malloc(128);
				strcpy(card_file, argument);
				break;
			case 'a':
				if (account != NULL || verify_name(argument, 0) != 0)
					return ERROR_CODE;
				account = argument;
				break;
			case 'n':
				if (current_mode != NONE || verify_amount(argument) != 0)
					return ERROR_CODE;
				current_mode = NEW;
				
				whole = strtoul(argument, NULL, 10);
				decimal_point = strchr(argument, '.');
				decimal = strtoul(decimal_point + 1, NULL, 10);
				if (whole < 10) return ERROR_CODE;
				break;
			case 'd':
				if (current_mode != NONE || verify_amount(argument) != 0)
					return ERROR_CODE;
				current_mode = DEPOSIT;

				whole = strtoul(argument, NULL, 10);
				decimal_point = strchr(argument, '.');
				decimal = strtoul(decimal_point + 1, NULL, 10);
				if (whole == 0 && decimal == 0) return ERROR_CODE;
				break;
			case 'w':
				if (current_mode != NONE || verify_amount(argument) != 0)
					return ERROR_CODE;
				current_mode = WITHDRAW;

				whole = strtoul(argument, NULL, 10);
				decimal_point = strchr(argument, '.');
				decimal = strtoul(decimal_point + 1, NULL, 10);
				if (whole == 0 && decimal == 0) return ERROR_CODE;
				break;
			default :
				return ERROR_CODE;
		}
	}

	// Fail if no command specified
	if (account == NULL || current_mode == NONE)
			return ERROR_CODE;

	// Default cardfile, port, ip address, and auth file
	if (card_file == NULL) {
		card_file = malloc(128);
		if (!card_file)
			return ERROR_CODE;
		strcpy(card_file, account);
		strcat(card_file, ".card");
	}

	if (port == 0)
		port = 3000;

	if (ipAddr == NULL)
		ipAddr = "127.0.0.1";
	
	if (auth_file == NULL)
		auth_file = "bank.auth";

	// Read authfile
	unsigned char auth_content[256];
	FILE *auth_file_fp = NULL;

	if ((auth_file_fp = fopen(auth_file, "rb")) == NULL)
		return ERROR_CODE;

	if (fread(auth_content, 256, 1, auth_file_fp) != 1)
		return ERROR_CODE;
			
	fclose(auth_file_fp);

	// Create/read cardfile
	unsigned char card_content[CARD_FILE_SIZE];
	FILE *card_file_fp = NULL;

	if (current_mode == NEW) {
		if (access(card_file, F_OK) == 0)
			return ERROR_CODE;
		
		if (1 != RAND_bytes(card_content, CARD_FILE_SIZE))
			return ERROR_CODE;

	} else {
		if ((card_file_fp = fopen(card_file, "rb")) == NULL)
			return ERROR_CODE;

		if (fread(card_content, CARD_FILE_SIZE, 1, card_file_fp) != 1)
			return ERROR_CODE;
			
		fclose(card_file_fp);
	}

	// Send packet and receive response
	ATM *atm = atm_create(ipAddr, port);

	// Send atm random session number
	unsigned char atm_session_number[SESSION_SIZE / 2];
	if (1 != RAND_bytes(atm_session_number, SESSION_SIZE / 2)) {
		early_fail(atm);
		return ERROR_CODE;
	}
	
	//Encrypt
	char e_atm_session_number[(SESSION_SIZE / 2) + 12 + 16];
	if (encrypt(e_atm_session_number, auth_content, atm_session_number, SESSION_SIZE / 2) != 0) {
		early_fail(atm);
		return ERROR_CODE;
	}

	if (atm_send(atm, e_atm_session_number, (SESSION_SIZE / 2) + 12 + 16) < 0)
		return PROTOCOL_ERROR;

	// Recieve atm and bank random numbers to use for session number
	char e_session_number[SESSION_SIZE + 12 + 16];
	if (atm_recv(atm, e_session_number, SESSION_SIZE + 12 + 16) < 0)
		return PROTOCOL_ERROR;

	//Decrypt
	char session_number[SESSION_SIZE];
	if (decrypt(session_number, auth_content, e_session_number, SESSION_SIZE) != 0) {
		early_fail(atm);
		return ERROR_CODE;
	}

	// Verify session number
	if (memcmp((char *) atm_session_number, session_number, 16) != 0) {
		early_fail(atm);
		return ERROR_CODE;
	}

	// Create packet buffer (session number, mode, account, card content, amount)
	char buffer[BUFFER_SIZE + SESSION_SIZE];
	char *ptr = memcpy(buffer, session_number, SESSION_SIZE);
	ptr = memcpy(ptr + SESSION_SIZE, &current_mode, sizeof(current_mode));
	ptr = strcpy(ptr + sizeof(current_mode), account);
	ptr = memcpy(ptr + 123, &card_content, CARD_FILE_SIZE);
	ptr = memcpy(ptr + CARD_FILE_SIZE, &whole, sizeof(whole));
	ptr = memcpy(ptr + sizeof(whole), &decimal, sizeof(decimal));
	ptr = NULL;

	//Encrypt
	char e_buffer[BUFFER_SIZE + SESSION_SIZE + 12 + 16];
	if (encrypt(e_buffer, auth_content, (unsigned char *) buffer, BUFFER_SIZE + SESSION_SIZE) != 0) {
		early_fail(atm);
		return ERROR_CODE;
	}
	
	// Send command packet and recieve response
	if (atm_send(atm, e_buffer, BUFFER_SIZE + SESSION_SIZE + 12 + 16) < 0)
		return PROTOCOL_ERROR;
	if (atm_recv(atm, buffer, BUFFER_SIZE + SESSION_SIZE) < 0)
		return PROTOCOL_ERROR;

	//Decrypt
	char result[256 + 12 + 16 + SESSION_SIZE];
	if (decrypt(result, auth_content, buffer, 256 + SESSION_SIZE) != 0) {
		return ERROR_CODE;
	}

	// Verify session number
	if (memcmp((char *) session_number, result, 32) != 0) {
		return ERROR_CODE;
	}

	// Print appropriate response
	if (!strncmp(result + SESSION_SIZE, "ERROR", 6)) return ERROR_CODE;
	printf("%s", result + SESSION_SIZE);
	fflush(stdout);

	// If successful NEW
	if (current_mode == NEW) {
		if ((card_file_fp = fopen(card_file, "wb")) == NULL) {
			return ERROR_CODE;
		}
		
		if (fwrite(card_content, CARD_FILE_SIZE, 1, card_file_fp) != 1) {
			return ERROR_CODE;
		}
			
		fclose(card_file_fp);
	}
	
	atm_free(atm);
	free(card_file);

	return EXIT_SUCCESS;
}
