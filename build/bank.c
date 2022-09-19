#include "bank.h"
#include "net.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define ERROR_CODE 255
#define CARD_FILE_SIZE 512
#define SESSION_SIZE 32

Bank* bank_create(char *auth_file, char *ip, unsigned short port)
{

	Bank *bank = (Bank*) calloc(1, sizeof(Bank));
    
	if(bank == NULL) {
		perror("Could not allocate Bank");
		exit(255);
	}

	// if not auth_file exists, create auth_file
	// Generate Auth File Symmetric Key
	// Fail if already exists or creation fails
	unsigned char *k = malloc(256);
	FILE *auth_file_fp = NULL;

	if(RAND_bytes(k, 256) != 1) exit(ERROR_CODE);

	if (access(auth_file, F_OK) == 0)
		exit(ERROR_CODE);

	if ((auth_file_fp = fopen(auth_file, "wb")) == NULL)
		exit(ERROR_CODE);
		
	if (fwrite(k, 256, 1, auth_file_fp) != 1)
		exit(ERROR_CODE);
			
	fclose(auth_file_fp);
	printf("created\n");
	fflush(stdout);
	bank->auth_file = (char *) k;

#define BOOL_CHK(x,msg) if (x) { perror(msg); exit(255); }


	/* setup network connection */
	BOOL_CHK(inet_pton(AF_INET, ip, &(bank->bank_addr.sin_addr)) != 1, "could not convert ip address");

	bank->bank_addr.sin_port = htons(port);
	bank->bank_addr.sin_family = AF_INET;

	int s = socket(AF_INET, SOCK_STREAM, 0);
	BOOL_CHK(s<0,"could not create socket");

	int enable = 1;
	BOOL_CHK(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0, "setsockopt(SO_REUSEADDR) failed");
	struct timeval tv;
	tv.tv_sec = 100;
	tv.tv_usec = 0;
	BOOL_CHK(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0, "setsockopt(SO_RCVTIMEO) failed");

	BOOL_CHK(bind(s, (struct sockaddr*)&(bank->bank_addr), sizeof(bank->bank_addr)) < 0, "could not bind");

	listen(s, 5);

	bank->sockfd = s;

#undef BOOL_CHK

	return bank;
}

void bank_free(Bank *bank){
	close(bank->sockfd);
	free(bank->auth_file);
}

/* sends data_len bytes from data to atm, returns size 0 on success, negative on failure */
int bank_send(Bank *bank, const char *data, size_t data_len) {
	if (bank->clientfd < 0) {
		return -1;
	}

	if (send_all(bank->clientfd, (const char*)&data_len, sizeof(data_len)) != sizeof(data_len)) {
		return -2;
	}

	if (send_all(bank->clientfd, data, data_len) != (ssize_t)data_len) {
		return -3;
	}
	return 0;	
}

/* receive a message (i.e., something sent via atm_send) and store it
 * in data. If the message exceeds max_data_len, a negative value is
 * returned and the message is discarded */
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len) {

	size_t msg_len;

	if (bank->clientfd < 0) {
		return -1;
	}

	if (recv_all(bank->clientfd, (char*)&msg_len, sizeof(msg_len)) != sizeof(msg_len)) {
		return -2;
	}

	if (msg_len > max_data_len) {
		/* message doesn't fit in data, read all of the message to discard it */
		char tmp[4096];
		do {
			size_t to_read = msg_len > sizeof(tmp) ? sizeof(tmp) : msg_len;
			if (recv_all(bank->clientfd, tmp, to_read) != sizeof(to_read)) {
				/* logic error somewhere, should probably crash/restart */
				return -3;
			}
			msg_len -= to_read;
		} while(msg_len > 0) ;
	}

	return recv_all(bank->clientfd, data, msg_len);	

}

// Get index of linked list that could contain account
int hash_account(char *account) {
	EVP_MD_CTX *mdctx; 
	const EVP_MD *md; 
	
	// Get and initialize context 
	md = EVP_get_digestbyname("sha256");
	
	if (!md) { 
		return -1; 
	} 

	mdctx = EVP_MD_CTX_new(); 

 	if (!mdctx) { 
        return -1; 
	}

	if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) { 
		return -1; 
	}

	unsigned char *hash = malloc(EVP_MAX_MD_SIZE);

	if (1 != EVP_DigestUpdate(mdctx, account, strlen(account))) { 
		return -1; 
	} 

	if (1 != EVP_DigestFinal_ex(mdctx, hash, NULL)) { 
		return -1; 
	}

	// Array is size 256 so 1 bytes index (0 to 255)
	int index = (int) hash[0];
	
	EVP_MD_CTX_free(mdctx); 
	free(hash);

	return index;
}

void failure(Bank *bank, char* session_number) {
	// Send failure response with session number
	char result[256 + SESSION_SIZE];
	memcpy(result, session_number, SESSION_SIZE);
	strcpy(result + SESSION_SIZE, "ERROR");

	//Encrypt
	char e_result[256 + 12 + 16 + SESSION_SIZE];
	if (encrypt(e_result, (unsigned char *) (bank->auth_file), (unsigned char *) result, 256 + SESSION_SIZE) != 0) {
		return;
	}

	bank_send(bank, e_result, 256 + 12 + 16 + SESSION_SIZE);
}

void bank_process_remote_command(Bank *bank, char *command) {
	
	// Initialize command information
	enum mode{NONE, NEW, DEPOSIT, WITHDRAW, GET};
	char session_number[SESSION_SIZE];
	memcpy(session_number, command, SESSION_SIZE);
	unsigned char card_file[CARD_FILE_SIZE];
	char account[123];
	unsigned long whole = 0;
	unsigned int decimal = 0;
	int temp_decimal = 0;
		
	enum mode current_mode = NONE;

	// Slip command into parts
	memcpy(&current_mode, command + SESSION_SIZE, sizeof(current_mode));
	memcpy(account, command + sizeof(current_mode) + SESSION_SIZE, 123);
	account[122] = '\0';
	memcpy(card_file, command + sizeof(current_mode) + 123 + SESSION_SIZE, CARD_FILE_SIZE);
	memcpy(&whole, command + sizeof(current_mode) + 123 + CARD_FILE_SIZE + SESSION_SIZE, sizeof(decimal));
	memcpy(&decimal, command + sizeof(current_mode) + 123 + CARD_FILE_SIZE + SESSION_SIZE + sizeof(decimal), sizeof(decimal));

	// Find alist for appropriate account
	int ind = hash_account(account);
	if (ind == -1) {
		failure(bank, session_number);
		return;
	}
	struct alist *curr = bank->table[ind];
	while (curr) {
		if (!strcmp(account, curr->account)) {
			if (current_mode == GET) {
				whole = curr->whole;
				decimal = curr->decimal;
			}
			break;
		}
		curr = curr->next;
	}

	// If not found or (is found but trying to create) or card file is invalid, fail
	if ((current_mode != NEW && (curr == NULL || (memcmp(card_file, curr->card, CARD_FILE_SIZE)))) || (current_mode == NEW && curr != NULL) ) {
		failure(bank, session_number);
		return;
	}
	
	// Process command
	char *value = "initial_balance";
	switch(current_mode) {
		case NEW:;
			// Add account
			struct alist *loc = bank->table[ind];
			struct alist *new = (struct alist*) calloc(1, sizeof(struct alist));
			if (!new) {
				failure(bank, session_number);
				return;
			}
			new->next = loc;
			memcpy(new->account, account, 123);
			memcpy(new->card, card_file, CARD_FILE_SIZE);
			new->whole = whole;
			new->decimal = decimal;
			bank->table[ind] = new;
			break;
		case DEPOSIT:
			value = "deposit";
			if (curr->whole + whole < curr->whole) {
				failure(bank, session_number);
				return;
			}
			temp_decimal = curr->decimal + decimal;
			if (temp_decimal >= 100) {
				temp_decimal -= 100;
				if (curr->whole + 1 < curr->whole) {
					failure(bank, session_number);
					return;
				}
				curr->whole += 1;
				curr->decimal = temp_decimal;
			} else {
				curr->decimal += decimal;
			}
			curr->whole += whole;
			break;
		case WITHDRAW:
			value = "withdraw";
			if (curr->whole < whole || (curr->whole == whole && curr->decimal < decimal)) {
				failure(bank, session_number);
				return;
			}
			curr->whole -= whole;
			temp_decimal = curr->decimal - decimal;
			if (temp_decimal < 0) {
				curr->decimal = temp_decimal + 100;
				curr->whole -= 1;
			} else {
				curr->decimal -= decimal;
			}
			break;
		case GET:
			value = "balance";
			break;
		default:
			return;
	}
	
	// Send back successful response with session number
	char result[256 + SESSION_SIZE];
	memcpy(result, session_number, SESSION_SIZE);
	snprintf (result + SESSION_SIZE, 256, "{\"account\":\"%s\",\"%s\":%lu.%02u}\n", account, value, whole, decimal);
	printf("%s",result + SESSION_SIZE);
	fflush(stdout);

	//Encrypt
	char e_result[256 + 12 + 16 + SESSION_SIZE];
	if (encrypt(e_result, (unsigned char *) (bank->auth_file), (unsigned char *) result, 256 + SESSION_SIZE) != 0) {
		return;
	}

	bank_send(bank, e_result, 256 + 12 + 16 + SESSION_SIZE);
	
}
