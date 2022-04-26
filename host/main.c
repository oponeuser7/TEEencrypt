/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define _CRT_SECURE_NO_WARNINGS

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	char option = 0;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encryptedkey[2] = {0,};
	int len = 64;
	int temp = 0;
	uint32_t err_origin;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));
	/* Get option (-e or -d)*/
	option = argv[1][1];
	/* Open file*/
	FILE* srcfile = fopen(argv[2], "r");
	/* Branch by option argument*/
	switch(option) {
		case 'e':
			if(strcmp(argv[3], "RSA")==0) {
				/*case RSA*/
				/*Read and close file*/
				fgets(plaintext, len, srcfile);
				fclose(srcfile);
				/*Initialize buffers*/
				char clear[RSA_MAX_PLAIN_LEN_1024];
				char ciph[RSA_CIPHER_LEN_1024];
				/*Prepare op*/
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = clear;
				op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
				op.params[1].tmpref.buffer = ciph;
				op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;
				/*Generate key*/
				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_GENKEYS, &op, &err_origin);
				/*Invoke RSA command*/
				printf("RSA encryption on it's way!\n");
				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENC,
				 &op, &err_origin);
				memcpy(ciph, op.params[1].tmpref.buffer, strlen(op.params[1].tmpref.buffer));
				/*Create output file and write encrypted string and close file*/
				FILE* encrypted = fopen("rsa_encrypted.txt", "w");
				fputs(ciph, encrypted);
				fclose(encrypted);
				break;
			}
			else if(strcmp(argv[3], "Ceaser")==0) {
				/*case Ceaser encrypt*/
				/*Read plain text and close file*/
				fgets(plaintext, len, srcfile);
				fclose(srcfile);
				/*Set parameters*/
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
						 TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = plaintext;
				op.params[0].tmpref.size = len;
				op.params[1].value.a = 0;
				/*Invoke encrypt command*/
				printf("Encryption on it's way!\n");
				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					&err_origin);
				/*Copy cipher text from shared memory*/
				memcpy(ciphertext, op.params[0].tmpref.buffer, len);
				/*Get key and convert into string*/
				temp = op.params[1].value.a;
				sprintf(encryptedkey, "%d", temp);
				/*Write and close file*/
				FILE* encrypted = fopen("encrypted.txt", "w");
				fputs(ciphertext, encrypted);
				fputs(encryptedkey, encrypted);
				fclose(encrypted);
				break;
			}
			else {
				printf("Wrong Parameter");
			}
		case 'd':
			/*case Ceaser decrypt*/
			/*Read cipher text and key from file*/
			fgets(ciphertext, len, srcfile);
			fgets(encryptedkey, 10, srcfile);
			fclose(srcfile);
			/*Set parameters*/
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
			op.params[0].tmpref.buffer = ciphertext;
			op.params[0].tmpref.size = len;
			op.params[1].value.a = atoi(encryptedkey);
			/*invoke decrypt command*/
			printf("Decryption on it's way!\n");
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				&err_origin);
			/*Copy result into plaintext*/
			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			/*Write and close file*/
			FILE* decrypted = fopen("decrypted.txt", "w");
			fputs(plaintext, decrypted);
			fclose(decrypted);
			break;
		default:
			printf("Wrong option ... -e or -d required");
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
