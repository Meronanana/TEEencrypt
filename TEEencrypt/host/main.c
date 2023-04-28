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

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define MAX_LENGTH 100

int main(int argc, char** argv)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	// Parameter
	char plaintext[MAX_LENGTH] = {0,};
	char ciphertext[MAX_LENGTH] = {0,};
	char* option = argv[1];
	int random_key;
	FILE *fp, *fi;

	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = MAX_LENGTH;

	// Encrypt
	if(strcmp(option, "-e") == 0) {	
		printf("========================Caesar Encryption========================\n");
		fp = fopen(argv[2], "r");
		fgets(plaintext, sizeof(plaintext), fp);
		printf("Plaintext: %s\n", plaintext);
		memcpy(op.params[0].tmpref.buffer, plaintext, MAX_LENGTH);
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, MAX_LENGTH);
		printf("Ciphertext : %s\n", ciphertext);

		fp = fopen("ciphertext.txt","w");
		fputs(ciphertext, fp);

		fp = fopen("encryptedkey.txt", "w");
		fprintf(fp, "%d\n", op.params[1].value.a);
		fclose(fp);
	}
	
	// Decrypt
	else if(strcmp(option, "-d") == 0) {
		// Ciphertext and key is stored at seperated file
		printf("========================Caesar Decryption========================\n");
		fi = fopen(argv[2], "r");
		fgets(ciphertext, sizeof(ciphertext), fi);
		fflush(fi);

		fi = fopen(argv[3],"r");
		fscanf(fi, "%d", &random_key);
		printf("dec_key: %d\n", random_key);
		printf("Ciphertext : %s\n", ciphertext);

		memcpy(op.params[0].tmpref.buffer, ciphertext, MAX_LENGTH);
		op.params[1].value.a = random_key;

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, MAX_LENGTH);
		printf("Plaintext : %s\n", plaintext);

		fi = fopen("caesar_plaintext.txt","w");
		fputs(plaintext, fi);
		fclose(fi);
	}

	// Unable option
	else{
		printf("wrong option\n");	
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
