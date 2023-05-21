/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cpplite/CTemplate.c to edit this template
 */

// gcc AP.c -o AP -L. -lpbc -lgmp -lcbor
// ./AP <../a.param
// ./AP <~/Desktop/ris/pbc-0.5.14/param/a.param

// Boneh-Lynn-Shacham short signatures demo.
//
// See the PBC_sig library for a practical implementation.
//
// Ben Lynn
#include "../../pbc-0.5.14/include/pbc.h"
#include "../../pbc-0.5.14/include/pbc_test.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <cbor.h>
#include "aes.h"
#include "aes.c"
#include "sha256.h"
#include "sha256.c"

#define CLIENT_PORT 50000
#define NM_PORT 40000
#define AP_PORT 60000

struct m1
{
	element_t T1;
	element_t C1;
	element_t Auth1;
};

struct m2
{
	element_t y2;
	element_t Auth2;
	element_t t2;
};

struct m3
{
	element_t Auth3;
};

int main(int argc, char **argv)
{
	/* Preallocate the map structure CBOR */
	cbor_item_t * root = cbor_new_definite_map(1);

	int sfd, len;
	struct sockaddr_in client_address, nm_address, ap_address;
	unsigned char buf[1024];
	unsigned char temp_buf[1024];
	element_t temp;
	pairing_t pairing;
	element_t g, h;
	element_t public_key, sig;
	element_t secret_key;
	element_t temp1, temp2;

	element_t P, q, Gnm, Snm, Qnm, Sap, Kap, Rc, Sc, Gc, Hc, x, Xc, T1, t1, h1, h1P, h1PplusQnm, Xch1PplusQnm, K1, K2, h1plusSnm, Xch1plusSnm, PXch1plusSnm, XcP, Invh1plusSnm, Yap, Y1, Y2,
		SnmHc, YapPlusSap, SKap, Y1K2, XcPlusSc, XcPlusScDivSc, SKc, InvSc;
	// element_t G1 , G2 , q, e, P,Qnm , gnm g, h1 , h2 , omega;

	int IDap = 100, IDc = 200;
	struct timeval now;
	unsigned long time1, time2, pres_time, prev_time, prev_time_m2, pres_time_m2;
	unsigned long prev_time_file, pres_time_file;

	pbc_demo_pairing_init(pairing, argc, argv);

	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	client_address.sin_family = AF_INET;
	client_address.sin_addr.s_addr = INADDR_ANY;
	client_address.sin_port = htons(CLIENT_PORT);

	nm_address.sin_family = AF_INET;
	nm_address.sin_addr.s_addr = inet_addr("127.0.0.1");
	nm_address.sin_port = htons(NM_PORT);

	ap_address.sin_family = AF_INET;
	ap_address.sin_addr.s_addr = inet_addr("127.0.0.1");
	ap_address.sin_port = htons(AP_PORT);

	if (bind(sfd, (struct sockaddr *)&ap_address,
			 sizeof(ap_address)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	printf("\n****************************************** Waiting for message from NM ****************************************** \n\n");
	len = recvfrom(sfd, buf, 1024, 0, 0, 0);
	printf("Received Authentication message from NM of size %d\n\n", len);

	element_init_G1(P, pairing);
	element_from_bytes(P, buf);
	element_printf("P is %B\n\n", P);

	element_init_Zr(Snm, pairing);
	element_from_bytes(Snm, buf + 128);
	element_printf("Snm is %B\n\n", Snm);

	element_init_G1(Qnm, pairing);
	element_from_bytes(Qnm, buf + 148);
	element_printf("Qnm is %B\n\n", Qnm);

	element_init_GT(g, pairing);
	element_from_bytes(g, buf + 276);
	element_printf("g is %B\n\n", g);

	element_init_GT(Gnm, pairing);
	element_from_bytes(Gnm, buf + 404);
	element_printf("Gnm is %B\n\n", Gnm);

	element_init_Zr(Sc, pairing);
	element_from_bytes(Sc, buf + 532);
	element_printf("Sc is %B\n\n\n", Sc);

	/*element_init_GT(Gc, pairing);
	element_from_bytes(Gc,buf+552);
	element_printf("Gc is %B\n",Gc);*/

	// return 0;

	printf("****************************************** Pairing based Authentication test****************************************** \n\n");
	/***************Authentication*******************************/

	/********NM Parameter generation********************/
	/*element_init_G1(P, pairing);
	element_random(P);
	element_printf("system parameter P = %B\n", P);

	element_init_Zr(Snm, pairing);
	element_random(Snm);
	element_printf("system parameter Snm = %B\n", Snm);

	element_init_G1(Qnm, pairing);
	element_mul_zn(Qnm,P,Snm);
	element_printf("system parameter  Qnm= %B\n", Qnm);

	element_init_GT(g, pairing);
	element_pairing(g, P, P);
	element_printf("system parameter g = %B\n", g);

	element_init_GT(Gnm, pairing);
	element_pow_zn(Gnm, g, Snm);
	element_printf("system parameter Gnm = %B\n", Gnm);*/

	/*******************Additional NM Parameter******************/
	/*element_init_Zr(Rc, pairing);
	element_random(Rc);
	element_printf("system parameter Rc = %B\n", Rc);

	element_init_GT(Gc, pairing);
	element_pow_zn(Gc, g, Rc);
	element_printf("system parameter Gc = %B\n", Gc);

	element_init_Zr(Hc, pairing);
	element_from_hash(Hc, "gc, Rightc, Qnm", 16);
	element_printf("system parameter Hc = %B\n", Hc);

	element_init_Zr(SnmHc, pairing);
	element_mul_zn(SnmHc,Snm,Hc);
	element_printf("system parameter SnmHc= %B\n", SnmHc);

	element_init_Zr(Sc, pairing);
	element_add(Sc,Rc,SnmHc);
	element_printf("system parameter Sc= %B\n", Sc);*/

	/*****************End Additional NM Parameter************************/

	/********End NM Parameter generation********************/

	/*************Phase-1 Message Verification Compute K2 and check against k1**********************/
	unsigned char T1_bytes[128];
	unsigned char C1_bytes[128];
	unsigned char Gc_bytes[128];
	unsigned char K2_bytes[128];
	unsigned char hash[32];
	unsigned char dec_key[32];
	unsigned char dec_buf[1024];
	unsigned char T1Gc[1024];
	unsigned char Y2SKap[1024];
	unsigned char SKapK2[1024];
	unsigned char Auth1[32];
	unsigned char Auth2[32];
	unsigned char tmp[128];
	unsigned char Y2_bytes[128];
	unsigned char SKap_bytes[128];

	printf("\n****************************************** Waiting for message from Client ****************************************** \n");
	// len = recvfrom(sfd, buf, 1024, 0, 0, 0);
	len = recvfrom(sfd, temp_buf, 1024, 0, 0, 0);
	memcpy(buf, temp_buf+6, 288);
	// for(int i=0;i<294;i++)
	// {
	// 	printf("%hhu ",temp_buf[i]);
	// }
	// printf("\n");
	
	printf("Received Authentication message from Client of size: %d and percent reduction: %f\n\n", len, (100.0-(len/388.0)*100));
	printf("\n****************************************** Verification of message m1 ****************************************** \n");
	element_init_G1(T1, pairing);
	element_from_bytes(T1, buf);
	element_printf("system parameter T1 = %B\n", T1);

	/*if (sendto(sfd, buf, 1024 , 0, (struct sockaddr*) &client_address, sizeof(client_address)) == -1)
{
printf("Sendto failed\n");
}*/

	element_init_Zr(h1, pairing);
	element_from_hash(h1, "ID(AP)", 7);
	element_printf("system parameter h1 = %B\n\n", h1);

	element_init_Zr(h1plusSnm, pairing);
	element_add(h1plusSnm, h1, Snm);
	element_printf("system parameter h1plusSnm = %B\n\n", h1plusSnm);

	element_init_Zr(Invh1plusSnm, pairing);
	element_invert(Invh1plusSnm, h1plusSnm);
	element_printf("system parameter Invh1plusSnm = %B\n\n", Invh1plusSnm);

	element_init_G1(Kap, pairing);
	element_mul_zn(Kap, P, Invh1plusSnm);
	element_printf("system parameter Kap = %B\n\n", Kap);

	element_init_GT(K2, pairing);
	element_pairing(K2, T1, Kap);
	element_printf("system parameter K2 = %B\n\n", K2);

	element_to_bytes(K2_bytes, K2);
	gettimeofday(&now, NULL);
	prev_time = now.tv_sec * 1000000 + now.tv_usec;
	sha256(K2_bytes, 128, hash);
	memcpy(dec_key, hash, 32);
	gettimeofday(&now, NULL);
	pres_time = now.tv_sec * 1000000 + now.tv_usec;
	printf("Time for SHA-256 computation time is %d microseconds\n", (pres_time - prev_time));
	gettimeofday(&now, NULL);
	prev_time = now.tv_sec * 1000000 + now.tv_usec;
	decrypt_aes(buf + 128, 128, Gc_bytes, dec_key);
	gettimeofday(&now, NULL);
	pres_time = now.tv_sec * 1000000 + now.tv_usec;
	printf("\nTime for decryption (AES-256) computation time is %d microseconds\n", (pres_time - prev_time));

	element_init_GT(Gc, pairing);
	element_from_bytes(Gc, Gc_bytes);
	element_printf("system parameter Gc = %B\n", Gc);

	element_to_bytes(T1_bytes, T1);
	memcpy(T1Gc, T1_bytes, 128);
	memcpy(T1Gc + 128, Gc_bytes, 128);
	memcpy(T1Gc + 256, K2_bytes, 128);
	gettimeofday(&now, NULL);
	prev_time = now.tv_sec * 1000000 + now.tv_usec;
	sha256(T1Gc, 384, hash);
	gettimeofday(&now, NULL);
	pres_time = now.tv_sec * 1000000 + now.tv_usec;
	printf("Time for SHA-256 computation time is %d microseconds\n", (pres_time - prev_time));

	/*printf("\nT1Gc is\n");
	for(int i=0;i<256;i++)
	printf("%hhu ",T1Gc[i]);*/
	if (memcmp(hash, buf + 256, 32) == 0)
		printf("\n[+] Authentication of message m1 verified!!!!!!\n");
	else
		printf("\n[-] Authentication of message m1 failed????????\n");

	/*if (!element_cmp(K1, K2)) {
			printf("signature verifies\n");
		  } else {
			printf("*BUG* signature does not verify *BUG*\n");
		  }*/

	/**************Phase-2 Authentication i.e. Message m2 Generation********************/
	printf("\n ************************* Message m2 Generation ************************* \n\n");
	gettimeofday(&now, NULL);
	prev_time_m2 = now.tv_sec * 1000000 + now.tv_usec;

	element_init_Zr(Yap, pairing);
	element_random(Yap);
	element_printf("system parameter Yap = %B\n\n", Yap);

	element_init_Zr(Sap, pairing);
	element_from_hash(Sap, "Kap||ID(AP)", 12);
	element_printf("system parameter Sap = %B\n\n", Sap);

	element_init_GT(Y1, pairing);
	element_pow_zn(Y1, g, Sc);
	element_printf("system parameter Y1 = %B\n\n", Y1);

	element_init_Zr(YapPlusSap, pairing);
	element_add(YapPlusSap, Yap, Sap);
	element_printf("system parameter YapPlusSap = %B\n\n", YapPlusSap);

	element_init_GT(Y2, pairing);
	element_pow_zn(Y2, Y1, YapPlusSap);
	element_printf("system parameter Y2 = %B\n\n", Y2);

	element_init_GT(Y1K2, pairing);
	element_mul(Y1K2, Y1, K2);
	element_printf("system parameter Y1K2 = %B\n\n", Y1K2);

	element_init_GT(SKap, pairing);
	element_pow_zn(SKap, Y1K2, YapPlusSap);
	element_printf("system parameter SKap = %B\n\n", SKap);

	element_to_bytes(Y2_bytes, Y2);
	element_to_bytes(SKap_bytes, SKap);

	memcpy(buf, Y2_bytes, 128);

	memcpy(Y2SKap, Y2_bytes, 128);
	memcpy(Y2SKap + 128, SKap_bytes, 128);
	memcpy(Y2SKap + 256, Gc_bytes, 128);
	memcpy(Y2SKap + 384, T1_bytes, 128);
	memcpy(Y2SKap + 512, K2_bytes, 128);

	/*printf("\nY2SKap is");
	for(int i=0;i<640;i++)
	{
	  if(i%128==0)
	  printf("\n");
	  printf("%hhu ",Y2SKap[i]);
	}*/

	gettimeofday(&now, NULL);
	prev_time = now.tv_sec * 1000000 + now.tv_usec;
	sha256(Y2SKap, 640, hash);
	memcpy(buf + 128, hash, 32);
	gettimeofday(&now, NULL);
	pres_time = now.tv_sec * 1000000 + now.tv_usec;
	printf("Time for SHA-256 computation time is %d microseconds\n", (pres_time - prev_time));
	gettimeofday(&now, NULL);
	time2 = now.tv_sec * 1000000 + now.tv_usec;
	// printf("\ntime2 is %lu",time2);
	memcpy(buf + 160, (unsigned char *)&time2, 8);

	// for(int i=0;i<168;i++)
	// {
	// 	printf("%hhu ",buf[i]);
	// }

	/* Add the content */
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("1")),
		.value = cbor_move(cbor_build_bytestring(buf, 168))
	});
	
	/* Output: `length` bytes of data in the `buffer` */
	unsigned char * buffer;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

	// printf("\nbuffer_size: %lu \n", buffer_size);
	// printf("\nlength: %lu \n", length);

	// for(int i=0;i<173;i++)
	// {
	// 	printf("%hhu ",buffer[i]);
	// }
	// printf("\n");

	gettimeofday(&now, NULL);
	pres_time_m2 = now.tv_sec * 1000000 + now.tv_usec;

	printf("Time for m2 generation is %d microseconds\n", (pres_time_m2 - prev_time_m2));
	
	// if (sendto(sfd, buf, 168, 0, (struct sockaddr *)&client_address, sizeof(client_address)) == -1)
	if (sendto(sfd, buffer, 173, 0, (struct sockaddr *)&client_address, sizeof(client_address)) == -1)
	{
		printf("[-] Sendto failed for m2\n");
	}
	else
	{
		printf("[+] Sendto successful for m2\n");
	}

	printf("\n****************************************** Waiting for message from Client ****************************************** \n");
	// len = recvfrom(sfd, buf, 1024, 0, 0, 0);
	len = recvfrom(sfd, temp_buf, 1024, 0, 0, 0);
	memcpy(buf, temp_buf+5, 32);
	// for(int i=0;i<37;i++)
	// {
	// 	printf("%hhu ",temp_buf[i]);
	// }
	// printf("\n");
	printf("Received Authentication message from Client of size: %d and percent reduction: %f\n\n", len, (100.0-(len/47.0)*100));

	printf("\n****************************************** Verification of message m3 ****************************************** \n");

	memcpy(SKapK2, SKap_bytes, 128);
	memcpy(SKapK2 + 128, K2_bytes, 128);
	memcpy(SKapK2 + 256, Y2_bytes, 128);
	sha256(SKapK2, 384, hash);

	if (memcmp(hash, buf, 32) == 0)
	{
		printf("\n[+] Authentication of message m3 verified!!!!!!\n\n");
		// printf("***************Authentication Successful*******************\n\n");
	}
	else
	{
		printf("\n[-] Authentication of message m3 failed????????\n\n");
		// printf("\nXXXXXXXXXXXXXXXXAuthentication FailedXXXXXXXXXXXXXXXXXXXXX\n\n");
	}

	/* receiving .txt file over network */
	// printf("\n ****************************************** Receiving file over network ****************************************** \n");
	// unsigned long long offset_pos = 0;
	// unsigned long long r;
	// int fd_write;
	// char *destn_loc = "ABC.txt";
	// // char *destn_loc = "ABC.pdf";
	// fd_write = open(destn_loc, O_CREAT | O_WRONLY, 0777);
	// if (fd_write == -1)
	// {
	// 	// msg("Error Occured opening file");
	// }
	// while (1)
	// {
	// 	bzero(buf, 1024);
	// 	int len = recvfrom(sfd, buf, 1024, 0, 0, 0);
	// 	// int len = recv(network_socket, b, MESSAGELEN, 0);
	// 	if (len < 0)
	// 	{
	// 		printf("Receiving failed\n");
	// 		break;
	// 	}
	// 	else if (len == 0)
	// 	{
	// 		printf("Time to leave\n");
	// 		break;
	// 	}
	// 	else if (len > 0)
	// 	{
	// 		char *resposne = buf;
	// 		if (strcmp(resposne, "NULLS") == 0)
	// 		{
	// 			printf("%s\n", resposne);
	// 			break;
	// 		}
	// 		else
	// 		{
	// 			unsigned long long rs = pwrite(fd_write, buf, len, offset_pos);
	// 			offset_pos += rs;
	// 		}
	// 	}
	// }
	// close(fd_write);
	// printf("\n Receiving file successful \n");

	/* receiving .txt file over network with session key */
	len = recvfrom(sfd, buf, 1024, 0, 0, 0);
	// printf("len: %d\n", len);
	// for(int i=0;i<8;i++)
	// {
	// 	printf("%hhu ",buf[i]);
	// }
	// printf("\n");
	prev_time_file = *((unsigned long*)buf);
	
	printf("\n ****************************************** Receiving file over network ****************************************** \n");
	// buf[1024];
	// hash[32];
	bzero(hash, 32);
	bzero(dec_key, 32);
	sha256(SKap_bytes, 128, hash);
	memcpy(dec_key, hash, 32);
	unsigned long long offset_pos = 0;
	unsigned long long r;
	int fd_write;
	char *destn_loc = "ABC.txt";
	// char *destn_loc = "ABC.pdf";
	fd_write = open(destn_loc, O_CREAT | O_WRONLY, 0777);
	if (fd_write == -1)
	{
		// msg("Error Occured opening file");
	}
	while (1)
	{
		bzero(buf, 1024);
		bzero(dec_buf, 1024);
		int len = recvfrom(sfd, dec_buf, 1024, 0, 0, 0);
		// printf("length: %d\n", len);
		decrypt_aes(dec_buf, len, buf, dec_key); // decrypting the text buffer buf with key enc_key
		int updated_length = 0;
		for(int i=0; i<len; i++)
		{
			if(buf[i] == '\0')
			{
				break;
			}
			else
			{
				updated_length++;
			}
		}
		// printf("updated length: %d\n", updated_length);
		len = updated_length;
		if (len < 0)
		{
			printf("Receiving failed\n");
			break;
		}
		else if (len == 0)
		{
			printf("Time to leave\n");
			break;
		}
		else if (len > 0)
		{
			char *resposne = buf;
			// printf("received data = %s\n\n", buf);
			// if (strcmp(resposne, "NULLSNULLSNULLS") == 0|| (resposne == "" )|| (resposne == "\n" )|| (resposne == " " ))
			if (strcmp(resposne, "NULLSNULLSNULLS") == 0)
			
			{
				// printf("%s\n", resposne);
				break;
			}
			else
			{
				unsigned long long rs = pwrite(fd_write, buf, len, offset_pos);
				offset_pos += rs;
			}
		}
	}
	close(fd_write);
	printf("\n ******************************* Receiving file successful ****************************** \n\n");

	gettimeofday(&now, NULL);
	pres_time_file = now.tv_sec * 1000000 + now.tv_usec;
	printf("File time before send: %lu\n", prev_time_file);
	printf("File time after send: %lu\n", pres_time_file);
	printf("Total Time for file transfer is %d microseconds\n", (pres_time_file - prev_time_file));


	/*element_clear(P);
	element_clear(Snm);
	element_clear(Gnm);
	element_clear(Qnm);
	element_clear(g);
	element_clear(Xc);
	element_clear(h1);
	element_clear(h1P);
	element_clear(h1PplusQnm);
	element_clear(T1);
	element_clear(K1);
	element_clear(h1plusSnm);
	element_clear(Invh1plusSnm);
	element_clear(Kap);
	element_clear(K2);*/

	pairing_clear(pairing);
	return 0;
}

void sha256(unsigned char *msg, int len, unsigned char *buf)
{

	// BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, msg, len);
	sha256_final(&ctx, buf);

	/*printf("\nHash is:");
	for(int i=0;i<32;i++)
	  {
		printf("%hhu ",buf[i]);
	   }*/
}

void decrypt_aes(unsigned char *cipher_text, int len, unsigned char *plain_text, unsigned char *key)
{
	WORD key_schedule[60];
	BYTE enc_buf[128];

	BYTE iv[1][16] = {
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};

	// printf("* CBC mode:\n");
	aes_key_setup(key, key_schedule, 256);

	// printf(  "Key          : ");
	// print_hex(key[0], 32);
	// printf("\nIV           : ");
	// print_hex(iv[0], 16);
	/*printf("\nOriginal message is:");

for(int i=0;i<len;i++)
	printf("%hhu ",plain_text[i]);

aes_encrypt_cbc(plain_text, len , cipher_text, key_schedule, 256, iv[0]);

	*/

	/*printf("\nEncrypted message is:");

for(int i=0;i<len;i++)
	printf("%hhu ",cipher_text[i]);*/

	aes_decrypt_cbc(cipher_text, len, plain_text, key_schedule, 256, iv[0]);
	/*printf("\nOriginal message is:");

	for(int i=0;i<len;i++)
		printf("%hhu ",plain_text[i]);*/

	printf("\n");
}
