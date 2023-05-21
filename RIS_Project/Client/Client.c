/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cpplite/CTemplate.c to edit this template
 */

// gcc Client.c -o Client -L. -lpbc -lgmp -lcbor
// ./Client <../a.param
// ./Client <~/Desktop/ris/pbc-0.5.14/param/a.param

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
#include <stdlib.h>
#include <cbor.h>
#include "aes.h"
#include "aes.c"
#include "sha256.h"
#include "sha256.c"
#define min(a, b) a < b ? a : b

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
	unsigned long time1, time2, pres_time, prev_time, pres_time_m1, prev_time_m1, pres_time_m3, prev_time_m3;
	unsigned long prev_time_file;
	
	pbc_demo_pairing_init(pairing, argc, argv);

	int sfd, len;
	struct sockaddr_in client_address, nm_address, ap_address;
	unsigned char buf[1024];
	unsigned char temp_buf[1024];

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

	if (bind(sfd, (struct sockaddr *)&client_address,
			 sizeof(client_address)) < 0)
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
	element_printf("Sc is %B\n\n", Sc);

	element_init_GT(Gc, pairing);
	element_from_bytes(Gc, buf + 552);
	element_printf("Gc is %B\n\n", Gc);

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

	/********Client C Authentication message generation********************/
	printf("\n******************* Message m1 generation phase ******************* \n");
	gettimeofday(&now, NULL);
	prev_time_m1 = now.tv_sec * 1000000 + now.tv_usec;
	element_init_Zr(Xc, pairing);
	element_random(Xc);
	element_printf("system parameter Xc = %B\n\n", Xc);

	element_init_Zr(h1, pairing);
	element_from_hash(h1, "ID(AP)", 7);
	element_printf("system parameter h1 = %B\n\n", h1);

	element_init_G1(h1P, pairing);
	element_mul_zn(h1P, P, h1);
	element_printf("system parameter  h1P= %B\n\n", h1P);

	element_init_G1(h1PplusQnm, pairing);
	element_add(h1PplusQnm, h1P, Qnm);
	element_printf("system parameter  h1PplusQnm= %B\n\n", h1PplusQnm);

	element_init_G1(T1, pairing);
	element_mul_zn(T1, h1PplusQnm, Xc);
	element_printf("system parameter T1 = %B\n\n", T1);

	element_init_GT(K1, pairing);
	element_pow_zn(K1, g, Xc);
	element_printf("system parameter K1 = %B\n\n", K1);

	/***********Encryption , hashing and sending over socket***********/
	// printf("Sizeof element_t T1 is %d\n",element_length_in_bytes(T1));

	unsigned char T1_bytes[128];
	unsigned char C1_bytes[128];
	unsigned char Gc_bytes[128];
	unsigned char K1_bytes[128];
	unsigned char hash[32];
	unsigned char enc_key[32];
	unsigned char enc_buf[1024];
	unsigned char T1Gc[1024];
	unsigned char Auth1[32];
	unsigned char temp[128];
	unsigned char Y2SKc[1024];
	unsigned char SKcK1[1024];
	unsigned char Y2_bytes[128];
	unsigned char SKc_bytes[128];

	element_to_bytes(T1_bytes, T1);
	memcpy(buf, T1_bytes, element_length_in_bytes(T1));

	element_to_bytes(K1_bytes, K1);
	sha256(K1_bytes, 128, hash);
	memcpy(enc_key, hash, 32);
	// printf("Sizeof element_t Gc is %d\n",element_length_in_bytes(Gc));
	element_printf("\nGc is %B", Gc);
	element_to_bytes(Gc_bytes, Gc);
	gettimeofday(&now, NULL);
	prev_time = now.tv_sec * 1000000 + now.tv_usec;
	encrypt_aes(Gc_bytes, 128, enc_buf, enc_key);
	gettimeofday(&now, NULL);
	pres_time = now.tv_sec * 1000000 + now.tv_usec;
	printf("\n >>>>>>>>>>> Time calculation for encryption and hashing <<<<<<<<<<<<<<<< \n");
	printf("\nTime for encryption (AES-256) computation time is %d microseconds\n", (pres_time - prev_time));

	memcpy(buf + 128, enc_buf, element_length_in_bytes(Gc));

	memcpy(T1Gc, T1_bytes, 128);
	memcpy(T1Gc + 128, Gc_bytes, 128);
	memcpy(T1Gc + 256, K1_bytes, 128);
	gettimeofday(&now, NULL);
	prev_time = now.tv_sec * 1000000 + now.tv_usec;
	sha256(T1Gc, 384, hash);
	memcpy(buf + 256, hash, 32);
	gettimeofday(&now, NULL);
	pres_time = now.tv_sec * 1000000 + now.tv_usec;
	printf("Time for SHA-256 computation time is %d microseconds\n", (pres_time - prev_time));

	/*printf("\nT1Gc is\n");
	for(int i=0;i<256;i++)
	printf("%hhu ",T1Gc[i]);*/

	// element_to_bytes(temp,C1);
	// memcpy(buf+element_length_in_bytes(T1),temp,element_length_in_bytes(Cs1));
	// memcpy(buf+sizeof(element_t),(unsigned char*)&T1,sizeof(element_t));
	// for(int i=0;i<288;i++)
	// printf("%hhu ",buf[i]);

	/* Preallocate the map structure CBOR */
	cbor_item_t * root = cbor_new_definite_map(1);

	/* Add the content */
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("1")),
		.value = cbor_move(cbor_build_bytestring(buf, 288))
	});
	
	/* Output: `length` bytes of data in the `buffer` */
	unsigned char * buffer;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

	// printf("\nbuffer_size: %lu \n", buffer_size);
	// printf("\nlength: %lu \n", length);

	// for(int i=0;i<294;i++)
	// printf("%hhu ",buffer[i]);

	gettimeofday(&now, NULL);
	pres_time_m1 = now.tv_sec * 1000000 + now.tv_usec;
	printf("\nTime for message m1 generation is %d microseconds\n", (pres_time_m1 - prev_time_m1));


	// if (sendto(sfd, buf, 288, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	if (sendto(sfd, buffer, 294, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	{
		printf("\n[-] Sendto failed for m1\n");
	}
	else
	{
		printf("\n[+] Sendto successful for m1\n");
	}

	/*************************END Encryption , hashing and sending over socket***************/

	printf("\n****************************************** Waiting for message from AP ****************************************** \n");
	// len = recvfrom(sfd, buf, 1024, 0, 0, 0);
	len = recvfrom(sfd, temp_buf, 1024, 0, 0, 0);
	memcpy(buf, temp_buf+5, 168);
	memcpy((unsigned char *)&time2, buf + 160, 8);
	// printf("\ntime2 is %lu",time2);
	gettimeofday(&now, NULL);
	time1 = now.tv_sec * 1000000 + now.tv_usec;
	printf("\nCommunication delay over network is %lu microseconds\n", time1 - time2);
	printf("\nReceived Authentication message from AP of size %d\n", len);
	element_init_GT(Y2, pairing);
	element_from_bytes(Y2, buf);
	element_printf("\nsystem parameter Y2 = %B\n", Y2);

	/**************Phase-2 Authentication i.e. Message m2 Generation********************/
	printf("\n******************* Message m2 verification phase ******************* \n");
	element_init_Zr(XcPlusSc, pairing);
	element_add(XcPlusSc, Xc, Sc);
	element_printf("\nsystem parameter XcPlusSc = %B\n", XcPlusSc);

	/*element_init_Zr(InvSc, pairing);
	element_invert(InvSc,Sc);
	element_printf("system parameter InvSc = %B\n", InvSc);*/

	element_init_Zr(XcPlusScDivSc, pairing);
	element_div(XcPlusScDivSc, XcPlusSc, Sc);
	element_printf("\nsystem parameter XcPlusScDivSc = %B\n", XcPlusScDivSc);

	element_init_GT(SKc, pairing);
	element_pow_zn(SKc, Y2, XcPlusScDivSc);
	element_printf("\nsystem parameter SKc = %B\n", SKc);

	element_to_bytes(Y2_bytes, Y2);
	element_to_bytes(SKc_bytes, SKc);
	element_to_bytes(Gc_bytes, Gc);
	element_to_bytes(T1_bytes, T1);
	element_to_bytes(K1_bytes, K1);

	memcpy(Y2SKc, Y2_bytes, 128);
	memcpy(Y2SKc + 128, SKc_bytes, 128);
	memcpy(Y2SKc + 256, Gc_bytes, 128);
	memcpy(Y2SKc + 384, T1_bytes, 128);
	memcpy(Y2SKc + 512, K1_bytes, 128);

	/*printf("\nY2SKc is");
	for(int i=0;i<640;i++)
	{
	  if(i%128==0)
	  printf("\n");
	  printf("%hhu ",Y2SKc[i]);
	}*/

	gettimeofday(&now, NULL);
	prev_time = now.tv_sec * 1000000 + now.tv_usec;
	sha256(Y2SKc, 640, hash);
	gettimeofday(&now, NULL);
	pres_time = now.tv_sec * 1000000 + now.tv_usec;
	printf("Time for SHA-256 computation time is %d microseconds\n", (pres_time - prev_time));

	if (memcmp(hash, buf + 128, 32) == 0)
		printf("\n[+] Authentication of message m2 verified!!!!!!\n");
	else
		printf("\n[-] Authentication of message m2 failed????????\n");

	printf("\n******************* Message m3 generation phase ******************* \n");
	gettimeofday(&now, NULL);
	prev_time_m3 = now.tv_sec * 1000000 + now.tv_usec;

	printf("\n >>>>>>>>>>> Time calculation for encryption and hashing <<<<<<<<<<<<<<<< \n");
	printf("\nTime for encryption (AES-256) computation time is %d microseconds\n", (pres_time - prev_time));

	memcpy(SKcK1, SKc_bytes, 128);
	memcpy(SKcK1 + 128, K1_bytes, 128);
	memcpy(SKcK1 + 256, Y2_bytes, 128);
	gettimeofday(&now, NULL);
	prev_time = now.tv_sec * 1000000 + now.tv_usec;
	sha256(SKcK1, 384, hash);
	memcpy(buf, hash, 32);
	gettimeofday(&now, NULL);
	pres_time = now.tv_sec * 1000000 + now.tv_usec;
	printf("Time for SHA-256 computation time is %d microseconds\n", (pres_time - prev_time));

	for(int i=0;i<32;i++)
	printf("%hhu ",buf[i]);
	printf("\n");

	/* Preallocate the map structure CBOR */
	cbor_item_t * root2 = cbor_new_definite_map(1);

	/* Add the content */
	cbor_map_add(root2, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("2")),
		.value = cbor_move(cbor_build_bytestring(buf, 32))
	});
	
	/* Output: `length` bytes of data in the `buffer` */
	unsigned char * buffer2;
	size_t buffer_size2, length2 = cbor_serialize_alloc(root2, &buffer2, &buffer_size2);

	// printf("\nbuffer_size: %lu \n", buffer_size2);
	// printf("length: %lu \n\n", length2);

	// for(int i=0;i<37;i++)
	// printf("%hhu ",buffer2[i]);
	// printf("\n\n");

	gettimeofday(&now, NULL);
	pres_time_m3 = now.tv_sec * 1000000 + now.tv_usec;

	printf("Time for m3 generation is %d microseconds\n", (pres_time_m3 - prev_time_m3));

	printf("Time for session key generation (m1 + m2 + m3) is %d microseconds\n", (pres_time_m3 - prev_time_m1));

	// if (sendto(sfd, buf, 32, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	if (sendto(sfd, buffer2, 37, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	{
		printf("[-] Sendto failed for m3\n");
	}
	else
	{
		printf("[+] Sendto successful for m3\n");
	}

	/* Sending .txt file over network */
	// printf("\n****************************************** Sending file over network ****************************************** \n");
	// // buf[1024];
	// bzero(buf, 1024);
	// int fd_read;
	// unsigned long long offset_pos = 0;
	// char *fileName = "ABC.txt";
	// // char *fileName = "ABC.pdf";
	// fd_read = open(fileName, O_RDONLY);
	// if ((fd_read != -1))
	// {
	// 	while (1)
	// 	{
	// 		bzero(buf, 1024);
	// 		unsigned long long r = pread(fd_read, buf, 1 * 1024, offset_pos);
	// 		if (r <= 0)
	// 		{
	// 			break;
	// 		}
	// 		int k = min(r, 1024);
	// 		if (sendto(sfd, buf, k, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	// 		{
	// 			printf("Sendto failed\n");
	// 		}
	// 		offset_pos += r;
	// 	}
	// 	close(fd_read);
	// }
	// char *eofSignal = "NULLS";
	// strcpy(buf, eofSignal);
	// if (0 > sendto(sfd, buf, 6, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	// {
	// 	printf("last write (NULLS) failed\n");
	// }
	// printf("Sending file successful\n");

	/* Sending .txt file over network with session key*/
	printf("\n****************************************** Sending file over network ****************************************** \n");
	gettimeofday(&now, NULL);
	prev_time_file = now.tv_sec * 1000000 + now.tv_usec;
	printf("File time before send: %lu\n", prev_time_file);
	bzero(buf, 1024);
	memcpy(buf, (unsigned char*)&prev_time_file, 8);

	// for(int i=0;i<8;i++)
	// {
	// 	printf("%hhu ",buf[i]);
	// }
	// printf("\n");

	if (sendto(sfd, buf, 8, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	{
		printf("[-] Sendto failed for file time\n");
	}
	else
	{
		printf("[+] Sendto successful for file time\n");
	}

	// buf[1024];
	// hash[32];
	bzero(hash, 32);
	bzero(enc_key, 32);
	sha256(SKc_bytes, 128, hash);
	memcpy(enc_key, hash, 32);
	bzero(buf, 1024);
	int fd_read;
	unsigned long long offset_pos = 0;
	char *fileName = "ABC.txt";
	// char *fileName = "ABC.pdf";
	fd_read = open(fileName, O_RDONLY);
	if ((fd_read != -1))
	{
		while (1)
		{
			bzero(buf, 1024);
			unsigned long long r = pread(fd_read, buf, 1 * 1024, offset_pos);
			if (r <= 0)
			{
				break;
			}
			int k = min(r, 1024);
			// printf("length: %d\n", k);
			if(k%16 != 0) // make it nearest multiple of 16 bcoz aes block siz is 16
			{
				k = ((k/16)+1)*16;
			}
			// printf("updated length: %d\n", k);
			bzero(enc_buf, 1024);
			encrypt_aes(buf, k, enc_buf, enc_key); // encrypting the text buffer buf with key enc_key
			// if (sendto(sfd, buf, k, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
			// {
			// 	printf("Sendto failed\n");
			// }
			if (sendto(sfd, enc_buf, k, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
			{
				printf("Sendto failed\n");
			}
			else
			{
				// printf("sent data = %s\n", buf);
			}
			offset_pos += r;
		}
		close(fd_read);
	}

	bzero(buf, 1024);
	char *eofSignal = "NULLSNULLSNULLS";
	strcpy(buf, eofSignal);
	bzero(enc_buf, 1024);
	encrypt_aes(buf, 16, enc_buf, enc_key); // encrypting the text buffer buf with key enc_key
	if (0 > sendto(sfd, enc_buf, 16, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	{
		printf("last write (NULLS) failed\n");
	}
	else
	{
		// printf("sent data = %s\n", buf);
	}
	printf("Sending file successful\n");

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

void encrypt_aes(unsigned char *plain_text, int len, unsigned char *cipher_text, unsigned char *key)
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
	printf("%hhu ",plain_text[i]);*/

	aes_encrypt_cbc(plain_text, len, cipher_text, key_schedule, 256, iv[0]);

	/*printf("\nEncrypted message is:");

for(int i=0;i<len;i++)
	printf("%hhu ",cipher_text[i]);*/

	/*aes_decrypt_cbc(cipher_text, len, enc_buf, key_schedule, 256, iv[0]);
printf("\nOriginal message is:");

for(int i=0;i<len;i++)
	printf("%hhu ",enc_buf[i]);*/

	printf("\n");
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

	printf("\nEncrypted message is:");

	for (int i = 0; i < len; i++)
		printf("%hhu ", cipher_text[i]);

	aes_decrypt_cbc(cipher_text, len, plain_text, key_schedule, 256, iv[0]);
	printf("\nOriginal message is:");

	for (int i = 0; i < len; i++)
		printf("%hhu ", plain_text[i]);

	printf("\n");
}