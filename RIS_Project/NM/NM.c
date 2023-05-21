/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/cpplite/CTemplate.c to edit this template
 */

// gcc NM.c -o NM -L. -lpbc -lgmp
// ./NM <../a.param
// ./NM <~/Desktop/ris/pbc-0.5.14/param/a.param

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
#include <cbor.h>
#define CLIENT_PORT 50000
#define NM_PORT 40000
#define AP_PORT 60000

struct m
{
};
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

	int sfd, len;
	struct sockaddr_in client_address, nm_address, ap_address;
	unsigned char buf[1024];

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

	if (bind(sfd, (struct sockaddr *)&nm_address,
			 sizeof(nm_address)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	pairing_t pairing;
	element_t g, h;
	element_t public_key, sig;
	element_t secret_key;
	element_t temp1, temp2;

	element_t P, q, Gnm, Snm, Qnm, Sap, Kap, Rc, Sc, Gc, Hc, x, Xc, T1, t1, h1, h1P, h1PplusQnm, Xch1PplusQnm, K1, K2, h1plusSnm, Xch1plusSnm, PXch1plusSnm, XcP, Invh1plusSnm, Yap, Y1, Y2,
		SnmHc, YapPlusSap, SKap, Y1K2, XcPlusSc, XcPlusScDivSc, SKc, InvSc;
	// element_t G1 , G2 , q, e, P,Qnm , gnm g, h1 , h2 , omega;

	int IDap = 100, IDc = 200;

	pbc_demo_pairing_init(pairing, argc, argv);

	printf(" ****************************************** Pairing based Authentication test ****************************************** \n\n");
	/***************Authentication*******************************/

	/********NM Parameter generation********************/
	printf(" ****************************************** NM Parameter generation ****************************************** \n\n");
	element_init_G1(P, pairing);
	element_random(P);
	element_printf("system parameter P = %B\n\n", P);

	element_init_GT(g, pairing);
	element_pairing(g, P, P);
	element_printf("system parameter g = %B\n\n", g);

	element_init_Zr(Snm, pairing);
	element_random(Snm);
	element_printf("system parameter Snm = %B\n\n", Snm);

	element_init_G1(Qnm, pairing);
	element_mul_zn(Qnm, P, Snm);
	element_printf("system parameter  Qnm= %B\n\n", Qnm);

	element_init_GT(Gnm, pairing);
	element_pow_zn(Gnm, g, Snm);
	element_printf("system parameter Gnm = %B\n\n\n", Gnm);

	/*******************Additional NM Parameter******************/
	printf(" ****************************************** Additional NM Parameter generation ****************************************** \n\n");
	element_init_Zr(Rc, pairing);
	element_random(Rc);
	element_printf("system parameter Rc = %B\n\n", Rc);

	element_init_GT(Gc, pairing);
	element_pow_zn(Gc, g, Rc);
	element_printf("system parameter Gc = %B\n\n", Gc);

	element_init_Zr(Hc, pairing);
	element_from_hash(Hc, "gc, Rightc, Qnm", 16);
	element_printf("system parameter Hc = %B\n\n", Hc);

	element_init_Zr(SnmHc, pairing);
	element_mul_zn(SnmHc, Snm, Hc);
	element_printf("system parameter SnmHc= %B\n\n", SnmHc);

	element_init_Zr(Sc, pairing);
	element_add(Sc, Rc, SnmHc);
	element_printf("system parameter Sc= %B\n\n", Sc);

	/*****************End Additional NM Parameter************************/

	/********End NM Parameter generation********************/

	unsigned char P_bytes[128];
	unsigned char Snm_bytes[128];
	unsigned char Qnm_bytes[128];
	unsigned char g_bytes[128];
	unsigned char Gnm_bytes[128];
	unsigned char Sc_bytes[128];
	unsigned char Gc_bytes[128];

	element_to_bytes(P_bytes, P);
	element_to_bytes(Snm_bytes, Snm);
	element_to_bytes(Qnm_bytes, Qnm);
	element_to_bytes(g_bytes, g);
	element_to_bytes(Gnm_bytes, Gnm);
	element_to_bytes(Sc_bytes, Sc);
	element_to_bytes(Gc_bytes, Gc);

	printf("\n****************************************** Size of the NM parameters ******************************************\n");
	printf("\nSize of P is %d", element_length_in_bytes(P));
	printf("\nSize of Snm is %d", element_length_in_bytes(Snm));
	printf("\nSize of Qnm is %d", element_length_in_bytes(Qnm));
	printf("\nSize of g is %d", element_length_in_bytes(g));
	printf("\nSize of Gnm is %d", element_length_in_bytes(Gnm));
	printf("\nSize of Sc is %d", element_length_in_bytes(Sc));
	printf("\nSize of Gc is %d\n", element_length_in_bytes(Gc));

	memcpy(buf, P_bytes, 128);
	memcpy(buf + 128, Snm_bytes, 20);
	memcpy(buf + 148, Qnm_bytes, 128);
	memcpy(buf + 276, g_bytes, 128);
	memcpy(buf + 404, Gnm_bytes, 128);
	memcpy(buf + 532, Sc_bytes, 20);
	memcpy(buf + 552, Gc_bytes, 128);

	printf("\n****************************************** Sending NM parameters to Client and AP ******************************************\n");
				
	if (sendto(sfd, buf, 680, 0, (struct sockaddr *)&client_address, sizeof(client_address)) == -1)
	{
		printf("\n[-] Sendto Client failed\n");
	}
	else
	{
		printf("\n[+] Sendto Client successful\n");
	}
	if (sendto(sfd, buf, 680, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	{
		printf("[-] Sendto AP failed\n");
	}
	else
	{
		printf("[+] Sendto AP successful\n\n");
	}

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
