
// gcc AP.c -o AP -L. -lpbc -lgmp -lcbor
// ./AP <../a.param
// ./AP <~/Desktop/ris/pbc-0.5.14/param/a.param

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

#define CLIENT_PORT 50000
#define NM_PORT 40000
#define AP_PORT 60000


int main(int argc, char **argv)
{
    int sfd, len;
	struct sockaddr_in client_address, nm_address, ap_address;
    unsigned char buf[64];
	unsigned char buffer[64];
	unsigned char temp_buf[32];

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

    /* receiving .txt file over network */
	printf("\n****************************************** Receiving file over network ****************************************** \n");
	unsigned long long offset_pos = 0;
	unsigned long long r;
	int fd_write;
	char *destn_loc = "ABC.txt";

	fd_write = open(destn_loc, O_CREAT | O_WRONLY, 0777);
	if (fd_write == -1)
	{
		// msg("Error Occured opening file");
	}
	while (1)
	{
		bzero(temp_buf, 32);
		int len2 = recvfrom(sfd, temp_buf, 32, 0, 0, 0);
		if (len2 < 0)
		{
			break;
		}
		size_t c_l = *((unsigned long*)temp_buf);
		// printf("header length: %lu\n", c_l);
	

		bzero(buffer, 64);
		int len3 = recvfrom(sfd, buffer, 64, 0, 0, 0);
		// printf("total_length: %d\n", len3);
		// printf("actual_length: %d\n\n", len3-(int)(c_l));
		// int len = recv(network_socket, b, MESSAGELEN, 0);
		if (len3 < 0)
		{
			printf("Receiving failed\n");
			break;
		}
		else if (len3 == 0)
		{
			printf("Time to leave\n");
			break;
		}
		else if (len3 > 0)
		{
			memcpy(buf, buffer+c_l, (len3-c_l));
			char *resposne = buf;

			// printf("%s\n", resposne);

			if (strcmp(resposne, "NULLS") == 0)
			{
				printf("%s\n", resposne);
				break;
			}
			else
			{
				// printf("writing response: %s\n", resposne);
				unsigned long long rs = pwrite(fd_write, buf, (len3-c_l), offset_pos);
				offset_pos += rs;
			}
		}
	}
	close(fd_write);
	printf("\n**************************************** Receiving file successful ****************************************\n");

}