// gcc Client.c -o Client -L. -lpbc -lgmp -lcbor
// ./Client <../a.param
// ./Client <~/Desktop/ris/pbc-0.5.14/param/a.param

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
#define min(a, b) a < b ? a : b

#define CLIENT_PORT 50000
#define NM_PORT 40000
#define AP_PORT 60000

int main(int argc, char **argv)
{
    int sfd, len;
    struct sockaddr_in client_address, nm_address, ap_address;
	unsigned char buf[32];
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

	if (bind(sfd, (struct sockaddr *)&client_address,
			 sizeof(client_address)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

    printf("\n****************************************** Sending file over network ****************************************** \n");
	// buf[1024];
	bzero(buf, 32);
	int fd_read;
	unsigned long long offset_pos = 0;
	char *fileName = "ABC.txt";

	fd_read = open(fileName, O_RDONLY);
	if ((fd_read != -1))
	{
		while (1)
		{
			bzero(buf, 32);
			unsigned long long r = pread(fd_read, buf, 1 * 32, offset_pos);
			if (r <= 0)
			{
				break;
			}
			int k = min(r, 32);

			for(int i=0; i<k; i++)
			{
				printf("%hhu ", buf[i]);
			}
			printf("\n");

			printf("Before cbor effective buffer size: %d\n", k);

			/* Preallocate the map structure CBOR */
			cbor_item_t * root = cbor_new_definite_map(1);

			/* Add the content */
			cbor_map_add(root, (struct cbor_pair) {
				.key = cbor_move(cbor_build_string("1")),
				.value = cbor_move(cbor_build_bytestring(buf, k))
			});
			
			/* Output: `length` bytes of data in the `buffer` */
			unsigned char * buffer;
			size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

			for(int i=0; i<length; i++)
			{
				printf("%hhu ", buffer[i]);
			}
			printf("\n");

			// printf("\nbuffer_size: %lu \n", buffer_size);
			printf("After cbor effective buffer size: %lu\n", length);
			printf("Extra header size: %d\n\n", (int)(length)-k);

			size_t c_l = (length - (size_t)(k));
			bzero(temp_buf, 32);
			memcpy(temp_buf, (unsigned char*)&(c_l), 8);
			if (sendto(sfd, temp_buf, length, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
			{
				printf("Sendto of compressed length failed\n");
			}

			// for(int i=0;i<294;i++)
			// printf("%hhu ",buffer[i]);

			// if (sendto(sfd, buf, k, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
			if (sendto(sfd, buffer, length, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
			{
				printf("Sendto of data failed\n");
			}
			offset_pos += r;
		}
		close(fd_read);
	}

	char *eofSignal = "NULLS";
	strcpy(buf, eofSignal);

	/* Preallocate the map structure CBOR */
	cbor_item_t * root = cbor_new_definite_map(1);

	/* Add the content */
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("1")),
		.value = cbor_move(cbor_build_bytestring(buf, 6))
	});
	
	/* Output: `length` bytes of data in the `buffer` */
	unsigned char * buffer;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

	// printf("Before cbor effective buffer size: 6\n");
	// // printf("\nbuffer_size: %lu \n", buffer_size);
	// printf("After cbor effective buffer size: %lu\n", length);
	// printf("Extra header size: %d\n\n", (int)(length)-6);

	printf("Before cbor effective buffer size: \n", length);
	// printf("\nbuffer_size: %lu \n", buffer_size);
	printf("After cbor effective buffer size: %lu\n", length);
	printf("Extra header size: %d\n\n", (int)(length)-6);
	
	size_t c_l = (length - (size_t)(6));
	bzero(temp_buf, 32);
	memcpy(temp_buf, (unsigned char*)&(c_l), 8);
	if (sendto(sfd, temp_buf, length, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	{
		printf("Sendto of compressed length failed\n");
	}

	if (0 > sendto(sfd, buffer, length, 0, (struct sockaddr *)&ap_address, sizeof(ap_address)) == -1)
	{
		printf("last write (NULLS) failed\n");
	}
	printf("**************************************** Sending file successful ****************************************\n");

	// element_to_bytes(temp,C1);
	// memcpy(buf+element_length_in_bytes(T1),temp,element_length_in_bytes(Cs1));
	// memcpy(buf+sizeof(element_t),(unsigned char*)&T1,sizeof(element_t));
	// for(int i=0;i<288;i++)
	// printf("%hhu ",buf[i]);
}