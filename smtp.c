#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void test_smtp(int, int, int, const u_char*, int, int);
void smtp(int, const u_char*, int, int);

void
test_smtp(int source_port,
					  int destination_port,
	 					int size,
						const u_char *packet,
            int taille_du_paquet,
					  int verbo) {

    if ((source_port == 25 || destination_port == 25) ) {
  		smtp(size, packet, taille_du_paquet, verbo);
    }
}


void
smtp(int size, const u_char* packet, int taille_du_paquet, int verbo) {

  printf("\n\n--------------- SMTP ----------------\n\n");
	printf("/* Les points représentent des caractères spéciaux (ou des points) */\n\n");

	while ( size < taille_du_paquet) {
		if ( (int)(packet+size)[0]>31 && (int)(packet+size)[0]<127) {
			putchar((packet + size)[0]);
		}
		else if( (int)(packet+size)[0] == 13 ||
				(int)(packet+size)[0] == 10 ||
				(int)(packet+size)[0] == 11 ) {
					putchar((packet+size)[0]);

		} else {
			putchar('.');
		}
		size ++;
	}
	printf("\n\n");

  printf("     Taille total du paquet: %i\n", taille_du_paquet);

}
