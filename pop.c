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

void
pop(int size, const u_char* packet, int taille_du_paquet, int verbo) {

	printf("\n\n------------ POP/TLSv1.2 ------------\n\n");
	printf("/* Si les données affichées ne sont pas lisibles alors ");
	printf("on est probablement dans le protocole TLSv1.2 */\n\n");

	int i=1;
	int p=1;
	while ( size < taille_du_paquet) {
		if ( (int)(packet+size)[0]>31 && (int)(packet+size)[0]<127) {
			putchar((packet + size)[0]);
		}
		else if ( (int)(packet+size)[0] == 13 ||
		    (int)(packet+size)[0] == 10 ||
			  (int)(packet+size)[0] == 11 ) {
					putchar((packet+size)[0]);

		} else {
			putchar('.'); //--> caractères spécieaux
		}
		size ++;
	}
	printf("\n\n");
	printf("taille_du_paquet : %i\n", taille_du_paquet);
}

void
test_pop( int source_port,
					 int destination_port,
	 				 int size,
					 const u_char *packet,
           int taille_du_paquet,
				   int verbo) {

    if ((source_port == 110 || destination_port == 110) ) {
  		pop(size, packet, taille_du_paquet, verbo);
    }
}
