#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>

void
ftp(int size, const u_char* packet, int taille_du_paquet, int verbo) {

	printf("\n\n--------------- FTP ---------------\n\n");
	printf("/* Les points représentent des caractères spéciaux */\n\n");

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
test_ftp( int source_port,
					 int destination_port,
	 				 int size,
					 const u_char *packet,
           int taille_du_paquet,
				   int verbo) {

    if (((source_port == 21 || destination_port == 20)
			&& (destination_port == 21 || destination_port == 20)) ) {
  		ftp(size, packet, taille_du_paquet, verbo);
    }
}
