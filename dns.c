#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include "dns.h"

void test_dns(int, int, int, const u_char*,int, int);
void dns(int, const u_char*,int, int);

/* fonction qui teste les ports et appelle la fonction dns*/
void
test_dns( int source_port,
					  int destination_port,
	 					int size,
						const u_char *packet,
						int taille_du_paquet,
					  int verbo) {

	if ((source_port == 53 || destination_port == 53) ) {
		dns(size, packet, taille_du_paquet, verbo);
	}
}

/* fonction qui affiche les informations du protocole dsn */
void
dns(int size, const u_char * packet, int taille_du_paquet, int verbo) {
	printf("\n\n---------------- DNS -----------------\n\n");
	struct sock_dns_hdr_t *dns;
	dns = (struct sock_dns_hdr_t*)(packet + size);
	printf("      Transaction ID: 0x%.2x\n", ntohs(dns->id));
	if (verbo != 2) {
		printf("    > Flags: 0x%.2x\n", ntohs(dns->flags));
		printf("      Questions: %i\n", ntohs(dns->qdcount));
		printf("      Answers RRs: %i\n", ntohs(dns->ancount));
		printf("      Authority RRs: %i\n", ntohs(dns->nscount));
		printf("      Additionnal RRs: %i\n", ntohs(dns->nscount));

		int p=0;
		int i=0;
		while(i <= (int)(ntohs(dns->qdcount)) ) {
			i++;
			printf("    > Queries\n");
			printf("        Name: ");

			/* tant qu'on n'atteind pas le nombre de questions */
			while ((int)(dns->payload[p]) != 0 && p<(taille_du_paquet - size)) {

				if ( (int)(dns->payload[p])>31 && (int)(dns->payload[p])<127) {
					putchar(dns->payload[p]);
				}
				else if ( (int)(dns->payload[p]) == 13 ||
				(int)(dns->payload[p]) == 10 ||
				(int)(dns->payload[p]) == 11 ) {
					putchar(dns->payload[p]);

				} else {
					putchar('.');
				}
				p++;
			}
			p++;
			printf("\n");
			printf("        Type: 0x");
			for (int h = p; h<p+2; h++) {
				printf("%.2x", dns->payload[h]);
			}
			printf("\n");
			p+=2;
			printf("        Class: 0x");
			for (int h = p; h<p+2; h++) {
				printf("%.2x", dns->payload[h]);
			}
			printf("\n");
			p+=2;
			i++;
		}

		i=0;
		/* tant qu'on atteind pas le nombre de reponse */
		while(i != (int)(ntohs(dns->ancount)) ) {
			i++;
			printf("    > Answers\n");
			printf("        Name: ");

			/* quand on a c00c il faut le reprendre le nom de la dernière section */
			if((int)(dns->payload[p]) == 0xc0 && (int)(dns->payload[p+1] == 0x0c)) {
				printf(" 0xc00c  (same name than the last one)\n");
				p += 2;
				printf("        Type: 0x");
				for (int h = p; h<p+2; h++) {
					printf("%.2x", dns->payload[h]);
				}
				p += 2;
				printf("\n");
				printf("        Class: 0x");
				for (int h = p; h<p+2; h++) {
					printf("%.2x", dns->payload[h]);
				}
				p += 2;
				printf("\n");
			}

			else {  //sinon on continu
				while ((int)(dns->payload[p]) != 0 && p<(taille_du_paquet - size)) {

					if ( (int)(dns->payload[p])>31 && (int)(dns->payload[p])<127) {
						putchar((dns->payload[p]));
					}
					else if ( (int)(dns->payload[p]) == 13 ||
					(int)(dns->payload[p]) == 10 ||
					(int)(dns->payload[p]) == 11 ) {
						putchar((packet+size)[0]);

					} else {
						putchar('.');
					}
					p++;
				}
				p++;
				printf("\n");
				printf("        Type: 0x");
				for (int h = p; h<p+2; h++) {
					printf("%.2x", dns->payload[h]);
				}
				printf("\n");
				p+=2;
				printf("        Class: 0x");
				for (int h = p; h<p+2; h++) {
					printf("%.2x", dns->payload[h]);
				}
				printf("\n");
			}
		}
		printf("\n    Taille totale du paquet: %i\n", taille_du_paquet);
	}
}
