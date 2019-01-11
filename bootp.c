#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include "bootp.h"

void test_bootp(int, int, int, const u_char*, int, int);
void bootp_udp(int, const u_char*, int, int);

void
test_bootp( int source_port,
					  int destination_port,
	 					int size,
						const u_char *packet,
						int taille_du_paquet,
						int verbo) {

	if ((source_port == 67 && destination_port == 68)
				|| (source_port == 68 && destination_port == 67)) {
		bootp_udp(size, packet, taille_du_paquet, verbo);
	}
}

void
bootp_udp(int size, const u_char * packet, int taille_du_paquet, int verbo) {
	printf("\n\n-------------- BOOTP -------------\n\n");

	struct bootp *bootp_head;
	bootp_head = (struct bootp*)(packet + size);

	printf("      Message type: ");
	int a = bootp_head->bp_op;
	switch (a) {
		case 1:
			printf("Boot Request (1)\n");
			break;
		case 2:
			printf("Boot Reply (2)\n");
			break;
		default:
			printf("Unknown");
			break;
	}

	printf("      Hardware type: ");
	a = bootp_head->bp_htype;
	switch (a) {
		case 1:
			printf("Ethernet (0x01)\n");
			break;
		default:
			printf("Unknown\n");
			break;
	}

	if (verbo != 2) {

		printf("      Hardware address length: %i \n", bootp_head->bp_hlen);
		printf("      Hops: %i\n", bootp_head->bp_hops);
		printf("      Transaction ID: %i\n", ntohl(bootp_head->bp_xid));
		printf("      Seconds elapsed: %i \n", ntohs(bootp_head->bp_secs));
		printf("    > Bootp flags: 0x%.2x ", ntohs(bootp_head->bp_flags));
		switch ((int)ntohs(bootp_head->bp_flags)) {
			case 0:
			printf("(Unicast)\n");
			break;
			default:
			printf("(Unknown or not implemented)\n");
			break;
		}
		printf("      Client IP address: %s\n", inet_ntoa(bootp_head->bp_ciaddr));
		printf("      Your (client) IP address: %s\n", inet_ntoa(bootp_head->bp_yiaddr));
		printf("      Next server IP address: %s\n", inet_ntoa(bootp_head->bp_siaddr));
		printf("      Relay agent IP address: %s\n", inet_ntoa(bootp_head->bp_giaddr));
		printf("      Client MAC address: ");
		for(int i=0; i<16; i++) {
			printf("%.2x:", bootp_head->bp_chaddr[i]);
		}
		printf("\n");

		printf("    > Server name option\n");

		switch ((int)(bootp_head->bp_sname[0])) {
			case 56:
			printf("      > Option: (56) Message\n");
			break;
			default:
			printf("      > Option: 0x%.2x\n", (bootp_head->bp_sname[0]));
			break;
		}

		int lname = (int)bootp_head->bp_sname[1];
		printf("         Lenght: %i\n", bootp_head->bp_sname[1]);
		printf("         Message: sname field overload:\n              ");
		for (int i=2; i<lname+2; i++) {
			if(i%8==0) printf(" ");
			if(i%16==0) printf("\n              ");
			printf("%.2x:", bootp_head->bp_sname[i]);
		}
		printf("\n");

		switch ((int)(bootp_head->bp_sname[lname+2])) {
			case 255:
			printf("      > Option: (255) End\n");
			break;
			default:
			printf("      > Option: 0x%.2x\n", (bootp_head->bp_sname[lname+2]));
			break;
		}

		printf("    > Boot file name option\n");
		switch ((int)(bootp_head->bp_file[0])) {
			case 56:
			printf("      > Option: (56) Message\n");
			break;
			default:
			printf("      > Option: 0x%.2x\n", (bootp_head->bp_file[0]));
			break;
		}

		int lfile = (int)bootp_head->bp_file[1];
		printf("         Lenght: %i\n", bootp_head->bp_file[1]);

		printf("         Message: file name field overload:\n              ");
		for (int i=2; i<lfile+2; i++) {
			if(i%8==0) printf(" ");
			if(i%16==0) printf("\n              ");
			printf("%.2x:", bootp_head->bp_file[i]);
		}
		printf("\n");

		switch ((int)(bootp_head->bp_file[lfile+2])) {
			case 255:
			printf("      > Option: (255) End\n");
			break;
			default:
			printf("      > Option: 0x%.2x\n", (bootp_head->bp_file[lfile+2]));
			break;
		}

		printf("     Magic cookie: ");
		for (int i=0; i<4; i++) {
			printf("%.2x:", bootp_head->bp_vend[i]);
		}
		printf("\n");

		int p=4;
		int l;
		while ( (int)bootp_head->bp_vend[p] != 255 && p<63) {
			if ( bootp_head->bp_vend[p] == 0) {
				printf("     Option: PADDING 00\n");
				p++;
			} else {
				printf("     Option: 0x%.2x\n", bootp_head->bp_vend[p]);
				l = (int)bootp_head->bp_vend[p+1];
				printf("        Lenght: %i\n", l);

				printf("        Data : 0x");
				int i=0;
				for (int h=p; h<p+l+2; h++) {
					i++;
					if(i%8==0) printf(" ");
					if(i%16==0) printf("\n              ");
					printf("%.2x:",bootp_head->bp_vend[h]);
				}
				printf("\n");
				p = p + (int)bootp_head->bp_vend[p+1]+2;
			}
		}

		switch ((int)(bootp_head->bp_vend[p])) {
			case 255:
			printf("   > Option: (255) End\n");
			break;
			default:
			printf("   > Option: 0x%.2x\n", (bootp_head->bp_vend[p]));
			break;
		}


		printf("     Taille total du paquet: %i\n", taille_du_paquet);

	}

}
