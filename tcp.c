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
tcp(int size, const u_char* packet, int taille_du_paquet, int verbo) {

  printf("\n\n------------- TCP Header ------------\n\n");
  struct tcphdr *tcp;
  tcp = (struct tcphdr*)(packet + size);
  int source_port = ntohs(tcp->th_sport);
  int destination_port = ntohs(tcp->th_dport);
  printf("      Source Port: %u\n", source_port);
  printf("      Destination Port: %u\n",destination_port);


  if (verbo != 2) {
    printf("      Sequence number: 0x%.2x\n", ntohl(tcp->th_seq));
    printf("      Acknowledgement number: 0x%.2x\n", ntohl(tcp->th_ack));
    printf("      Hearder Length: %i bytes (%i)\n", 4*tcp->th_off, tcp->th_off);

    printf("    > Flags: 0x%.2x ", ntohs(tcp->th_flags));
    int a = ntohs(tcp->th_flags);
    switch(a) {
      case 10:
      printf("(ACK)\n");
      break;
      case 2:
      printf("(SYN)\n");
      break;
      case 11:
      printf("(FIN-ACK)\n");
      break;
      case 12:
      printf("(SYN-ACK)\n");
      break;
      default:
      printf("(not implemented)");
      break;
    }
    printf("\n");

    printf("      Window size value: %i\n", ntohs(tcp->th_win));
    printf("      Checksum: 0x%.2x\n", ntohs(tcp->th_sum));
    printf("      Urgent pointer: %i\n", ntohs(tcp->th_urp));

    int l;
    size += sizeof(struct tcphdr);
    u_int8_t additional_lenght =0;
    int p=0;
    while ( p<(int)(tcp->th_off) && (packet + size)[p]!=0) {
			if ( (packet + size)[p] == 1) {
				printf("     Option: No Opération\n");
				p++;
        additional_lenght ++;
			} else {
				printf("     Option: 0x%.2x\n", (packet + size)[p]);
				l = (int)(packet + size)[p+1];
        additional_lenght += l + 2;
				printf("        Lenght: %i Ox(%.2x)\n", l, (packet + size)[p+1]);
        p++;
        if (l =! 0) {
          printf("        Data : 0x");
          int i=0;
          for (int h=p; h<p+l; h++) {
            i++;
            if(i%8==0) printf(" ");
            if(i%16==0) printf("\n              ");
            printf("%.2x:",(packet + size)[h]);
          }
          printf("\n");
          p = p + (int)(packet + size)[p+1];

        }
			}
		}
    printf("\n");
		printf("     Taille total du paquet: %i\n", taille_du_paquet);

	}

  test_smtp(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_imap(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_bootp(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_dns(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_http(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_pop(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_ftp(source_port, destination_port, size, packet, taille_du_paquet, verbo);
}
