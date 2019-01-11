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
udp(int size, const u_char* packet, int taille_du_paquet, int verbo) {

  printf("\n\n------------- UDP Header ------------\n\n");
  struct udphdr *udp_header;
  udp_header = (struct udphdr*)(packet + size);
  int source_port = ntohs(udp_header->uh_sport);
  int destination_port = ntohs(udp_header->uh_dport);
  printf("      Source Port: %i \n", source_port);
  printf("      Destination Port: %i\n", ntohs(udp_header->uh_dport));

  if (verbo != 2) {
    printf("      Length: %i\n", ntohs(udp_header->uh_ulen));
    printf("      Checksum: 0x%.2x\n", ntohs(udp_header->uh_sum));
  }
  size += sizeof(struct udphdr);
  test_http(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_smtp(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_bootp(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_dns(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_pop(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_ftp(source_port, destination_port, size, packet, taille_du_paquet, verbo);
  test_imap(source_port, destination_port, size, packet, taille_du_paquet, verbo);

}
