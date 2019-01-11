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

#define DATA_TYPE_IPV4 0x0800
#define DATA_TYPE_ARP 0x0806
#define DATA_TYPE_RARP 0x0835
#define DATA_TYPE_IPV6 0x86dd

#include "ip.c"
#include "ipv6.c"
#include "arp.c"

#define SIZE_OF_ETHERNET 14

void
afficher_source_destination(struct ether_header *eth_head) {
  printf("\n---------- Ethernet Header ----------\n\n");
  int i=0;
  printf("    > Destination: ");
  for(i;i<6;i++) {
    printf("%.2x:",eth_head->ether_dhost[i]);
  }
  printf("\n");
  i=0;
  printf("    > Source : ");
  for(i;i<6;i++) {
    printf("%.2x:",eth_head->ether_shost[i]);
  }
  printf("\n");
}

void
test_type(struct ether_header *eth_head,
          const u_char *packet,
          int taille_du_paquet,
          int verbo) {

  int size = 0;
  int ether_type_t = ntohs(eth_head->ether_type);
  size = sizeof(struct ether_header);
  switch (ether_type_t) {
    case DATA_TYPE_IPV4:
      printf("      Type : 0x%.2x\n",ether_type_t);
      couche_ip(size, packet, taille_du_paquet, verbo);
      break;
    case DATA_TYPE_ARP:
      printf("      Type : 0x%.2x\n",ether_type_t);
      couche_arp(size, packet, taille_du_paquet, verbo);
      break;
    case DATA_TYPE_RARP:
      printf("      Type : 0x%.2x\n",ether_type_t);
      printf("\n\n------------- RARP Header -------------\n\n");
      printf("                   not implemented\n");
      break;
    case DATA_TYPE_IPV6:
      printf("      Type : 0x%.2x\n",ether_type_t);
      couche_ipv6(size, packet, taille_du_paquet, verbo);
      break;
    default:
      printf("      Type : 0x%.2x\n",ether_type_t);
      printf("               not implemented\n");
      break;
  }
}

void
couche_ethernet(const u_char *packet, int taille_du_paquet, int verbo) {
  struct ether_header *eth_head;
	eth_head = (struct ether_header*)packet;
  afficher_source_destination(eth_head);
  if (verbo == 1) {
    //on fait rien
  } else {
    test_type(eth_head, packet, taille_du_paquet, verbo);
  }
}
