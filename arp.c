#include <stdio.h>
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
couche_arp(int size, const u_char *packet, int taille_du_paquet, int verbo) {

  printf("\n\n------------- ARP Header -------------\n\n");

  struct ether_arp *arp;
  arp = (struct ether_arp*)(packet + size);
  printf("     Hardware type: ");
  switch(ntohs(arp->arp_hrd)) {
    case 1:
      printf("Ethernet (%i)\n", ntohs(arp->arp_hrd));
      break;
  }

  printf("     Protocol type: ");
  int a = ntohs(arp->arp_pro);
  switch(a) {
    case 2048:
      printf("IPv4 (0x%.2x)\n", ntohs(arp->arp_pro));
      break;
    case 34525:
      printf("IPv6 (0x%.2x)\n", ntohs(arp->arp_pro));
      break;
    default:
      printf(" Number of protocol (0x%.2x) --> not implemented or unknown", ntohs(arp->arp_pro));
      break;
  }
  if (verbo != 2) {
    printf("     Hardware size: %i\n", arp->arp_hln);
    printf("     Protocol size: %i\n", arp->arp_pln);
    printf("     Opcode: ");
    switch((int)ntohs(arp->arp_op)) {
      case 1:
      printf("Request (%i)\n", ntohs(arp->arp_op));
      break;
      case 2:
      printf("Reply (%i)\n", ntohs(arp->arp_op));
      break;
    }

    printf("     Sender MAC address: ");
    for(int i=0; i<6; i++) {
      printf("%.2x:", arp->arp_sha[i]);
    }
    printf("\n");

    printf("     Sender IP address: ");
    for(int i=0; i<4; i++) {
      printf("%u.", arp->arp_spa[i]);
    }
    printf("\n");

    printf("     Target MAC address: ");
    for(int i=0; i<6; i++) {
      printf("%.2x:", arp->arp_tha[i]);
    }
    printf("\n");

    printf("     Target IP address: ");
    for(int i=0; i<4; i++) {
      printf("%u.", arp->arp_tpa[i]);
    }
    printf("\n\n");

  }
}
