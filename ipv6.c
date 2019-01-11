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

#include "ipv6.h"

#define PROTOCOLE_UDP 17
#define PROTOCOLE_TCP 6
#define PROTOCOLE_ICMP 1


void
couche_ipv6(int size, const u_char *packet, int taille_du_paquet, int verbo) {

  printf("\n\n------------ IPv6 Header ------------\n\n");

  char buf1[INET6_ADDRSTRLEN];
  char buf2[INET6_ADDRSTRLEN];
  // unsigned char buf1[sizeof(struct in6_addr)];
  // unsigned char buf2[sizeof(struct in6_addr)];
  int i=0;
  int a;
	struct ipv6hdr* ipv6;
  ipv6 = (struct ipv6hdr*)(packet+size);
  if (inet_ntop(AF_INET6, &(ipv6->ipv6_src), buf1, INET6_ADDRSTRLEN)==NULL)
    raler(1, 1, "inet_inop");
  printf("      Source: %s\n", buf1);
  if (inet_ntop(AF_INET6, &(ipv6->ipv6_dst), buf2, INET6_ADDRSTRLEN)== NULL)
    raler(1, 1, "inet_ntop");
  printf("      Destination: %s\n", buf2);
  size += sizeof(struct ipv6hdr);

  if (verbo != 2) {
    printf("      Version: %i\n", ipv6->ipv6_version);
    printf("      Traffic Class: (0x%.2x)\n", ipv6->ipv6_priority);
    printf("      Flow Label: 0x");
    for(i; i<3; i++){
      printf("%.2x", ipv6->ipv6_flow_lbl[i]);
    }
    printf("\n");

    printf("      Hop limit: %i\n", ipv6->ipv6_hoplimit);



  }
  a = (ipv6->ipv6_nextheader);
  printf("      Next Header:");
  switch(a){
    case 6:
    printf(" TCP (%i)", ipv6->ipv6_nextheader);
    tcp(size, packet, taille_du_paquet, verbo);
    break;
    case 17:
    printf(" UDP (%i)", ipv6->ipv6_nextheader);
    udp(size, packet, taille_du_paquet, verbo);
    break;
    case 1:
    printf(" ICMP (%i)", ipv6->ipv6_nextheader);
    break;
    case 58:
    printf(" ICMP for IPv6 (%i)", ipv6->ipv6_nextheader);
    break;
    default:
    printf(" Number of protocol (%i) --> not implemented or unknown", ipv6->ipv6_nextheader);
    break;
  }
  printf("\n");

}
