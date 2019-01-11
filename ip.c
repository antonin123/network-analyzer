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

#include "http.c"
#include "imap.c"
#include "pop.c"
#include "ftp.c"
#include "bootp.c"
#include "dns.c"
#include "smtp.c"
#include "tcp.c"
#include "udp.c"


#define PROTOCOLE_UDP 17
#define PROTOCOLE_TCP 6
#define PROTOCOLE_ICMP 1


void
couche_ip(int size, const u_char *packet, int taille_du_paquet, int verbo) {

  printf("\n\n------------- IP Header -------------\n\n");
  struct ip *ipp;
  ipp = (struct ip*)(packet + size);
  printf("      Source:  %s\n", inet_ntoa(ipp->ip_src));
  printf("      Destination: %s\n", inet_ntoa(ipp->ip_dst));

  if (verbo != 2) {
    printf("      Version: %i\n",ipp->ip_v);
    printf("      Header Length: %i bits\n", 4*ipp->ip_hl);
    printf("    > Type of service: 0x%.2x\n", ipp->ip_tos);
    printf("      Total Length: %i bits\n", ntohs(ipp->ip_len));
    printf("      Identification: ");
    printf("0x%.2x (%i)\n", ntohs(ipp->ip_id), ntohs(ipp->ip_id));
    printf("    > Flags: %i\n", ntohs(ipp->ip_off));
    printf("      Time to live: %i\n", ipp->ip_ttl);
    printf("      Header checksum: 0x%.4x\n", ntohs(ipp->ip_sum));


  }
  int protocol = ipp->ip_p;
  size += sizeof(struct ip);
  if(protocol == PROTOCOLE_TCP) {
    printf("      Protocol: TCP (%i)\n",protocol);
    tcp(size, packet, taille_du_paquet, verbo);
  }

  if(protocol == PROTOCOLE_UDP) {
    printf("      Protocol: UDP (%i)\n",protocol);
    udp(size, packet, taille_du_paquet, verbo);
  }
}
