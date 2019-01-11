/*
	pour compiler gcc -Wextra -Werror -Wall main.c -o main -lpcap
	possibilité de faire alldevsp->next->name !!!
	mettre sudo a l'execution
*/

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

void raler(int, int, char*);
#include "ethernet_header.c"

void usage(char *);
void got_packet(u_char *,const struct pcap_pkthdr *,const u_char *);
pcap_t *p;
int verbo=3; //par défaut on affiche toutes les données
int count=0; //le numéro du paquet affiché

/* affiche les infos d'un trame */
void info_trame(int count, int taille_du_paquet) {
	printf("\n\n\n");
	printf("\n___________________________________");
	printf("___________________________________________\n\n");
	printf("Trame numéro %i\n", count);
	printf("Taille de la trame %i\n", taille_du_paquet);
}

/* affiche la manière d'utiliser l'exécutable ./main */
void
usage(char * prog) {
  fprintf(stderr, "\nusage: %s [-i interface]", prog);
	fprintf(stderr," [-o fichier] [-f filtre] [-v version]\n");
}

/* fonction qui gère des erreurs et quitte le code 2eme arg vaut 1*/
void
raler(int perr, int quit, char * mess_err) {
	fprintf(stderr,"%s\n", mess_err);
	if (perr == 1) perror("");
	if (quit == 1) exit (EXIT_FAILURE);
}

/* fonction qui récupére les trames*/
void
got_packet( u_char *args,
					  const struct pcap_pkthdr *header,
						const u_char *packet) {

	count++;
	int taille_du_paquet = header->len;
	info_trame(count, taille_du_paquet);
	/* appel de la 1er couche ethernet */
	couche_ethernet(packet, taille_du_paquet, verbo);
}


int
main(int argc,  char ** argv) {
	int num_packets = -1; // on peut choisir ici les nombre de paquet qu'on veut
												// afficher. Ici il vaut -1 : on affiche tout
	pcap_if_t *alldevsp;
	int errflg = 0;
  int c;
  char * progname = argv[0]; //nom du programme
	char errbuf[PCAP_ERRBUF_SIZE];
	const char * fichier;
	const char * interface;
	struct bpf_program fp;
	bpf_u_int32 mask=0;
	bpf_u_int32 net=0;
	char *filter="";

	if (argc == 1) {
		usage(progname);
		raler(0, 1, "il n'y pas assez d'argument\n");
	}

  while ((c = getopt(argc, argv, "v:i:o:f:")) != -1) {
    switch (c) {

		/* option f permet de mettre un filtre
			il faut bien mettre le type de filtre entre guillemets */
		case 'f':
			printf("\n\n\n Pour choisir un filtre ");
			printf("il faut que le choix se fasse avant -o ou -i\n\n\n");
			printf("option f, filtre BPF :  %s\n", optarg);
			filter = optarg;
			break;

		/*  verbosité : nombre d'informations que l'on veut afficher
		 peur être egale à 1, 2 ou 3. Il faut le mettre avant les options
		 -i et -o */
		case 'v':
			printf("\n\n\n Pour choisir une verbosité ");
			printf("il faut que le choix se fasse avant -o ou -i\n\n\n");
			verbo = atoi(optarg);
			if (verbo < 1 || verbo >3)
				raler(0, 1, "il faut que le verbosité soit entre 1 et 3 inclus\n");
			printf("option v, niveau de verbosité : %s\n", optarg);
			break;

	  /* on récupére les trames en ligne. Si on veut récupérer une interface
		par défaut il faut mettre : ./main -i default */
    case 'i':
			printf("option i, interface : %s\n", optarg);
			if ( strcmp(optarg, "default") == 0) {
				// pcap_findalldevs permet de trouver l'interface demandée
				if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
						raler(1,0,errbuf);
					}
				printf("1er interface trouvée : %s\n",alldevsp->name);
				optarg = alldevsp->name;
				interface = optarg;
			}
			//charge le mask et le net avec l'interface trouvée
			if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
				fprintf(stderr, "Pas de mask trouvé pour %s: %s\n", interface, errbuf);
				net = 0;
				mask = 0;
			}

			//ouvre l'interface pour visualiser les trames
		  p = pcap_open_live(interface, 1518, 1, 1000, errbuf);
			if(p==NULL){
		    fprintf(stderr, "Ouverture impossible %s: %s\n", interface, errbuf);
		    return(1);
		  }

			//met en place le filtre
			if (pcap_compile(p, &fp, filter, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(p));
				raler(0,1,"");
			}
			if (pcap_setfilter(p, &fp) == -1) {
				fprintf(stderr, "Problème de filtre %s: %s\n", filter, pcap_geterr(p));
				raler(0,1,"");
			}

			//lance l'analyse des trames
			if(pcap_loop(p, num_packets, got_packet, NULL) <0) {
		    fprintf(stderr,"pcap_loop : %s\n",pcap_geterr(p));
		    raler(0,1,"");
		  }

			exit(EXIT_SUCCESS);

		// analyse offline de fichiers comportant des trames placés en argument
    case 'o':
			fichier=optarg;
			printf("option o, fichier d'entrée %s pour analyse offline	 \n", optarg);
			p = pcap_open_offline(fichier, errbuf);
			if (p == NULL) {
				fprintf(stderr, "Ouverture impossible %s: %s\n", interface, errbuf);
				return 1;
			}

			//installe un filtre pour l'analyse que si celui si a été précisé en option
			if (strcmp(filter,"")) {
				if (pcap_compile(p, &fp, filter, 0, net) == -1) {
					fprintf(stderr, "Mauvais filtre %s: %s\n", filter, pcap_geterr(p));
					raler(0,1,"");
				}
				if (pcap_setfilter(p, &fp) == -1) {
					fprintf(stderr, "Mise en place du filtre impossible %s: %s\n", filter, pcap_geterr(p));
					raler(0,1,"");
				}
			}

			//lance l'analyse de trame
			if(pcap_loop(p, num_packets, got_packet, NULL) <0) {
		    fprintf(stderr,"pcap_loop : %s\n",pcap_geterr(p));
		    raler(0,1,"");
		  }
      break;

    case '?':
      errflg++;
      break;
    }
	}
  if (errflg) usage(progname);
	exit(EXIT_SUCCESS);
}
