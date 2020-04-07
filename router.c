#include "skel.h"


int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init();

	arpEntry* arpTable[100];

	/*se parseaza tabela ARP daca este data si tabela de rutare
	routingTable se sorteaza dupa prefix pentru a se
	putea aplica cautarea binara*/
	int arpSize = parseArpTable(arpTable);

	routeEntry* routingTable[100000];

	int routeSize = parseRoutingTable(routingTable);
	quickSort(routingTable, 0, routeSize - 1);


	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		
		/*la primirea adresei de broadcast, se trateaza cazul
		pachetului de ARP request*/
		if (checkBroadcastAddress(eth_hdr->ether_dhost))
		{
			struct arphdr *arp_hdr = (struct arphdr *)(m.payload + ARP_OFF);

			if (ntohs(arp_hdr->ar_op) == 1)
			{
				requestPayload *payload = (requestPayload *)(m.payload + REQUEST_OFF);

				char ipString[15];
				sprintf(ipString, "%d.%d.%d.%d", payload->ipTarget[0], payload->ipTarget[1], payload->ipTarget[2], payload->ipTarget[3]);
				
				/*daca request-ul este adresat router-ului, acesta va construi
				pachetul de reply continand adresa MAC*/
				if (strcmp(ipString, get_interface_ip(m.interface)) == 0)
				{
					packet reply;

					reply.len = sizeof(struct ether_header) + sizeof(struct arphdr) + sizeof(requestPayload);
					reply.interface = m.interface;

					struct ether_header *reth_hdr = (struct ether_header *)reply.payload;
					struct arphdr *rarp_hdr = (struct arphdr *)(reply.payload + ARP_OFF);
					requestPayload *rpayload = (requestPayload *)(reply.payload + REQUEST_OFF);

					u_char routerMacAddress[6];

					get_interface_mac(m.interface, routerMacAddress);

					memcpy(&reth_hdr->ether_dhost, &eth_hdr->ether_shost, 6);
					memcpy(&reth_hdr->ether_shost, &routerMacAddress, 6);
					memcpy(&reth_hdr->ether_type, &eth_hdr->ether_type, 2);

					memcpy(&rarp_hdr->ar_hrd, &arp_hdr->ar_hrd, 6);
					rarp_hdr->ar_op = htons(2);

					memcpy(&rpayload->macSender, &routerMacAddress, 6);
					memcpy(&rpayload->ipSender, &payload->ipTarget, 4);
					memcpy(&rpayload->macTarget, &payload->macSender, 6);
					memcpy(&rpayload->ipTarget, &payload->ipSender, 4);


					send_packet(reply.interface, &reply);


				}

			}
		}
		//se verifica adresa destinatie ca fiind adresa router-ului
		else if (checkMacAddress(eth_hdr->ether_dhost, m.interface))
		{
			//cazul primirii unui pachet de tip ARP
			if (ntohs(eth_hdr->ether_type) == 0x0806)
			{
				struct arphdr *arp_hdr = (struct arphdr *)(m.payload + ARP_OFF);
				requestPayload *payload = (requestPayload *)(m.payload + REQUEST_OFF);

				if (ntohs(arp_hdr->ar_op) == 2)
				{
					/*daca pachetul ARP reply este adresat router-ului, acesta isi va actualiza
					tabela ARP si va renunta la pachet*/
					if (checkMacAddress(payload->macTarget, m.interface))
					{
						int ipSender;
						memcpy(&ipSender, &payload->ipSender, 4);
						arpEntry* arpTableEntry = getArpEntry(ipSender, arpTable, arpSize);

						if (arpTableEntry == NULL)
						{
							arpTableEntry = (arpEntry*)malloc(sizeof(arpEntry));
							arpTableEntry->ip = ipSender;
							memcpy(&arpTableEntry->mac, &payload->macSender, 6);
							arpTable[arpSize] = arpTableEntry;
							arpSize++;

						}

						continue;

					}
					/*daca pachetul nu este destina router-ului, acesta isi va actualiza tabela
					doar in cazul gasirii destinatiei ca dispozitiv local*/
					else
					{
						int ipSender, ipTarget;
						memcpy(&ipSender, &payload->ipSender, 4);
						memcpy(&ipTarget, &payload->ipTarget, 4);
						routeEntry* routeSenderEntry = getRouteEntry(ipSender, routingTable, routeSize);
						routeEntry* routeTargetEntry = getRouteEntry(ipTarget, routingTable, routeSize);

						if (ipSender == routeSenderEntry->nextHop)
						{
							arpEntry* arpTableEntry = getArpEntry(ipSender, arpTable, arpSize);

							if (arpTableEntry == NULL)
							{
								arpTableEntry = (arpEntry*)malloc(sizeof(arpEntry));
								arpTableEntry->ip = ipSender;
								memcpy(&arpTableEntry->mac, &payload->macSender, 6);
								arpTable[arpSize] = arpTableEntry;
								arpSize++;

							}
						}

						/*se trimite pachetul la urmatoarea dispozitiv
						din ruta catre destinatiei*/
						u_char routerMacAddress[6];
						get_interface_mac(routeTargetEntry->interface, routerMacAddress);
						arpEntry* arpTargetEntry = getArpEntry(routeTargetEntry->nextHop, arpTable, arpSize);

						memcpy(&eth_hdr->ether_shost, &routerMacAddress, 6);
						memcpy(&eth_hdr->ether_dhost, &arpTargetEntry->mac, 6);

						send_packet(routeTargetEntry->interface, &m);


					}
				}
				

			}
			//se analizeaza pachetul de tip IPv4
			else
			{
				struct iphdr *ip_hdr = (struct iphdr *)(m.payload + IP_OFF);

				/*daca IP-ul destinatie apartine router-ului, se raspunde
				cu un pachet de tip echo reply*/
				if (ip_hdr->daddr == inet_addr(get_interface_ip(m.interface)))
				{
					struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);

					__u16 sum = ip_hdr->check;
					ip_hdr->check = 0;

					if (sum != checksum(ip_hdr, sizeof(struct iphdr)))
					{
						continue;
					}

					sum = icmp_hdr->checksum;
					icmp_hdr->checksum = 0;

					//daca checksum-ul difera de cel calculat, se arunca pachetul
					if (sum != checksum(icmp_hdr, ICMP_SIZE))
					{
						continue;
					}

					/*ca raspuns la echo request, se construieste si se trimite
					pachetul de echo reply*/
					if (icmp_hdr->type == 8)
					{
						u_char routerMacAddress[6];

						get_interface_mac(m.interface, routerMacAddress);

						memcpy(&eth_hdr->ether_dhost, &eth_hdr->ether_shost, 6);
						memcpy(&eth_hdr->ether_shost, &routerMacAddress, 6);

						ip_hdr->daddr = ip_hdr->saddr;
						ip_hdr->saddr = inet_addr(get_interface_ip(m.interface));
						ip_hdr->ttl = 64;
						ip_hdr->id = htons(ip_hdr->id + 1);
						ip_hdr->frag_off = 0;
						ip_hdr->check = checksum(ip_hdr, sizeof(struct iphdr));

						icmp_hdr->type = 0;
						icmp_hdr->checksum = checksum(icmp_hdr, ICMP_SIZE);

						send_packet(m.interface, &m);

					}			
				}
				//se trimite pachetul mai departe pe ruta catre destinatar
				else
				{

					__u16 sum = ip_hdr->check;
					ip_hdr->check = 0;

					//daca checksum-ul difera de cel calculat, se arunca pachetul
					if (sum != checksum(ip_hdr, sizeof(struct iphdr)))
					{
						printf("Invalid checksum\n");
						continue;
					}

					/*se recalculeaza checksum-ul dupa decrementarea TTL folosind
					algoritmul incremental din RFC 1624*/
					ip_hdr->check = rfcChecksum(sum, ip_hdr->ttl);
					ip_hdr->ttl--;

					/*daca valoarea Time To Live a expirat, se arunca pachetul
					si se raspunde cu mesajul respectiv*/
					if (ip_hdr->ttl < 1)
					{
						
						packet reply;
						reply.len = sizeof(struct ether_header) + 56;
						reply.interface = m.interface;

						u_char routerMacAddress[6];

						get_interface_mac(reply.interface, routerMacAddress);

						struct ether_header *reth_hdr = (struct ether_header *)reply.payload;
						struct iphdr *rip_hdr = (struct iphdr*)(reply.payload + IP_OFF);
						struct icmphdr *ricmp_hdr = (struct icmphdr *)(reply.payload + ICMP_OFF);

						memcpy(&reth_hdr->ether_dhost, &reth_hdr->ether_shost, 6);
						memcpy(&reth_hdr->ether_shost, &routerMacAddress, 6);
						reth_hdr->ether_type = htons(0x0800);

						rip_hdr->version = 4;
						rip_hdr->ihl = 5;
						rip_hdr->tos = 0;
						rip_hdr->tot_len = htons(56);
						rip_hdr->id = htons(2162);
						rip_hdr->frag_off = 0;
						rip_hdr->ttl = 64;
						rip_hdr->protocol = 1;
						rip_hdr->check = 0;
						rip_hdr->daddr = ip_hdr->saddr;
						rip_hdr->saddr = inet_addr(get_interface_ip(reply.interface));

						rip_hdr->check = checksum(rip_hdr, sizeof(struct iphdr));

						ricmp_hdr->type = 11;
						ricmp_hdr->code = 0;
						ricmp_hdr->checksum = 0;
						ricmp_hdr->checksum = checksum(ricmp_hdr, 36);

						send_packet(reply.interface, &reply);

						continue;
					}

					//se cauta urmatoarea destinatie in tabela de rutare
					routeEntry* routeTableEntry = getRouteEntry(ip_hdr->daddr, routingTable, routeSize);

					/*in cazul in care aceasta nu a fost gasita, se raspunde
					cu Unreachable Host*/
					if (routeTableEntry == NULL)
					{
						packet reply;
						reply.len = sizeof(struct ether_header) + 56;
						reply.interface = m.interface;

						u_char routerMacAddress[6];

						get_interface_mac(reply.interface, routerMacAddress);

						struct ether_header *reth_hdr = (struct ether_header *)reply.payload;
						struct iphdr *rip_hdr = (struct iphdr*)(reply.payload + IP_OFF);
						struct icmphdr *ricmp_hdr = (struct icmphdr *)(reply.payload + ICMP_OFF);

						memcpy(&reth_hdr->ether_dhost, &reth_hdr->ether_shost, 6);
						memcpy(&reth_hdr->ether_shost, &routerMacAddress, 6);
						reth_hdr->ether_type = htons(0x0800);

						rip_hdr->version = 4;
						rip_hdr->ihl = 5;
						rip_hdr->tos = 0;
						rip_hdr->tot_len = htons(56);
						rip_hdr->id = htons(2162);
						rip_hdr->frag_off = 0;
						rip_hdr->ttl = 64;
						rip_hdr->protocol = 1;
						rip_hdr->check = 0;
						rip_hdr->daddr = ip_hdr->saddr;
						rip_hdr->saddr = inet_addr(get_interface_ip(reply.interface));

						rip_hdr->check = checksum(rip_hdr, sizeof(struct iphdr));

						ricmp_hdr->type = 3;
						ricmp_hdr->code = 0;
						ricmp_hdr->checksum = 0;
						ricmp_hdr->checksum = checksum(ricmp_hdr, 36);

						send_packet(reply.interface, &reply);

						continue;
					}

					//se cauta adresa MAC a destinatiei in tabela
					arpEntry* arpTableEntry = getArpEntry(routeTableEntry->nextHop, arpTable, arpSize);

					/*in cazul in care aceasta nu a fost gasita, se trimite
					un ARP request*/
					if (arpTableEntry == NULL)
					{
						packet arpRequest;

						arpRequest.len = sizeof(struct ether_header) + sizeof(struct arphdr) + sizeof(requestPayload);

						struct ether_header *reth_hdr = (struct ether_header *)arpRequest.payload;
						struct arphdr *rarp_hdr = (struct arphdr *)(arpRequest.payload + ARP_OFF);
						requestPayload *rpayload = (requestPayload *)(arpRequest.payload + REQUEST_OFF);


						int i;

						for (i = 0; i < 6; i++)
						{
							reth_hdr->ether_dhost[i] = 0xff;						
						}

						reth_hdr->ether_type = htons(0x0806);

						rarp_hdr->ar_hrd = htons(1);
						rarp_hdr->ar_pro = htons(0x0800);
						rarp_hdr->ar_hln = 6;
						rarp_hdr->ar_pln = 4;
						rarp_hdr->ar_op = htons(1);

						for (i = 0; i < 6; i++)
						{
							rpayload->macTarget[i] = 0x00;						
						}

						memcpy(&rpayload->ipTarget, &routeTableEntry->nextHop, 4);


						arpRequest.interface = routeTableEntry->interface;

						u_char routerMacAddress[6];
						get_interface_mac(routeTableEntry->interface, routerMacAddress);
						memcpy(&reth_hdr->ether_shost, &routerMacAddress, 6);

						int ip = inet_addr(get_interface_ip(routeTableEntry->interface));
						memcpy(&rpayload->macSender, &routerMacAddress, 6);
						memcpy(&rpayload->ipSender, &ip, 4);

						send_packet(routeTableEntry->interface, &arpRequest);


						while(1)
						{
							packet reply;

							rc = get_packet(&reply);
							DIE(rc < 0, "get_message");

							struct arphdr *reparp_hdr = (struct arphdr *)(reply.payload + ARP_OFF);
							requestPayload *reppayload = (requestPayload *)(reply.payload + REQUEST_OFF);

							/*la primirea pachetului de tip ARP reply, se actualizeaza tabela
							si se poate trimite pachetul*/
							if (ntohs(reparp_hdr->ar_op) == 2)
							{
								u_char targetMacAddress[6];

								memcpy(&targetMacAddress, &reppayload->macSender, 6);

								arpTableEntry = (arpEntry*)malloc(sizeof(arpEntry));
								arpTableEntry->ip = routeTableEntry->nextHop;
								memcpy(&arpTableEntry->mac, &targetMacAddress, 6);

								arpTable[arpSize] = arpTableEntry;
								arpSize++;

								break;
								
							}
						}


					}
					
					//se trimite pachetul la urmatorul dispozitiv din ruta destinatiei
					u_char routerMacAddress[6];
					get_interface_mac(routeTableEntry->interface, routerMacAddress);

					memcpy(&eth_hdr->ether_dhost, &arpTableEntry->mac, 6);
					memcpy(&eth_hdr->ether_shost, &routeTableEntry, 6);

					send_packet(routeTableEntry->interface, &m);
				}
			}
			

		}


	}
}
