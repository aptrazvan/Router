#pragma once
#include <time.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>
/* ethheader */
#include <net/ethernet.h>
/* ether_header */
#include <arpa/inet.h>
/* icmphdr */
#include <netinet/ip_icmp.h>
/* arphdr */
#include <net/if_arp.h>
#include <asm/byteorder.h>
#include <stdlib.h>
#include <stdbool.h>

/* 
 *Note that "buffer" should be at least the MTU size of the 
 * interface, eg 1500 bytes 
 */
#define MAX_LEN 1600
#define ROUTER_NUM_INTERFACES 4
#define ARP_OFF (sizeof(struct ether_header))
#define REQUEST_OFF (ARP_OFF + sizeof(struct arphdr))
#define IP_OFF (sizeof(struct ether_header))
#define ICMP_OFF (IP_OFF + sizeof(struct iphdr))
#define ICMP_SIZE 64

#define DIE(condition, message) \
	do { \
		if ((condition)) { \
			fprintf(stderr, "[%d]: %s\n", __LINE__, (message)); \
			perror(""); \
			exit(1); \
		} \
	} while (0)

typedef struct {
	int len;
	char payload[MAX_LEN];
	int interface;
} packet;

/*structura utilizata la accesarea campurilor pachetelor
de tip ARP request sau ARP reply*/
typedef struct {
	u_char macSender[6];
	u_char ipSender[4];
	u_char macTarget[6];
	u_char ipTarget[4];
} requestPayload;


extern int interfaces[ROUTER_NUM_INTERFACES];

int send_packet(int interface, packet *m);
int get_packet(packet *m);
char *get_interface_ip(int interface);
int get_interface_mac(int interface, uint8_t *mac);
void init();
void parse_arp_table();

/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr);

typedef struct {
	__u32 ip;
	uint8_t mac[6];
} arpEntry;


typedef struct {
	__u32 prefix;
	__u32 nextHop;
	__u32 mask;
	int interface;
} routeEntry;

uint16_t rfcChecksum(uint16_t, uint16_t);
int partition (routeEntry**, int, int);
void quickSort(routeEntry**, int, int);
void binarySearch(routeEntry**, int, int, __u32, int*, int);
uint16_t checksum(void* vdata,size_t length);
int parseArpTable(arpEntry**);
arpEntry* getArpEntry(__u32, arpEntry**, int);
int parseRoutingTable(routeEntry**);
routeEntry* getRouteEntry(__u32, routeEntry**, int);
bool checkBroadcastAddress(u_char*);
bool checkMacAddress(u_char*, int);

