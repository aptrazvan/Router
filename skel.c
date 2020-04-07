#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s , (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

packet* socket_receive_message(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	m->len = read(sockfd, m->payload, MAX_LEN);
	DIE(m->len == -1, "read");
	return m;
}

int send_packet(int sockfd, packet *m)
{        
	/* 
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 * */
	int ret;
	ret = write(interfaces[sockfd], m->payload, m->len);
	DIE(ret == -1, "write");
	return ret;
}

int get_packet(packet *m) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				socket_receive_message(interfaces[i], m);
				m->interface = i;
				return 0;
			}
		}
	}
	return -1;
}

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

int get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	sprintf(ifr.ifr_name, "r-%u", interface);
	ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
	return 1;
}

void init()
{
	int s0 = get_sock("r-0");
	int s1 = get_sock("r-1");
	int s2 = get_sock("r-2");
	int s3 = get_sock("r-3");
	interfaces[0] = s0;
	interfaces[1] = s1;
	interfaces[2] = s2;
	interfaces[3] = s3;
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}
/**
 * hwaddr_aton - Convert ASCII string to MAC address (colon-delimited format)
 * @txt: MAC address as a string (e.g., "00:11:22:33:44:55")
 * @addr: Buffer for the MAC address (ETH_ALEN = 6 bytes)
 * Returns: 0 on success, -1 on failure (e.g., string not a MAC address)
 */
int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}

uint16_t checksum(void *vdata, size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

/*functia de calculare a checksum-ului dupa decrementarea TTL folosind
algoritmul incremental din RFC 1624*/
uint16_t rfcChecksum(uint16_t oldChecksum, uint16_t ttl)
{
	return oldChecksum + ttl - (ttl - 1);
}

/*parsarea tabelei ARP in cazul introducerii acesteia
sub forma de fisier text*/
int parseArpTable(arpEntry** entries)
{
	FILE* arpTable;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    int index = 0;

    arpTable = fopen("arptable.txt", "r");

    if (arpTable == NULL) {
        return 0;
    }

    while ((read = getline(&line, &len, arpTable)) != -1) {       
        int i = 0;
        char ipAddress[15];
        char macAddress[20];

        while (line[i] != ' ')
        {
        	ipAddress[i] = line[i];
        	i++;
        }

        ipAddress[i] = '\0';
        int initialOffset = i;

        while (line[i] != '\0')
        {
        	macAddress[i - initialOffset] = line[i];
        	i++;
        }

        macAddress[i - initialOffset] = '\0';

        arpEntry* entry = (arpEntry*)malloc(sizeof(arpEntry));

        entry->ip = inet_addr(ipAddress);
        hwaddr_aton(macAddress, entry->mac);


        entries[index] = entry;
        index++;



    }

    fclose(arpTable);

    if (line) {
        free(line);
    }

    return index;
}

//parsarea fisierului text ce contine tabela de rutare
int parseRoutingTable(routeEntry** entries)
{
	FILE* routingTable;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    int index = 0;

    routingTable = fopen("rtable.txt", "r");

    if (routingTable == NULL)
        exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, routingTable)) != -1) {
    	int i = 0;
    	char prefixString[15];
    	char nextHopString[15];
    	char maskString[15];
    	char interfaceString[4];

    	while(line[i] != ' ')
    	{
    		prefixString[i] = line[i];
    		i++;
    	}

    	prefixString[i] = '\0';

    	i++;
    	int offset = i;

    	while(line[i] != ' ')
    	{
    		nextHopString[i - offset] = line[i];
    		i++;
    	}

    	nextHopString[i - offset] = '\0';

    	i++;
    	offset = i;

    	while(line[i] != ' ')
    	{
    		maskString[i - offset] = line[i];
    		i++;

    	}

    	maskString[i - offset] = '\0';

    	i++;
    	offset = i;

    	while(line[i] != '\0')
    	{
    		interfaceString[i - offset] = line[i];
    		i++;

    	}

    	interfaceString[i - offset] = '\0';

    	/*se convertesc adresele in forma de intreg si se stocheaza
    	in structuri de tip routeEntry*/
    	struct in_addr *ip = (struct in_addr *)malloc(sizeof(struct in_addr));

    	routeEntry* entry = (routeEntry*)malloc(sizeof(routeEntry));


    	inet_aton(prefixString, ip);
		entry->prefix = ip->s_addr;

		inet_aton(nextHopString, ip);
		entry->nextHop = ip->s_addr;

		inet_aton(maskString, ip);
		entry->mask = ip->s_addr;

		entry->interface = atoi(interfaceString);

		entries[index] = entry;
		index++;


    }

    return index;
}


int partition (routeEntry** routingTable, int low, int high) 
{ 
    int pivot = routingTable[high]->prefix;
    int i = (low - 1);
    routeEntry* entry;
  
    for (int j = low; j <= high- 1; j++) 
    { 
        if (routingTable[j]->prefix < pivot) 
        { 
            i++;
            routeEntry* entry = routingTable[i];
            routingTable[i] = routingTable[j];
            routingTable[j] = entry;

        } 
    }
    entry = routingTable[i + 1];
    routingTable[i + 1] = routingTable[high];
    routingTable[high] = entry;

    return (i + 1); 
} 

//realizeaza sortarea tabelei de rutare dupa prefix
void quickSort(routeEntry** routingTable, int low, int high) 
{ 
    if (low < high) 
    { 
        int pi = partition(routingTable, low, high); 
  
        quickSort(routingTable, low, pi - 1); 
        quickSort(routingTable, pi + 1, high); 
    } 
} 

/*se foloseste cautarea binara pentru gasirea eficienta a intrarii
din tabela de rutare*/
void binarySearch(routeEntry** routingTable, int l, int r, __u32 dest_ip, int *position, int maxMask) 
{ 
    if (r >= l) { 
        int mid = l + (r - l) / 2; 

  
        if ((dest_ip & routingTable[mid]->mask) == (routingTable[mid]->prefix & routingTable[mid]->mask)) {

            if (__builtin_popcount(routingTable[mid]->mask) > maxMask)
            {
            	maxMask = __builtin_popcount(routingTable[mid]->mask);
            	*position = mid;
            	
            }

            binarySearch(routingTable, l, mid - 1, dest_ip, position, maxMask); 
            binarySearch(routingTable, mid + 1, r, dest_ip, position, maxMask); 
        }

        else if ((dest_ip & routingTable[mid]->mask) < (routingTable[mid]->prefix & routingTable[mid]->mask)) {
            binarySearch(routingTable, l, mid - 1, dest_ip, position, maxMask); 
        }
        else {
        	binarySearch(routingTable, mid + 1, r, dest_ip, position, maxMask);         	
        }
  
    } 
  
    return; 
} 

/*functie pentru extragerea unei intrari din tabela
de rutare pe baza adresei IP*/
routeEntry* getRouteEntry(__u32 dest_ip, routeEntry** routingTable, int tableSize) {
	
	int maxMask = 0;
	int i = -1;
	routeEntry *entry = NULL;

	binarySearch(routingTable, 0, tableSize - 1, dest_ip, &i, maxMask);

	if (i != -1)
	{
		entry = routingTable[i];	
	}


	return entry;
}

//cautarea intrarii din tabela ARP cu adresa IP data
arpEntry* getArpEntry(__u32 dest_ip, arpEntry** arpTable, int tableSize)
{
	int i;

	for (i = 0; i < tableSize; i++)
	{
		if (arpTable[i]->ip == dest_ip)
		{
			return arpTable[i];
		}
	}

	return NULL;
}

/*verifica introducerea unei adrese de broadcast
specifice header-ului de ethernet*/
bool checkBroadcastAddress(u_char* macAddress)
{
	bool broadcast = true;
	int i;

	for (i = 0; i < 6; i++)
	{
		if (macAddress[i] != 0xff)
		{
			broadcast = false;
			break;
		}
	}

	return broadcast;
}

//verifica daca adresa MAC primita este adresa router-ului
bool checkMacAddress(u_char* macAddress, int interface)
{
	bool macAddresssMatch = true;
	int i;

	u_char routerMacAddress[6];

	get_interface_mac(interface, routerMacAddress);

	for (i = 0; i < 6; i++)
	{
		if (macAddress[i] != routerMacAddress[i])
		{
			macAddresssMatch = false;
			break;
		}
	}

	return macAddresssMatch;
}
