#include <arpa/inet.h>
#include <string.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

struct arp_table_entry *arp_table;
int arp_size;
struct arp_table_entry *arp_cache;
int  cache_size;
struct route_table_entry *rtable;
int rtable_size;
struct node *trie;

struct datagram_info {
	int interface;
	int len;
	uint32_t next_hop;
	struct ether_header *packet;
};

struct node {
    struct node *one;
    struct node *zero;
    uint32_t next_hop;
    int interface;
};

uint32_t getMSB(uint32_t prefix) {
    uint32_t mask = 1;
    mask = mask << 31;
    return ((prefix & mask) >> 31);
}

// adds a route table entry data in the trie tree
void add_node(struct route_table_entry *route, struct  node *tree) {
    uint32_t addr = ntohl(route->prefix);
    struct  node *crt = tree;
    uint32_t mask = ntohl(route->mask);
    
    while(1) {
        if(mask == 0) { // if the prefix was all used, exit the loop
            crt->next_hop = route->next_hop;
            crt->interface = route->interface;
            break;
        }
        if(getMSB(addr) == 0) {
            if(!crt->zero) {
                struct node *newest = malloc(sizeof(struct node));
                newest->interface = -1;
                newest->one = NULL;
                newest->zero = NULL;
                crt->zero = newest;
            }
            crt = crt->zero;
        }
        else {
            if(!crt->one) {
                struct node *newest = malloc(sizeof(struct node));
                newest->interface = -1;
                newest->one = NULL;
                newest->zero = NULL;
                crt->one = newest;
            }
            crt = crt->one;
        }
        addr = addr << 1;
        mask = mask << 1;
    }
}

// add all the routes from the route table into the trie
struct node *build_trie(struct route_table_entry *table, int size) {
    struct node *head = malloc(sizeof(struct node));
    head->interface = -1;
    head->zero = NULL;
    head->one = NULL;

    for(int i = 0; i < size; i++)
        add_node(&table[i], head);

    return head;
}

// find the longest prefix match for the given address in the trie
struct node *find_best_route(uint32_t ip, struct node *tree) {
    uint32_t addr = ntohl(ip);
    struct node *crt = tree;
    struct node *last_found = NULL;

    for(int i = 0; i < 32 && crt != NULL; i++) {
        printf("%d \n", crt->interface);
        if(crt->interface != -1) last_found = crt;

        if(getMSB(addr) == 0) 
            crt = crt->zero;
        else 
            crt = crt->one;
        
        addr = addr << 1;
    }
    return last_found;
} 

struct queue *packets; // datagrams waiting for an ARP reply
int num_waiting; // number of waiting packets

// find the mac of the next hop
struct arp_table_entry *get_mac(uint32_t ip, struct arp_table_entry *table, int size) {
	for(int i = 0; i < size; i++) {
		if(table[i].ip == ip) return &table[i];
	}
	return NULL;
}

// build and send an icmp message with the given type and code
void send_icmp_message(struct ether_header *old_eth, uint8_t type, uint8_t code, int interf) {
	struct ether_header *eth = malloc(sizeof(struct ether_header) 
										+ sizeof(struct iphdr) 
										+ sizeof(struct icmphdr)
										+ sizeof(struct iphdr)
										+ 64);
	struct iphdr *old_ip = (struct iphdr*)(old_eth + 1);
	struct iphdr *ip_hdr = (struct iphdr*)(eth + 1);
	struct icmphdr *icmp_hdr = (struct icmphdr *)(ip_hdr + 1);
	// copying the old ip header and some old payload into the icmp payload
	memcpy((icmp_hdr + 1), old_ip, 
		(sizeof(struct iphdr) + 64) < old_ip->tot_len ? sizeof(struct iphdr) + 64 : old_ip->tot_len);
	// completion of the icmp header
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = (uint16_t) 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	// completion of the ip header
	ip_hdr->tos =(uint8_t) 0;
	ip_hdr->frag_off = htons((uint16_t)0);
	ip_hdr->protocol = (uint8_t) 1;
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->id = htons((uint16_t)1);
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 64);
	ip_hdr->saddr = inet_addr(get_interface_ip(interf));
	ip_hdr->daddr = old_ip->saddr;
	ip_hdr->ttl = (uint8_t) 64;
	ip_hdr->check = (uint16_t) 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// completion of the ethernet header
	eth->ether_type = old_eth->ether_type;
	memcpy(eth->ether_shost, old_eth->ether_dhost, 6);
	memcpy(eth->ether_dhost, old_eth->ether_shost, 6);
	
	send_to_link(interf, (char *)eth, sizeof(struct ether_header) 
										+ sizeof(struct iphdr) 
										+ sizeof(struct icmphdr)
										+ sizeof(struct iphdr)
										+ 64);
	return;
}

// building an icmp reply to an icmp echo
void deal_for_me(struct iphdr *ip_hdr) {
	struct icmphdr *header = (struct icmphdr *)(ip_hdr + 1);
	if(header->type == 8 && header->code == 0) {
		header->type = 0;
		header->checksum = 0;
		header->checksum = htons(checksum((uint16_t *)header, sizeof(struct icmphdr)));

		ip_hdr->ttl = 64;
		uint32_t source = ip_hdr->saddr;
		ip_hdr->saddr = ip_hdr->daddr;
		ip_hdr->daddr = source;

		ip_hdr->check = (uint16_t) 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	}
}

// does the necesary steps for a received ip package
void deal_IP(struct ether_header *eth_hdr, int interf, int plen) {

	struct iphdr *ip_hdr = (struct iphdr *)(eth_hdr + 1);

	if(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
		// bad checksum, drop the packet
		return;
	}

	if(ip_hdr->ttl <= 1) {
			send_icmp_message(eth_hdr, 11, 0, interf); // time exceeded
			return;
			}


	if(ip_hdr->daddr == inet_addr(get_interface_ip(interf))) {
		deal_for_me(ip_hdr); // build icmp reply

		// send the built reply
		char macold[6];
		memcpy(macold, eth_hdr->ether_dhost, 6);
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
		memcpy(eth_hdr->ether_shost, macold, 6);
		send_to_link(interf, (char *)eth_hdr, plen);
		return;
		}

		uint16_t old_ttl = (uint16_t)ip_hdr->ttl;
		uint16_t old_check = ip_hdr->check;
		ip_hdr->check = (uint16_t) 0;
		ip_hdr->ttl--;
		ip_hdr->check = ~(~old_check + ~old_ttl + (uint16_t)ip_hdr->ttl) - 1;

	// find the next hop in the trie
	struct node *route = find_best_route(ip_hdr->daddr, trie);
	if(!route) {
		send_icmp_message(eth_hdr, 3, 0, interf); // destination unreachacble
		return;
	}
	
	get_interface_mac(route->interface, eth_hdr->ether_shost);
	// get the mac of the next hop host
	struct arp_table_entry *next_mac = get_mac(route->next_hop, arp_cache, cache_size);
	
	if(!next_mac) { // next hop host is not in arp cache
		// enque the current datagram
		struct datagram_info *one = malloc(sizeof(struct datagram_info));
		one->packet = malloc(plen);
		memcpy(one->packet, eth_hdr, plen);

		one->interface = route->interface;
		one->len = plen;
		one->next_hop = route->next_hop;
		queue_enq(packets, one);
		num_waiting++;

		// build ARP request
		struct ether_header *eth_arp = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
		eth_arp->ether_type = htons(0x806);

		get_interface_mac(route->interface, eth_arp->ether_shost);
		memset(eth_arp->ether_dhost, 0xFF, 6);

		struct arp_header *arp = (struct arp_header *)(eth_arp + 1);
		arp->hlen = (uint8_t)6;
		arp->plen = (uint8_t)4;
		get_interface_mac(route->interface, arp->sha);
		arp->op = htons((uint16_t) 1);
		arp->spa = inet_addr(get_interface_ip(route->interface));
		memset(arp->tha, 0x0000, 6);
		arp->tpa = route->next_hop;
		arp->htype = htons((uint16_t) 1);
		arp->ptype = htons((uint16_t) 0x800);

		send_to_link(route->interface, (char *)eth_arp, sizeof(struct ether_header) + sizeof(struct arp_header));
		return;
	}

	memcpy(eth_hdr->ether_dhost, next_mac->mac, 6);

	send_to_link(route->interface, (char *)eth_hdr, plen);

	return;
}

// recieved an ARP packet
void deal_ARP(struct ether_header *eth_hdr, int interf, int plen) {
	struct arp_header *arpin = (struct arp_header *)(eth_hdr + 1);

	if(arpin->tpa != inet_addr(get_interface_ip(interf))) return;
	
	
	if(ntohs(arpin->op) == 1) { // recieved request
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
		get_interface_mac(interf, eth_hdr->ether_shost);		

		arpin->op = htons(2);

		uint32_t sip = arpin->spa;
		arpin->spa = arpin->tpa;
		arpin->tpa = sip;

		memcpy(arpin->tha, arpin->sha, 6);
		get_interface_mac(interf, arpin->sha);

		send_to_link(interf, (char *)eth_hdr, plen);
		return;
	}

	if(ntohs(arpin->op) == 2) { // recived reply
		arp_cache[cache_size].ip = arpin->spa;
		memcpy(&arp_cache[cache_size].mac, arpin->sha, 6);

		int crt_cache = num_waiting;
		struct datagram_info *one;

		// check all the datagrams in the queue if they can be sent 
		// with the information from the arp reply
		for(int i = 0; i < crt_cache; i++) {
			one = (struct datagram_info *)(queue_deq(packets));
			if(arp_cache[cache_size].ip == one->next_hop) {
				memcpy(one->packet->ether_dhost, arp_cache[cache_size].mac, 6);
				send_to_link(one->interface, (char *)one->packet, one->len);
				free(one->packet);
				free(one);
				num_waiting--;
			} else {
				queue_enq(packets, one);
			}
		}
		cache_size++;
		return;
	}
}



int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	arp_cache = malloc(8000 * sizeof(struct arp_table_entry));
	cache_size = 0;
	packets = queue_create();
	

	rtable = malloc(100000 * sizeof(struct route_table_entry));
	rtable_size = read_rtable(argv[1], rtable);

	trie = build_trie(rtable, rtable_size);

	free(rtable);
 
	int interface;
	size_t len;

	while (1) {


		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if (eth_hdr->ether_type == ntohs(0x0800)) deal_IP(eth_hdr, interface, len); // received an ip package
	
		if (eth_hdr->ether_type == htons(0x806)) deal_ARP(eth_hdr, interface, len); // recieved an ARP package

	}
}

