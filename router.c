#include <math.h>

#include "queue.h"
#include "skel.h"

//trie node(route)
typedef struct rtable_node {
	struct route_table_entry* entry;
	struct rtable_node* neigh0;
	struct rtable_node* neigh1;
} rtable_node;

//entry in the arp queue
typedef struct {
	packet m;
	uint32_t next_hop;
} arp_q_entry;

//global variables
queue arp_queue;
rtable_node* rtable;
struct route_table_entry routes[100000];
struct arp_entry arp_table[10];
int arp_table_size = 0;

//creates an empty node for the trie
rtable_node* new_empty_node() {
	rtable_node* new_node = malloc(sizeof(rtable_node));
	new_node->entry = NULL;
	new_node->neigh0 = NULL;
	new_node->neigh1 = NULL;

	return new_node;
}

//inserts a route in the trie routing table
void insert_route(struct route_table_entry* entry) {
	uint32_t h_prefix = ntohl(entry->prefix);
	uint32_t h_mask = ntohl(entry->mask);
	rtable_node* curr_node = rtable;

	while(h_mask)
	{
		//sorting by MSB
		if(h_prefix >= pow(2, 31))
		{
			if(!curr_node->neigh1)
				curr_node->neigh1 = new_empty_node();
			curr_node = curr_node->neigh1;

		}
		else
		{
			if(!curr_node->neigh0)
				curr_node->neigh0 = new_empty_node();
			curr_node = curr_node->neigh0;
		}

		//getting the next bit in the MSB position for analysis
		h_mask = h_mask<<1;
		h_prefix = h_prefix<<1;
	}

	//adding the entry to the found position
	curr_node->entry = entry;
}

//finds the best matching route in the trie routing table
struct route_table_entry* get_route_entry(uint32_t ip) {
	uint32_t h_ip = ntohl(ip);
	rtable_node* curr_node = rtable;
	struct route_table_entry* returned_entry = NULL;

	while(1)
	{	//updating the last found entry
		if(curr_node->entry)
			returned_entry = curr_node->entry;

		//sorting by MSB
		if(h_ip >= pow(2, 31))
		{
			if(!curr_node->neigh1)
				break;
			curr_node = curr_node->neigh1;
		}
		else
		{
			if(!curr_node->neigh0)
				break;
			curr_node = curr_node->neigh0;
		}

		//getting the next bit in the MSB position
		h_ip = h_ip<<1;
	}

	return returned_entry;
}


//checks if the arp table has the mac for the given ip and returns that mac or null otherwise
uint8_t* arp_get_mac(uint32_t ip) {

	for(int i = 0; i < arp_table_size; i++)
	{
		if(arp_table[i].ip == ip)
		{
			return arp_table[i].mac;
		}
	}

	return NULL;
}

//implements the behaviour the router has when it receives an arp reply
void recv_arp_reply(packet arp_reply_m) {
	struct arp_header* arp_h = (struct arp_header*)(arp_reply_m.payload +
								sizeof(struct ether_header));
	//updating the arp table
	arp_table[arp_table_size++].ip = arp_h->spa;
	memcpy(arp_table[arp_table_size - 1].mac, arp_h->sha, sizeof(arp_h->sha));

	//sending the packets that have been waiting an arp reply
	arp_q_entry* e;
	struct ether_header* eth_h;
	struct iphdr* ip_h;
	queue temp_queue = queue_create();
	
	while(!queue_empty(arp_queue))
	{
		e = (arp_q_entry*)queue_deq(arp_queue);
		eth_h = (struct ether_header*)e->m.payload;
		ip_h = (struct iphdr*)(e->m.payload + sizeof(*eth_h));

		//when the packet can finally be sent
		if(e->next_hop == arp_h->spa)
		{
			//modifying packet metadata
			e->m.interface = arp_reply_m.interface;

			//modifying the ethernet header
			memcpy(eth_h->ether_dhost, arp_h->sha, sizeof(arp_h->sha));
			get_interface_mac(e->m.interface, eth_h->ether_shost);

			//update checksum
			ip_h->check = 0;
			ip_h->check = ip_checksum((uint8_t*)ip_h, sizeof(*ip_h));

			send_packet(&e->m);
			free(e);
		}

		//when the packets have to be kept more time
		else
			queue_enq(temp_queue, e);
	}

	//getting back the arp queue
	while(!queue_empty(temp_queue))
		queue_enq(arp_queue, queue_deq(temp_queue));
}

//implements the behaviour of a router when it receives an arp request
void recv_arp_req(packet m) {
	struct ether_header* eth_h = (struct ether_header*)m.payload;
	struct arp_header* arp_h = (struct arp_header*)(m.payload + sizeof(struct ether_header));

	//building the arp reply
	
	//building the arp header
	arp_h->op = htons(ARPOP_REPLY);
	memcpy(arp_h->tha, arp_h->sha, sizeof(arp_h->tha));
	get_interface_mac(m.interface, arp_h->sha);
	arp_h->tpa = arp_h->spa;
	arp_h->spa = inet_addr(get_interface_ip(m.interface));

	//building the ethernet header
	eth_h->ether_type = htons(ETHERTYPE_ARP);
	memcpy(eth_h->ether_dhost, eth_h->ether_shost, sizeof(eth_h->ether_dhost));
	get_interface_mac(m.interface, eth_h->ether_shost);

	send_packet(&m);
}

//sends an icmp response to a given icmp request
void send_icmp_reply(packet m) {
	struct ether_header* eth_h = (struct ether_header*)m.payload;
	struct iphdr* ip_h = (struct iphdr*)(m.payload + sizeof(*eth_h));
	struct icmphdr* icmp_h = (struct icmphdr*)((void*)ip_h + sizeof(*ip_h));

	//updating ethernet header
	memcpy(eth_h->ether_dhost, eth_h->ether_shost, sizeof(eth_h->ether_dhost));
	get_interface_mac(m.interface, eth_h->ether_shost);

	//updating the ip header
	uint32_t swap = ip_h->daddr;
	ip_h->daddr = ip_h->saddr;
	ip_h->saddr = swap;
	ip_h->check = 0;
	ip_h->check = ip_checksum((uint8_t*)ip_h, sizeof(*ip_h));

	//updating the icmp header
	icmp_h->code = 0;
	icmp_h->type = 0;
	icmp_h->checksum = 0;
	icmp_h->checksum = icmp_checksum((uint16_t*)icmp_h, sizeof(*icmp_h));

	send_packet(&m);
}

//implements the behaviour of the router when it has to send an arp request
void send_arp_req(packet m, struct route_table_entry* rtable_entry) {
	
	//saving the packet to be sent later
	arp_q_entry *e = malloc(sizeof(*e));
	memcpy(&e->m, &m, sizeof(m));
	e->next_hop = rtable_entry->next_hop;
	queue_enq(arp_queue, e);
	
	//building the arp request

	struct ether_header* eth_h = (struct ether_header*)m.payload;
	struct arp_header* arp_h = (struct arp_header*)(m.payload + sizeof(*eth_h));

	//updating the message metadata
	m.interface = rtable_entry->interface;
	m.len = sizeof(*eth_h) + sizeof(*arp_h);
	
	//building the arp header
	arp_h->htype = htons(1);
	arp_h->ptype = htons(2048);
	arp_h->hlen = 6;
	arp_h->plen = 4;
	arp_h->op = htons(ARPOP_REQUEST);
	get_interface_mac(m.interface, arp_h->sha);
	for(int i = 0; i < 6; i++)
		arp_h->tha[i] = 0xFF;
	arp_h->spa = inet_addr(get_interface_ip(m.interface));
	arp_h->tpa = rtable_entry->next_hop;

	//building the ethernet header
	eth_h->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(m.interface, eth_h->ether_shost);
	for(int i = 0; i < 6; i++)
		eth_h->ether_dhost[i] = 0xFF;

	send_packet(&m);
}

//sends a time exceeded message
void send_time_exd(packet m) {

	struct ether_header* eth_h = (struct ether_header*)m.payload;
	struct iphdr* ip_h = (struct iphdr*)(m.payload + sizeof(*eth_h));
	struct icmphdr* icmp_h = (struct icmphdr*)((void*)ip_h + sizeof(*ip_h));

	//updating the ethernet header
	memcpy(eth_h->ether_dhost, eth_h->ether_shost, sizeof(eth_h->ether_dhost));
	get_interface_mac(m.interface, eth_h->ether_shost);

	//updating the ip header
	ip_h->daddr = ip_h->saddr;
	ip_h->saddr = inet_addr(get_interface_ip(m.interface));
	ip_h->ttl = 64;
	ip_h->tot_len = htons(sizeof(*ip_h) + sizeof(*icmp_h) + 64);
	ip_h->protocol = IPPROTO_ICMP;
	ip_h->check = 0;
	ip_h->check = ip_checksum((uint8_t*)ip_h, sizeof(struct iphdr));

	//creating the icmp header and the payload that follows it
	memcpy((void*)icmp_h + sizeof(*ip_h), icmp_h, 64);
	icmp_h->code = 0;
	icmp_h->type = 11;
	icmp_h->checksum = 0;
	icmp_h->checksum = icmp_checksum((uint16_t*)icmp_h, sizeof(icmp_h));

	m.len = sizeof(*eth_h) + sizeof(*ip_h) + sizeof(*icmp_h) + 64;
	send_packet(&m);
}

//sends a destination unreachable message
void send_dest_unreach(packet m) {
	struct ether_header* eth_h = (struct ether_header*)m.payload;
	struct iphdr* ip_h = (struct iphdr*)(m.payload + sizeof(*eth_h));
	struct icmphdr* icmp_h = (struct icmphdr*)((void*)ip_h + sizeof(*ip_h));
	
	//updating the ethernet header
	memcpy(eth_h->ether_dhost, eth_h->ether_shost, sizeof(eth_h->ether_dhost));
	get_interface_mac(m.interface, eth_h->ether_shost);

	//updating the ip header
	ip_h->daddr = ip_h->saddr;
	ip_h->saddr = inet_addr(get_interface_ip(m.interface));
	ip_h->ttl = 64;
	ip_h->tot_len = htons(sizeof(*ip_h) + sizeof(*icmp_h) + 64);
	ip_h->protocol = IPPROTO_ICMP;
	ip_h->check = 0;
	ip_h->check = ip_checksum((uint8_t*)ip_h, sizeof(struct iphdr));

	//creating the icmp header and the payload that follows it
	memcpy((void*)icmp_h + sizeof(struct icmphdr), icmp_h, 64);
	icmp_h->code = 0;
	icmp_h->type = 3;
	icmp_h->checksum = 0;
	icmp_h->checksum = icmp_checksum((uint16_t*)icmp_h, sizeof(icmp_h));

	m.len = sizeof(*eth_h) + sizeof(*ip_h) + sizeof(*icmp_h) + 64;
	send_packet(&m);
}

//implements the packet forwarding function of the router
void forward_this_packet(packet m) {
	struct ether_header* eth_h = (struct ether_header*)m.payload;
	struct iphdr* ip_h = (struct iphdr*)(m.payload + sizeof(*eth_h));
	
	//getting the matching routing table entry
	struct route_table_entry* rtable_entry = get_route_entry(ip_h->daddr);
	
	//in case of failure
	if(!rtable_entry)
	{
		send_dest_unreach(m);
		return;
	}

	//checking whether to send the packet or an arp request
	uint8_t* dest_mac = arp_get_mac(rtable_entry->next_hop);

	if(!dest_mac)
	{
		send_arp_req(m, rtable_entry);
		return;
	}

	//updating the interface
	m.interface = rtable_entry->interface;

	//calculate checksum
	ip_h->check = 0;
	ip_h->check = ip_checksum((uint8_t*)ip_h, sizeof(*ip_h));

	//update ethernet header
	get_interface_mac(m.interface, eth_h->ether_shost);
	memcpy(eth_h->ether_dhost, dest_mac, sizeof(eth_h->ether_dhost));
	
	send_packet(&m);
}


int main(int argc, char *argv[])
{
	packet m;
	struct ether_header* eth_h;
	struct iphdr* ip_h;
	struct arp_header* arp_h;
	struct icmphdr* icmp_h;

	uint8_t intf_mac[6];
	int rc;

	//initialising global variables
	arp_queue = queue_create();
	int rtable_size = read_rtable(argv[1], routes);
	rtable = new_empty_node();

	for(int i = 0; i < rtable_size; i++)
	{
		insert_route(&routes[i]);
	}

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1)
	{
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		/* TODO */
		eth_h = (struct ether_header*)m.payload;
		get_interface_mac(m.interface, intf_mac);

		//checking if the frame came for the router or if it's a broadcast message
		if(!memcmp(eth_h->ether_dhost, intf_mac, sizeof(eth_h->ether_dhost)) ||
		   !memcmp(eth_h->ether_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(eth_h->ether_dhost)))
		{
			if(eth_h->ether_type == htons(ETHERTYPE_ARP)) {
				arp_h = (struct arp_header*)(m.payload + sizeof(*eth_h));

				//trying to match the ip destination with the router's interface
				if(arp_h->tpa != inet_addr(get_interface_ip(m.interface)))
					continue;
				
				if(arp_h->op == htons(ARPOP_REPLY))
					recv_arp_reply(m);
				else if(arp_h->op == htons(ARPOP_REQUEST))
					recv_arp_req(m);
			}
			else if(eth_h->ether_type == htons(ETHERTYPE_IP))
			{
				ip_h = (struct iphdr*)(m.payload + sizeof(*eth_h));

				//checking the checksum
				if(ip_checksum((uint8_t*)ip_h, sizeof(*ip_h)))
					continue;

				//checking the tt;
				if(ip_h->ttl <= 1)
				{
					send_time_exd(m);
					continue;
				}

				//updating the ttl
				ip_h->ttl--;

				// here we' ll use rc as a flag for whether we found a match for the router's
				//ip addresses or not
				rc = 0;

				//checking whether it came for the router
				for(int i = 0; i < ROUTER_NUM_INTERFACES; i++)
					if(ip_h->daddr == inet_addr(get_interface_ip(i)))
					{
						if(ip_h->protocol == IPPROTO_ICMP)
						{
							icmp_h = (struct icmphdr*)((void*)ip_h + sizeof(*ip_h));

							if(!icmp_h->code && icmp_h->type == 8)
								send_icmp_reply(m);
						}

						rc = 1;
					}

				//in this case the packet is not for the router
				if(!rc)
					forward_this_packet(m);
			}
		}
	}
}
