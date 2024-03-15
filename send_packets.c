#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>


#define MAX_PACKET_SIZE 65535


void send_packet(pcap_t *handle, const char *packet, int size){
    if(pcap_sendpacket(handle, (const u_char *)packet, size) != 0){
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char packet[MAX_PACKET_SIZE];
    int packet_size;

    printf("--- Send Packet using libpcap ---\n");
    char *dest_ip   ;
    int dest_port, source_port;
    printf("Destination IP: ");

    // get destination ip and port from the user
    scanf("%s", dest_ip);
    printf("Destination Port: ");
    scanf("%d", &dest_port);
    printf("Source Port: ");
    scanf("%d", &source_port);

    char *source_ip = pcap_lookupdev(errbuf);
    if (source_ip == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return EXIT_FAILURE;
    }
   

    pcap_t *handle = pcap_open_live("wlp2s0", MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // IP header
    ip_header = (struct iphdr *)packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header->id = htons(54321);
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(source_ip);
    ip_header->daddr = inet_addr(dest_ip);

    // TCP header
    tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp_header->source = htons(source_port);
    tcp_header->dest = htons(dest_port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->syn = 1;
    tcp_header->window = htons(5840);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

    send_packet(handle, packet, packet_size);

    pcap_close(handle);

    return EXIT_SUCCESS;
}