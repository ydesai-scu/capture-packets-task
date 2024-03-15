#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

void print_dest_addr(u_char *args, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    // print destination ip address and port 
    printf("Destination IP address: %d.%d.%d.%d\n", pkt_data[26], pkt_data[27], pkt_data[28], pkt_data[29]);
    printf("Destination port: %d\n", pkt_data[34]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Get a list of available devices
    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }
    pcap_if_t *interface;
    printf("Available interfaces:\n");
    for (interface = interfaces; interface != NULL; interface = interface->next) {
        printf("Interface name: %s\n", interface->name);
        if (interface->description)
            printf("Description: %s\n", interface->description);
        else
            printf("No description available\n");
        printf("\n");
    }
    // Choose a device
    device = interfaces->name;

    // Open the selected device
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, errbuf);
        return -1;
    }

    // capture all packets 
    pcap_loop(handle, -1, print_dest_addr, NULL);
    pcap_close(handle);

    // Free the device list
    pcap_freealldevs(interfaces);

    return 0;
}
