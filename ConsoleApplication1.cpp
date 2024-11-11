#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <winsock2.h> // For htons, ntohs
#include <Ws2tcpip.h> // For inet_ntop

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

// Ethernet header length
#define ETHERNET_HEADER_LEN 14

// IPv4 header
struct ip_header {
    unsigned char  ip_header_len : 4;       
    unsigned char  ip_version : 4;         
    unsigned char  ip_tos;                
    unsigned short ip_total_length;       
    unsigned short ip_id;                
    unsigned short ip_off;                
    unsigned char  ip_ttl;                
    unsigned char  ip_protocol;           
    unsigned short ip_checksum;           
    struct in_addr ip_src, ip_dst;        
};

// TCP header
struct tcp_header {
    unsigned short th_sport;              
    unsigned short th_dport;
    unsigned int   th_seq;                
    unsigned int   th_ack;               
    unsigned char  th_offx2;              
    unsigned char  th_flags;              
    unsigned short th_win;               
    unsigned short th_sum;                
    unsigned short th_urp;                
};

// UDP header
struct udp_header {
    unsigned short uh_sport;             
    unsigned short uh_dport;              
    unsigned short uh_len;                
    unsigned short uh_sum;                
};

// This function is called for each captured packet.
void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    cout << "Packet captured at: " << pkthdr->ts.tv_sec << "." << pkthdr->ts.tv_usec << endl;
    cout << "Packet length: " << pkthdr->len << endl;

    // Parse Ethernet header
    const unsigned char* mac_src = packet + 6;  
    const unsigned char* mac_dst = packet;      

    cout << "Source MAC: ";
    for (int i = 0; i < 6; i++) {
        cout << hex << setw(2) << setfill('0') << (int)mac_src[i];
        if (i < 5) cout << ":";
    }
    cout << endl;

    cout << "Destination MAC: ";
    for (int i = 0; i < 6; i++) {
        cout << hex << setw(2) << setfill('0') << (int)mac_dst[i];
        if (i < 5) cout << ":";
    }
    cout << endl;

    // Check if the packet is IPv4
    unsigned short eth_type = ntohs(*(unsigned short*)(packet + 12));
    if (eth_type == 0x0800) { 
        // Parse IP header
        ip_header* ipHeader = (ip_header*)(packet + ETHERNET_HEADER_LEN);
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dst_ip, INET_ADDRSTRLEN);

        cout << "Source IP: " << src_ip << endl;
        cout << "Destination IP: " << dst_ip << endl;

        // Determine the protocol type
        if (ipHeader->ip_protocol == IPPROTO_TCP) {
            cout << "Protocol: TCP" << endl;

            int ip_header_len = ipHeader->ip_header_len * 4; 
            tcp_header* tcpHeader = (tcp_header*)(packet + ETHERNET_HEADER_LEN + ip_header_len);

            cout << "Source Port: " << ntohs(tcpHeader->th_sport) << endl;
            cout << "Destination Port: " << ntohs(tcpHeader->th_dport) << endl;

        }
        else if (ipHeader->ip_protocol == IPPROTO_UDP) {
            cout << "Protocol: UDP" << endl;

            int ip_header_len = ipHeader->ip_header_len * 4; 
            udp_header* udpHeader = (udp_header*)(packet + ETHERNET_HEADER_LEN + ip_header_len);

            cout << "Source Port: " << ntohs(udpHeader->uh_sport) << endl;
            cout << "Destination Port: " << ntohs(udpHeader->uh_dport) << endl;
        }
        else {
            cout << "Protocol: Other" << endl;
        }
    }

    cout << "----------------------------------------" << endl;
}

void capture_packets(const string& interface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the interface for capturing packets
    pcap_t* handle = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening device " << interface_name << ": " << errbuf << endl;
        return;
    }

    cout << "Starting packet capture on interface: " << interface_name << endl;

    // Capture packets (here we capture 10 packets)
    if (pcap_loop(handle, 10, packet_handler, nullptr) < 0) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
    }

    pcap_close(handle);
}

int main() {
    // List available devices
    pcap_if_t* all_devs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all_devs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    // Print available devices
    cout << "Available devices:" << endl;
    int i = 0;
    for (pcap_if_t* dev = all_devs; dev != nullptr; dev = dev->next) {
        cout << ++i << ": " << (dev->description ? dev->description : "No description") << " (" << dev->name << ")" << endl;
    }

    // Prompt the user to select a device
    int device_index;
    cout << "Enter device number to capture packets from: ";
    cin >> device_index;

    pcap_if_t* selected_device = all_devs;
    for (int j = 1; j < device_index; j++) {
        selected_device = selected_device->next;
    }

    // Capture packets from the selected device
    capture_packets(selected_device->name);

    // Free device list
    pcap_freealldevs(all_devs);

    return 0;
}
