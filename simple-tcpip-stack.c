/*
 * Simple TCP/IP Stack Implementation
 * 
 * This is a minimal TCP/IP stack that demonstrates the core concepts
 * using raw sockets. It includes basic IP and TCP header construction,
 * checksum calculation, and a simple TCP client implementation.
 * 
 * IMPORTANT: This requires root/administrator privileges to run.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <netinet/ip.h>
 #include <netinet/tcp.h>
 #include <sys/socket.h>
 #include <arpa/inet.h>
 #include <errno.h>
 #include <time.h>
 
 // Packet buffer size
 #define PACKET_SIZE 4096
 
 // Pseudo header for TCP checksum calculation
 struct pseudo_header {
     uint32_t source_address;
     uint32_t dest_address;
     uint8_t placeholder;
     uint8_t protocol;
     uint16_t tcp_length;
 };
 
 // Function declarations
 uint16_t calculate_checksum(unsigned short *buf, int nwords);
 void print_ipv4_header(struct iphdr *ip);
 void print_tcp_header(struct tcphdr *tcp);
 
 // Calculate IP/TCP checksum
 uint16_t calculate_checksum(unsigned short *buf, int nwords) {
     unsigned long sum = 0;
     
     // Sum up all words in the buffer
     while (nwords > 0) {
         sum += *buf++;
         nwords--;
     }
     
     // Add carry
     sum = (sum >> 16) + (sum & 0xffff);
     sum += (sum >> 16);
     
     // Return one's complement
     return ~sum;
 }
 
 // Calculate TCP checksum including pseudo-header
 uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, char *payload, int payload_len) {
     struct pseudo_header psh;
     char *pseudogram;
     int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len;
     uint16_t checksum = 0;
     
     // Allocate memory for pseudo packet
     pseudogram = malloc(psize);
     if (pseudogram == NULL) {
         fprintf(stderr, "Memory allocation failed\n");
         exit(EXIT_FAILURE);
     }
     
     // Fill pseudo header
     psh.source_address = iph->saddr;
     psh.dest_address = iph->daddr;
     psh.placeholder = 0;
     psh.protocol = IPPROTO_TCP;
     psh.tcp_length = htons(sizeof(struct tcphdr) + payload_len);
     
     // Copy pseudo header to the buffer
     memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
     
     // Copy TCP header to the buffer
     memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
     
     // Copy payload to the buffer
     if (payload_len > 0) {
         memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), payload, payload_len);
     }
     
     // Calculate checksum
     checksum = calculate_checksum((unsigned short*)pseudogram, psize / 2);
     
     free(pseudogram);
     return checksum;
 }
 
 // Print IPv4 header information
 void print_ipv4_header(struct iphdr *ip) {
     struct in_addr source_ip, dest_ip;
     source_ip.s_addr = ip->saddr;
     dest_ip.s_addr = ip->daddr;
     
     printf("\n");
     printf("IPv4 Header\n");
     printf("   |-IP Version       : %d\n", ip->version);
     printf("   |-IP Header Length : %d DWORDS or %d Bytes\n", ip->ihl, ip->ihl * 4);
     printf("   |-Type Of Service  : %d\n", ip->tos);
     printf("   |-IP Total Length  : %d Bytes\n", ntohs(ip->tot_len));
     printf("   |-Identification   : %d\n", ntohs(ip->id));
     printf("   |-TTL              : %d\n", ip->ttl);
     printf("   |-Protocol         : %d\n", ip->protocol);
     printf("   |-Checksum         : %d\n", ntohs(ip->check));
     printf("   |-Source IP        : %s\n", inet_ntoa(source_ip));
     printf("   |-Destination IP   : %s\n", inet_ntoa(dest_ip));
 }
 
 // Print TCP header information
 void print_tcp_header(struct tcphdr *tcp) {
     printf("\n");
     printf("TCP Header\n");
     printf("   |-Source Port      : %u\n", ntohs(tcp->source));
     printf("   |-Destination Port : %u\n", ntohs(tcp->dest));
     printf("   |-Sequence Number  : %u\n", ntohl(tcp->seq));
     printf("   |-Acknowledge Number: %u\n", ntohl(tcp->ack_seq));
     printf("   |-Header Length    : %d DWORDS or %d BYTES\n", tcp->doff, tcp->doff * 4);
     printf("   |-Urgent Flag      : %d\n", tcp->urg);
     printf("   |-Acknowledgement Flag: %d\n", tcp->ack);
     printf("   |-Push Flag        : %d\n", tcp->psh);
     printf("   |-Reset Flag       : %d\n", tcp->rst);
     printf("   |-Synchronize Flag : %d\n", tcp->syn);
     printf("   |-Finish Flag      : %d\n", tcp->fin);
     printf("   |-Window           : %d\n", ntohs(tcp->window));
     printf("   |-Checksum         : %d\n", ntohs(tcp->check));
     printf("   |-Urgent Pointer   : %d\n", tcp->urg_ptr);
 }
 
 // Send a TCP SYN packet with our custom stack
 int send_syn_packet(char *src_ip, char *dst_ip, int src_port, int dst_port) {
     int sockfd;
     char datagram[PACKET_SIZE];
     struct iphdr *iph = (struct iphdr *)datagram;
     struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
     struct sockaddr_in sin;
     int one = 1;
     
     // Create a raw socket
     sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
     if (sockfd < 0) {
         perror("Socket creation failed");
         return -1;
     }
     
     // Set IP_HDRINCL to 1 so that kernel does not fill up IP header
     if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
         perror("setsockopt IP_HDRINCL failed");
         close(sockfd);
         return -1;
     }
     
     // Zero out the packet buffer
     memset(datagram, 0, PACKET_SIZE);
     
     // Fill in the IP Header
     iph->ihl = 5;
     iph->version = 4;
     iph->tos = 0;
     iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
     iph->id = htons(rand() % 65535); // Random ID
     iph->frag_off = 0;
     iph->ttl = 64;
     iph->protocol = IPPROTO_TCP;
     iph->check = 0; // Set to 0 before calculating checksum
     iph->saddr = inet_addr(src_ip);
     iph->daddr = inet_addr(dst_ip);
     
     // Calculate the IP checksum
     iph->check = calculate_checksum((unsigned short *)iph, sizeof(struct iphdr) / 2);
     
     // Fill in the TCP Header
     tcph->source = htons(src_port);
     tcph->dest = htons(dst_port);
     tcph->seq = htonl(rand()); // Random sequence number
     tcph->ack_seq = 0;
     tcph->doff = 5; // TCP header size in 32-bit words
     tcph->fin = 0;
     tcph->syn = 1; // SYN flag set
     tcph->rst = 0;
     tcph->psh = 0;
     tcph->ack = 0;
     tcph->urg = 0;
     tcph->window = htons(5840); // Maximum window size
     tcph->check = 0; // Set to 0 before calculating checksum
     tcph->urg_ptr = 0;
     
     // Calculate the TCP checksum
     tcph->check = tcp_checksum(iph, tcph, NULL, 0);
     
     // Destination information
     memset(&sin, 0, sizeof(sin));
     sin.sin_family = AF_INET;
     sin.sin_port = tcph->dest;
     sin.sin_addr.s_addr = iph->daddr;
     
     // Print the IP and TCP headers (for debugging)
     print_ipv4_header(iph);
     print_tcp_header(tcph);
     
     // Send the SYN packet
     printf("\nSending TCP SYN packet from %s:%d to %s:%d\n", 
            src_ip, src_port, dst_ip, dst_port);
            
     if (sendto(sockfd, datagram, ntohs(iph->tot_len), 0, 
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
         perror("sendto failed");
         close(sockfd);
         return -1;
     }
     
     printf("Packet sent successfully\n");
     return sockfd;
 }
 
 // Receive and parse TCP packets
 int receive_packets(int sockfd) {
     char buffer[PACKET_SIZE];
     struct iphdr *iph;
     struct tcphdr *tcph;
     struct sockaddr_in src_addr;
     socklen_t src_addr_size = sizeof(src_addr);
     int data_size;
     
     printf("\nWaiting for incoming packets...\n");
     
     // Receive packets in a loop
     while (1) {
         // Receive a packet
         data_size = recvfrom(sockfd, buffer, PACKET_SIZE, 0, 
                            (struct sockaddr *)&src_addr, &src_addr_size);
         
         if (data_size < 0) {
             perror("recvfrom failed");
             return -1;
         }
         
         // Parse IP header
         iph = (struct iphdr *)buffer;
         
         // Check if it's a TCP packet
         if (iph->protocol == IPPROTO_TCP) {
             // Parse TCP header
             tcph = (struct tcphdr *)(buffer + (iph->ihl * 4));
             
             printf("\nReceived packet from %s\n", inet_ntoa(src_addr.sin_addr));
             print_ipv4_header(iph);
             print_tcp_header(tcph);
             
             // Check if it's a response to our SYN
             if (tcph->syn == 1 && tcph->ack == 1) {
                 printf("\n*** Received SYN-ACK packet - TCP handshake in progress! ***\n");
                 
                 // Here you would normally send an ACK to complete the handshake
                 // This would be the third packet in the 3-way handshake
                 // For simplicity, we're not implementing that in this example
             }
         }
     }
     
     return 0;
 }
 
 int main(int argc, char *argv[]) {
     int sockfd;
     
     // Seed random number generator
     srand(time(NULL));
     
     // Check arguments
     if (argc != 5) {
         printf("Usage: %s <source_ip> <destination_ip> <source_port> <destination_port>\n", argv[0]);
         return 1;
     }
     
     char *src_ip = argv[1];
     char *dst_ip = argv[2];
     int src_port = atoi(argv[3]);
     int dst_port = atoi(argv[4]);
     
     // Send SYN packet
     sockfd = send_syn_packet(src_ip, dst_ip, src_port, dst_port);
     if (sockfd < 0) {
         fprintf(stderr, "Failed to send SYN packet\n");
         return 1;
     }
     
     // Receive packets
     receive_packets(sockfd);
     
     // Close socket
     close(sockfd);
     
     return 0;
 }