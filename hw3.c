#include<stdio.h>
#include<time.h>
#include<pcap.h>
#include<stdlib.h>
#include<arpa/inet.h>
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN  6


/* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;      /* version << 4 | header length >> 2 */
        u_char ip_tos;      /* type of service */
        u_short ip_len;     /* total length */
        u_short ip_id;      /* identification */
        u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
        u_char ip_ttl;      /* time to live */
        u_char ip_p;        /* protocol */
        u_short ip_sum;     /* checksum */
        struct in_addr ip_src;
        struct in_addr ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)        (((ip)->ip_vhl) >> 4)

    /* TCP header */
    struct sniff_tcp {
        u_short th_sport;   /* source port */
        u_short th_dport;   /* destination port */
        u_int th_seq;       /* sequence number */
        u_int th_ack;       /* acknowledgement number */

        u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;     /* window */
        u_short th_sum;     /* checksum */
        u_short th_urp;     /* urgent pointer */
};

int main(int argc, char *argv[])
{

    //get file
     char *filename = argv[1];

     //error buffer
     char errbuff[PCAP_ERRBUF_SIZE];

     //open file and create pcap handler
     pcap_t * handler = pcap_open_offline(filename, errbuff);

     //The header that pcap gives us
    struct pcap_pkthdr *header;

    //The actual packet 
    const u_char *packet;   

      int packetCount = 0;
      int i;
      struct tm *arrival;
      time_t tt;
      char hour[5]="00";
      char *filter_exp=argv[2];
      bpf_u_int32 net;
      struct bpf_program fp;

      //tcp info
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    u_int size_ip;
    u_int size_tcp;


    if(pcap_compile(handler,&fp,filter_exp,0,PCAP_NETMASK_UNKNOWN)==-1){
	    fprintf(stderr,"Couldn't parse filter %s: %s\n",filter_exp,pcap_geterr(handler));
	    exit(1);
    }
    if(pcap_setfilter(handler,&fp)==-1){
	    fprintf(stderr,"Couldn't install filter %s: %s\n",filter_exp,pcap_geterr(handler));
	    exit(1);
    }
    while (pcap_next_ex(handler, &header, &packet) >= 0)
    {
        // Show the packet number
        printf("Packet # %i\n", ++packetCount);

        // Show the size in bytes of the packet
        printf("Packet size: %d bytes\n", header->len);

        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);

        // Show Epoch Time
	arrival=localtime(&(header->ts.tv_sec));
	if(arrival->tm_hour==0)
		printf("%i/%i/%i  %s:%i:%i.%d\n",1900+arrival->tm_year,arrival->tm_mon+1,arrival->tm_mday,hour,arrival->tm_min,arrival->tm_sec,header->ts.tv_usec);
	else
		printf("%i/%i/%i  %i:%i:%i.%d\n",1900+arrival->tm_year,arrival->tm_mon+1,arrival->tm_mday,arrival->tm_hour,arrival->tm_min,arrival->tm_sec,header->ts.tv_usec);
        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
/*        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            exit(1);
        }*/
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp=TH_OFF(tcp)*4;

        printf("src address: %s  ",  inet_ntoa(ip->ip_src));
	printf("dst address: %s \n",inet_ntoa(ip->ip_dst));

        printf("src port: %d ", ntohs(tcp->th_sport));
	printf("dst port: %d\n",ntohs(tcp->th_dport));
  //      printf("seq number: %d ack number: %d \n", ntohl(tcp-> th_seq), ntohl(tcp->th_ack));

        // Add two lines between packets
        printf("\n");
    }
    return 0;
}
