#include <pcap.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <sstream>
#include <cstring>
#include <iostream>

# if __BYTE_ORDER == __LITTLE_ENDIAN
    #define tcp_hdr_len(tcp_hdr) 4*tcp_hdr->th_off
# elif __BYTE_ORDER == __BIG_ENDIAN
    #define tcp_hdr_len(tcp_hdr) 4*ntohs(tcp_hdr->th_off)
#else
    #error
# endif

/** For Empty UDP and TCP packet
    Size of Ethernet frame - 24 Bytes
    Size of IPv4 Header (without any options) - 20 bytes
    Size of TCP Header (without any options) - 20 Bytes
    So total size of empty TCP datagram - 24 + 20 + 20 = 64 bytes

    Size of UDP header - 8 bytes
    So total size of empty UDP datagram - 24 + 20 + 8 = 52 bytes **/

#define IP_HDR_LEN_MIN  20

constexpr int MIN_HTTP_REQUEST_LEN = strlen("GET / HTTP/1.1\r\n");

constexpr int constexpr_strlen(const char* str)
{
    return strlen(str);
}

#define METHODS 2
const static std::string method[METHODS]={"GET", "POST"
                                            //"OPTIONS", "HEAD", "PUT", "DELETE", "TRACE", "CONNECT"
                                         };


void pcap_handler_tcp(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    if( nullptr == pkthdr   ||  !ETHER_IS_VALID_LEN(pkthdr->len)    ||  nullptr == packet)
        return; ///Bad Packet

    ///Decode IP Frame Section:
    int ip_hdr_len = 0;

    struct iphdr*   ip4_hdr = nullptr;
    struct ip6_hdr* ip6_hdr = nullptr;

    /// Switch Ethernet packet type:
    switch(ntohs(((const struct ether_header*)packet)->ether_type))
    {
    case ETHERTYPE_IP :
    {
        ip4_hdr = (struct iphdr*)(packet + ETHER_HDR_LEN);
        ip_hdr_len = ip4_hdr->ihl*4;
    }
    break;
    case ETHERTYPE_IPV6 :
    {
        ip6_hdr = (struct ip6_hdr*)(packet + ETHER_HDR_LEN);
        ip_hdr_len = sizeof(struct ip6_hdr);
    }
    break;
    }


    if(ip_hdr_len < IP_HDR_LEN_MIN)
        return; ///Invalid IP header length


    const struct tcphdr* tcp_hdr = ((const struct tcphdr*)(packet + ETHER_HDR_LEN + ip_hdr_len));

    const u_char* pkt_data = (u_char*)(packet + ETHER_HDR_LEN + ip_hdr_len + tcp_hdr_len(tcp_hdr));
    const int pkt_data_size = pkthdr->caplen - (ETHER_HDR_LEN + ip_hdr_len + tcp_hdr_len(tcp_hdr));



    ///1) brute check min data-length in tcp-frame
    /*
    if(pkt_data_size < 0)
        return;
    */
    if(pkt_data_size < MIN_HTTP_REQUEST_LEN)
        return;

    ///2) brute check on first keyword:
    int meth_indx=0;
    for( ;  meth_indx<METHODS &&
            0!=strncmp((const char*)(pkt_data), method[meth_indx].data(), constexpr_strlen(method[meth_indx].data())) ; ++meth_indx);
    if(METHODS == meth_indx)
        return;

    ///------------------------------------------------------------------------------------------------------------------------------
    ///Whis Packet may be GET or POST HTTP Request:

    ///3) parse:
    std::istringstream iss(std::string((const char*)pkt_data, pkt_data_size));
    std::string str_meth, str_uri, str_proto, str_key_word,  str_hostname;

    //Dark magic!!
    if(!(iss>>str_meth>>str_uri>>str_proto>>str_key_word>>str_hostname))
        return;

    std::string::size_type pos = str_uri.find('?');
    if(std::string::npos != pos)
        str_uri.resize(pos);

    char buffer[INET_ADDRSTRLEN];

    if(ip4_hdr != nullptr)
    {
        std::cout << "src: "
                  << inet_ntoa(in_addr{ip4_hdr->saddr})
                  << " : "
                  << ntohs(tcp_hdr->th_sport) << "\n"
                  << "des: "
                  << inet_ntoa(in_addr{ip4_hdr->daddr})
                  << " : "
                  << ntohs(tcp_hdr->th_dport) << "\n"
                  << "URL: "
                  << str_uri << "\n"
                  << "hostname: "
                  << str_hostname
                  <<  std::endl;
    }
    else if(ip6_hdr != nullptr)
    {
        std::cout << "src: "
                  << inet_ntop(AF_INET6, &ip6_hdr->ip6_src, buffer, sizeof(buffer))
                  << " : "
                  << ntohs(tcp_hdr->th_sport) << "\n"
                  << "des: "
                  << inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, buffer, sizeof(buffer))
                  << " : "
                  << ntohs(tcp_hdr->th_dport) << "\n"
                  << "URL: "
                  << str_uri << "\n"
                  << "hostname: "
                  << str_hostname
                  <<  std::endl;
    }
    ///------------------------------------------------------------------------------------------------------------------------------
}


/// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN    ETHER_MAX_LEN

/// compiled filter program (expression)
#define FILTER "tcp port 80 or tcp port 8080"

int main(int argc, char **argv)
{
    char *dev = nullptr;                    // capture device name
    char errbuf[PCAP_ERRBUF_SIZE];          // error buffer
    bpf_u_int32 mask;                       // subnet mask
    bpf_u_int32 net;                        // ip
    pcap_t* handle;                         // packet capture handle

    const char filter_expr_src[] = FILTER;
    struct bpf_program filter_program;      // compiled filter program (expression)

    int num_caption_packets = -1;           // number of packets to capture: -1 -- unlimited


    /// check for capture device name on command-line
    if (argc == 2)
    {
        dev = argv[1];
    }
    else if (argc > 2)
    {
        std::cerr << "error: unrecognized command-line options" << std::endl;
        exit(EXIT_FAILURE);
    }
    else
    {
        /// find a capture device if not specified on command-line
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
        {
            std::cerr << "Couldn't find default device: " << errbuf << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    /// get network number and mask associated with capture device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        std::cerr << "Couldn't get netmask for device " << dev << ": " << errbuf << std::endl;
        net = mask = 0;
    }

    /// open capture device
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    /// compile the filter expression
    if (pcap_compile(handle, &filter_program, filter_expr_src, 0, net) == -1)
    {
        std::cerr << "Couldn't parse filter "
                  << filter_expr_src
                  << ": "
                  << pcap_geterr(handle) <<std::endl;
        exit(EXIT_FAILURE);
    }

    /// apply the compiled filter
    if (pcap_setfilter(handle, &filter_program) == -1)
    {
        std::cerr << "Couldn't install filter %s: %s\n"
                  << filter_expr_src
                  << ": "
                  << pcap_geterr(handle) <<std::endl;
        exit(EXIT_FAILURE);
    }

    /// print capture info
    std::cout << "IP  : " << inet_ntoa(in_addr{net}) << std::endl;
    std::cout << "Mask: " << inet_ntoa(in_addr{mask}) << std::endl;

    /// now we can set our callback function
    pcap_loop(handle, num_caption_packets, pcap_handler_tcp, NULL);

    /// cleanup
    pcap_freecode(&filter_program);
    pcap_close(handle);

    return 0;
}
