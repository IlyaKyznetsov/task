//#include "sample.h"

#include <pcap.h>

#include <iostream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef LOG
#define _print(a) {std::cout << #a <<" : "<< a << std::endl;}
#define _log {std::cout << __PRETTY_FUNCTION__ << std::endl;}
#else
#define _print(a)
#define _log
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#include <curlpp/Easy.hpp>
#include <curlpp/cURLpp.hpp>
#include <curlpp/Types.hpp>

#include <curl/curl.h>
#include <curl/easy.h>

#include <map>

#include <regex>

class HTTPRequestHeader
{
    #define HEADERS 7
    const static std::string request_fields[HEADERS];
    enum Headers
    {

    };

    /// Start line
    std::string //Request-Line: GET /index.html HTTP/1.1
                m_method,
                m_URI,
                m_httpVersion,
    /// Headers
                m_host,           //127.0.0.1:5000
                m_userAgent,      //Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0
                m_acceptLanguage,
                m_acceptEncoding,
                m_connection,
                m_upgradeInsecureRequests;

    std::map<std::string, std::string> m_headers;
    public:
        HTTPRequestHeader()=default;
        HTTPRequestHeader(const std::string req)
        {
            /*
            size_t pos = req.find(std::string("GET"));
            if(pos==std::string::npos)
            {
                pos = req.find(std::string("POST"));
                if(pos==std::string::npos)
                {
                    throw "Error";
                }
                else
                {
                    m_method = "POST";
                }
            }
            else
            {
                m_method = "GET";
            }

            pos++;
            size_t pos2 = req.find(std::string("HTTP"),pos);
            std::cout <<  req <<std::endl;
            */
        }

        int parse(const std::string req)
        {
            std::string::size_type posStart = 0,
                                   posEnd;
            const std::string end{"\r\n"};

            for (size_t i=0 ; i<HEADERS ; ++i)
            {
                posStart = req.find(request_fields[i]);
                if(posStart!=std::string::npos)
                {
                    posStart+=(request_fields[i].length()+2); //2 = len(": ")
                    posEnd = req.find(end, posStart);
                    if(posEnd!=std::string::npos)
                    {
                        m_headers.insert(std::pair<std::string,std::string>(request_fields[i],req.substr(posStart, posEnd-posStart)));
                    }
                }
            }
/*
            for(const auto& v : m_headers)
            {
                std::cout << v.second << std::endl;
            }
*/
        }

};

const std::string HTTPRequestHeader::request_fields[]={"Host",
                                                       "User-Agent",
                                                       "Accept",
                                                       "Accept-Language",
                                                       "Accept-Encoding",
                                                       "Connection",
                                                       "Upgrade-Insecure-Requests"};

std::string to_string_ether_host(const u_int8_t  ether_host[ETH_ALEN])
{
    std::string eth_addr_src;
    eth_addr_src.resize(3*ETH_ALEN-1);
    sprintf(&eth_addr_src[0], "%02x", ether_host[0]);
    for(int i=1, j=3 ; i<ETH_ALEN ; ++i, j+=3)
    {
        eth_addr_src[j-1]=':';
        sprintf(&eth_addr_src[j], "%02x", ether_host[i]);
    }
    return eth_addr_src;
}

std::string to_string_ip4_addr(const u_int32_t addr)
{
    return std::string(inet_ntoa(in_addr{addr}));
}

std::string to_string_ip4_proto(const int ipproto)
{
    switch(ipproto)
    {
        case IPPROTO_IP     : return "Dummy protocol for TCP";
        case IPPROTO_IPV6   : return "IPv6 header";
        case IPPROTO_ICMP   : return "ICMP";
        case IPPROTO_TCP    : return "TCP";
        case IPPROTO_UDP    : return "UDP";
        case IPPROTO_RAW    : return "Raw IP packets";
        default : std::to_string(ipproto);
    }
}

/// Перехватчик tcp-пакетов
void pcap_handler_tcp(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    _log;

    #ifdef LOG
    for(bpf_u_int32 i=0 ; i<pkthdr->len ; ++i)
    {
            if(isprint(packet[i]))                          /* Проверка, является ли символ печатаемым */
                printf("%c ",packet[i]);                    /* Печать символа */
            else
                printf(" . ",packet[i]);                    /* Если символ непечатаемый, вывод . */
            if((i%16==0 && i!=0) || i==pkthdr->len-1)
                printf("\n");
    }
    #endif

    std::cout << "pkthdr->len = " << pkthdr->len
              << "pkthdr->caplen = " << pkthdr->caplen << std::endl;
    /*
    uint32_t src_ip=0,
             src_port=0;
    uint32_t dst_ip=0,
             dst_port=0;
    std::string URL={};
    std::string hostname={};
    */

    /*
    /// 10Mb/s ethernet header
    struct ether_header
    {
      u_int8_t  ether_dhost[ETH_ALEN];	// destination eth addr
      u_int8_t  ether_shost[ETH_ALEN];	// source ether addr
      u_int16_t ether_type;		        // packet type ID field
    } __attribute__ ((__packed__));
    */


    const int   offset_eth_header  = 0,
                offset_ip_header   = ETHER_HDR_LEN,
                offset_tcp_header  = ETHER_HDR_LEN + sizeof(struct iphdr),
                offset_icmp_header = ETHER_HDR_LEN + sizeof(struct icmphdr);

    const struct ether_header*  p_ethernet_header = reinterpret_cast<const struct ether_header*>(packet+offset_eth_header);
    const struct iphdr*         p_ip_header = reinterpret_cast<const struct iphdr*>(packet+offset_ip_header);

    const struct tcphdr*        p_tcp_header = reinterpret_cast<const struct tcphdr*>(packet+offset_tcp_header);
    const struct icmphdr*       p_icmp_header = reinterpret_cast<const struct icmphdr*>(packet+offset_icmp_header);

    /// Размер_данных_в_пакете = размер_всего_пакета - размер_заголовка
    //int pkt_data_length = pkthdr->len - total_header_size;

/*
    if(nullptr == p_ethernet_header || !ETHER_IS_VALID_LEN(p_ethernet_header))
    {
        std::cout << "(nullptr == p_ethernet_header || !ETHER_IS_VALID_LEN(*p_ethernet_header))" <<std::endl;
    }
*/
    /// decode ethernet
    _print(to_string_ether_host(p_ethernet_header->ether_shost)); //MAC src
    _print(to_string_ether_host(p_ethernet_header->ether_dhost)); //MAC dst

    /// decode ip
    _print(to_string_ip4_proto(p_ip_header->protocol));
    _print(to_string_ip4_addr(p_ip_header->saddr));
    _print(to_string_ip4_addr(p_ip_header->daddr));
    _print(p_ip_header->id);


    /// decode tcp if iphdr->protocol == IPPROTO_TCP
    p_tcp_header->th_sport; //Порт отправителя
    p_tcp_header->th_dport; //Порт получателя

    _print(ntohs(p_tcp_header->th_sport)); //Порт корректный
    _print(ntohs(p_tcp_header->th_dport)); //Порт корректный

    _print(ntohl(p_tcp_header->th_seq));
    _print(ntohl(p_tcp_header->th_ack));

    /// check it --------------------------------------------
    /**
        В заголовке TCP поле Data Offset задает размер заголовка TCP в 32-битных словах.
        Опять же, вы можете вычесть число (умноженное на 4, чтобы дать вам количество байтов в заголовке)
        от размера TCP-пакета, который вы рассчитали ранее, чтобы получить размер данных в TCP-пакете.
    **/
    const int tcp_header_size = 4*p_tcp_header->th_off;
    _print(tcp_header_size);
    /// -----------------------------------------------------

    if(p_tcp_header->th_flags & TH_FIN)
    {
        //std::cout << " FIN";
    }
    if(p_tcp_header->th_flags & TH_SYN)
    {
        //std::cout << " SYN";
    }
    if(p_tcp_header->th_flags & TH_RST)
    {
        //std::cout << " RST";
    }
    if(p_tcp_header->th_flags & TH_PUSH)
    {
        //std::cout << " PUSH";
    }
    if(p_tcp_header->th_flags & TH_ACK)
    {
        //std::cout << " ACK";
    }
    if(p_tcp_header->th_flags & TH_URG)
    {
        //std::cout << " URG";
    }
    //std::cout << std::endl;


    if(pkthdr->len == pkthdr->caplen)
    {
        /// Пакет захвачен целиком
    }

    const int total_header_size = (ETHER_HDR_LEN + sizeof(struct iphdr) + tcp_header_size);
    const u_char* pkt_data_ptr  = packet + total_header_size;
    const int     pkt_data_size = pkthdr->len - total_header_size;

    static uint pac_num=1;

    if(pkt_data_size > 0)
    {
        //std::cout << pac_num++ << " : ";
        //std::cout << pkt_data_ptr << std::endl;
        HTTPRequestHeader h;
        h.parse(std::string((char*)pkt_data_ptr, pkt_data_size));

    }
    else
    {
        //std::cout << "No Data in Packet" << std::endl;
    }


    /*
    /// TCP header.
    /// Per RFC 793, September, 1981.
    struct tcphdr
      {
        __extension__ union
        {
          struct
          {
        u_int16_t th_sport;		// source port
        u_int16_t th_dport;		// destination port
        tcp_seq th_seq;         // sequence number
        tcp_seq th_ack;         // acknowledgement number
    # if __BYTE_ORDER == __LITTLE_ENDIAN
        u_int8_t th_x2:4;		// (unused)
        u_int8_t th_off:4;		// data offset
    # endif
    # if __BYTE_ORDER == __BIG_ENDIAN
        u_int8_t th_off:4;		// data offset
        u_int8_t th_x2:4;		// (unused)
    # endif
        u_int8_t th_flags;
    # define TH_FIN	0x01
    # define TH_SYN	0x02
    # define TH_RST	0x04
    # define TH_PUSH	0x08
    # define TH_ACK	0x10
    # define TH_URG	0x20
        u_int16_t th_win;		// window
        u_int16_t th_sum;		// checksum
        u_int16_t th_urp;		// urgent pointer
          };
          struct
          {
        u_int16_t source;
        u_int16_t dest;
        u_int32_t seq;
        u_int32_t ack_seq;
    # if __BYTE_ORDER == __LITTLE_ENDIAN
        u_int16_t res1:4;
        u_int16_t doff:4;
        u_int16_t fin:1;
        u_int16_t syn:1;
        u_int16_t rst:1;
        u_int16_t psh:1;
        u_int16_t ack:1;
        u_int16_t urg:1;
        u_int16_t res2:2;
    # elif __BYTE_ORDER == __BIG_ENDIAN
        u_int16_t doff:4;
        u_int16_t res1:4;
        u_int16_t res2:2;
        u_int16_t urg:1;
        u_int16_t ack:1;
        u_int16_t psh:1;
        u_int16_t rst:1;
        u_int16_t syn:1;
        u_int16_t fin:1;
    # else
    #  error "Adjust your <bits/endian.h> defines"
    # endif
        u_int16_t window;
        u_int16_t check;
        u_int16_t urg_ptr;
          };
        };
    };
    */



}


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main(int argc, char **argv)
{
/// Разобраться что это за зверье
    char *dev = NULL;                   /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    bpf_u_int32 mask;                   /* subnet mask */
    bpf_u_int32 net;                    /* ip */

    pcap_t *handle;                     /* packet capture handle */

    //char filter_expr_src[] = "tcp port 80 or tcp port 8080";		/* filter expression*/
    //const char filter_expr_src[] = "src host (192.168.20.1 or 192.168.20.2) and (tcp or icmp)";
    const char filter_expr_src[] = "";
    struct bpf_program filter_program;                              /* compiled filter program (expression) */

    int num_caption_packets = -1;       /* number of packets to capture: -1 -- unlimited */


    /* check for capture device name on command-line */
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
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL)
        {
            std::cerr << "Couldn't find default device: " << errbuf << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        std::cerr << "Couldn't get netmask for device " << dev << ": " << errbuf << std::endl;
        net = 0;
        mask = 0;
    }

    /* print capture info */
    std::cout << "IP  : " << inet_ntoa(in_addr{net}) << std::endl;
    std::cout << "Mask: " << inet_ntoa(in_addr{mask}) << std::endl;

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    /// Компилляция фильтра пакетов и его применение к handle
    /* compile the filter expression */
    if (pcap_compile(handle, &filter_program, filter_expr_src, 0, net) == -1)
    {
        std::cerr << "Couldn't parse filter "
                  << filter_expr_src
                  << ": "
                  << pcap_geterr(handle) <<std::endl;
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &filter_program) == -1)
    {
        std::cerr << "Couldn't install filter %s: %s\n"
                  << filter_expr_src
                  << ": "
                  << pcap_geterr(handle) <<std::endl;
        exit(EXIT_FAILURE);
    }
    /// -----------------------------------------------------

    /* now we can set our callback function */
    pcap_loop(handle, num_caption_packets, pcap_handler_tcp, NULL);

    /* cleanup */
    pcap_freecode(&filter_program);
    pcap_close(handle);

    printf("\nCapture complete.\n");


    return 0;
}

