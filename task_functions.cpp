#include "task_functions.h"

#include "fixes_centos.h"

#include "decode_packet_classes/decode_ethernet_packet.h"
#include "decode_packet_classes/decode_tcp_packet.h"
#include "decode_packet_classes/decode_ip_packet.h"

#include "decode_packet_classes/decode_tcp_data_classes/decode_http_request.h"

#include <iostream>
#include <fstream>
#include <iomanip>

#include <arpa/inet.h>

std::ofstream out, log_out;

void pcap_handler_tcp(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    log_out << "==[ Layer 1 :: Packet Captured               ]===========================\n"
            << "==[ Packet Length: "  << std::setw(4) << pkthdr->len
            <<     " Captured Length: " << std::setw(4) << pkthdr->caplen << "]"
            << std::endl;

    ///With Classes version--------------------------------------------------------
    if( nullptr != pkthdr             &&
        pkthdr->caplen > 0            &&
        nullptr != packet)
    {
        if(pkthdr->len != pkthdr->caplen && ETHER_MAX_LEN == pkthdr->caplen)
        {
            log_out << DecodeEthernetPacket(packet)
                    << DecodeIPPacket(packet)
                    << DecodeTCPPacket(pkthdr,packet)
                    << "\n\t\t\t\t\t\t\tNot Full Packet" << std::endl;
        }
        else
        {
            const DecodeIPPacket    ip(packet);
            const DecodeTCPPacket   tcp(pkthdr, packet);

            log_out << DecodeEthernetPacket(packet)
                    << ip
                    << tcp << std::endl;
            if(!tcp.emptyData())
            {
                DecodeHTTPRequest http(tcp.data());

                log_out << http << std::endl;

                /*
                src_ip:src_port
                dst_ip:dst_port
                URL
                hostname
                */

                if(!http.empty())
                {
                    out << "Source: " << ip.saddr()  << ":" <<tcp.sport() << "\n"
                        << "Dest  : " << ip.daddr()  << ":" <<tcp.dport() << "\n"
                        << "URL   : " << http.URL()  << "\n"
                        << "Host  : " << http.host() << "\n"
                        << "--------------------------------------------------------" << std::endl;
                }
            }
        }
    }
    log_out << "=========================================================================\n"<<std::endl;


}

void *start_routine(void *args)
{
    const Args* p_args = reinterpret_cast<Args*>(args);
    int argc    = p_args->m_argc;
    char **argv = p_args->m_argv;
    pcap_t* &handle = p_args->m_handle;     // packet capture handle



    char *dev = nullptr;                    // capture device name
    char errbuf[PCAP_ERRBUF_SIZE];          // error buffer
    bpf_u_int32 mask;                       // subnet mask
    bpf_u_int32 net;                        // ip

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

    /// open files
    out.open("out.txt", std::ios_base::out | std::ios_base::trunc);
    log_out.open("debug.log", std::ios_base::out | std::ios_base::trunc);

    /// now we can set our callback function
    pcap_loop(handle, num_caption_packets, pcap_handler_tcp, NULL);

    /// cleanup
    pcap_freecode(&filter_program);
    pcap_close(handle);

    /// close files
    out.close();
    log_out.close();
}
