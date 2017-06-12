#include "decode_tcp_packet.h"

#include "fixes_centos.h"

#include <string>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <ostream>

std::string DecodeTCPPacket::to_string_tcp_flags(const u_int8_t th_flags)
{
    std::string str_flags{""};
    /*
    auto add_separator = [](std::string& str_flags)
    {
        if(!str_flags.empty())
            str_flags.append(" | ");
    };
    */

    if(th_flags & TH_FIN)
    {
        if(!str_flags.empty())
            str_flags.append(" | ");
        str_flags.append("FIN");
    }
    if(th_flags & TH_SYN)
    {
        if(!str_flags.empty())
            str_flags.append(" | ");
        str_flags.append("SYN");
    }
    if(th_flags & TH_RST)
    {
        if(!str_flags.empty())
            str_flags.append(" | ");
        str_flags.append("RST");
    }
    if(th_flags & TH_PUSH)
    {
        if(!str_flags.empty())
            str_flags.append(" | ");
        str_flags.append("PUSH");
    }
    if(th_flags & TH_ACK)
    {
        if(!str_flags.empty())
            str_flags.append(" | ");
        str_flags.append("ACK");
    }
    if(th_flags & TH_URG)
    {
        if(!str_flags.empty())
            str_flags.append(" | ");
        str_flags.append("URG");
    }
    return str_flags;
}

DecodeTCPPacket::DecodeTCPPacket(const pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct tcphdr*        p_tcp_header = reinterpret_cast<const struct tcphdr*>(packet+ETHER_HDR_LEN + sizeof(struct iphdr));
    /**
    В заголовке TCP поле Data Offset (tcphdr::th_off) задает размер заголовка TCP в 32-битных словах.
    Можно вычесть: pcap_pkthdr::len - (ETHER_HDR_LEN + sizeof(struct iphdr) + 4*tcphdr::th_off)
                                                               (умноженное на 4, чтобы получить количество байтов в заголовке)
    от размера пакета (pcap_pkthdr::len), чтобы получить размер данных в TCP-пакете.
    **/

    # if __BYTE_ORDER == __LITTLE_ENDIAN
        const int tcp_header_size = 4*p_tcp_header->th_off;
    # endif
    # if __BYTE_ORDER == __BIG_ENDIAN
        const int tcp_header_size = 4*ntohs(p_tcp_header->th_off);
    # endif

    m_th_sport  = std::to_string(ntohs(p_tcp_header->th_sport));
    m_th_dport  = std::to_string(ntohs(p_tcp_header->th_dport));
    m_th_seq    = std::to_string(ntohl(p_tcp_header->th_seq));
    m_th_ack    = std::to_string(ntohl(p_tcp_header->th_ack));
    m_hdr_size  = std::to_string(tcp_header_size);
    th_flags    = p_tcp_header->th_flags;
    m_th_flags  = to_string_tcp_flags(th_flags);


    const int total_header_size = (ETHER_HDR_LEN + sizeof(struct iphdr) + tcp_header_size);
    const int     pkt_data_size = pkthdr->caplen - total_header_size;

    if(pkt_data_size > 0)
    {
        m_pkt_data.resize(pkt_data_size);

        const u_char* pkt_data_ptr = packet + total_header_size;

        std::copy(pkt_data_ptr, (pkt_data_ptr+pkt_data_size),
                  m_pkt_data.begin());
    }
}

bool DecodeTCPPacket::emptyData() const
{
    return m_pkt_data.empty();
}

const std::vector<u_char> &DecodeTCPPacket::data() const
{
    return m_pkt_data;
}

std::string DecodeTCPPacket::sport() const
{
    return m_th_sport;
}

std::string DecodeTCPPacket::dport() const
{
    return m_th_dport;
}

std::ostream &operator <<(std::ostream &out, const DecodeTCPPacket &obj)
{
    /// remove it
    if(obj.m_pkt_data.empty())
        return out;

    out << "\t\t\t{{ Layer 4 :::: TCP Header }}\n"
        << "\t\t\t{ Src Port: " << obj.m_th_sport <<   " Dest Port: " << obj.m_th_dport << "}\n"
        << "\t\t\t{ Seq #: " << obj.m_th_seq << " Ack #: " << obj.m_th_ack << "}\n"
        << "\t\t\t{ Header Size: " << obj.m_hdr_size <<   " Flags: " << obj.m_th_flags << "}\n";

    if(obj.m_pkt_data.empty())
    {
        out << "\t\t\t\tNo Data in Packet";
    }
    else
    {
        out << "\t\t\t\t" << obj.m_pkt_data.size() << " bytes of packet data";
    }
    return out;
}
