#include "decode_ip_packet.h"

#include "fixes_centos.h"

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ostream>

std::string DecodeIPPacket::to_string_ip4_proto(const int ipproto)
{
    switch(ipproto)
    {
    case IPPROTO_IP     : return "Dummy protocol for TCP";
    case IPPROTO_IPV6   : return "IPv6 header";
    case IPPROTO_ICMP   : return "ICMP";
    case IPPROTO_TCP    : return "TCP";
    case IPPROTO_UDP    : return "UDP";
    case IPPROTO_RAW    : return "Raw IP packets";
    default             : return std::to_string(ipproto);
    }
}

bool DecodeIPPacket::isProtocol(const int IPPROTO)
{
    return protocol == IPPROTO;
}

DecodeIPPacket::DecodeIPPacket(const u_char *packet)
{
    const struct iphdr* p_ip_header = reinterpret_cast<const struct iphdr*>(packet+ETHER_HDR_LEN);

    protocol    = p_ip_header->protocol;

    m_saddr     = (inet_ntoa(in_addr{p_ip_header->saddr}));
    m_daddr     = (inet_ntoa(in_addr{p_ip_header->daddr}));
    m_protocol  = to_string_ip4_proto(p_ip_header->protocol);
    m_id        = std::to_string(ntohs(p_ip_header->id));

#if __BYTE_ORDER == __LITTLE_ENDIAN
    m_length    = std::to_string(p_ip_header->ihl);
#elif __BYTE_ORDER == __BIG_ENDIAN
    m_length    = std::to_string(ntohs(p_ip_header->ihl));
#else
# error	"Please fix <bits/endian.h>"
#endif
}

std::ostream &operator <<(std::ostream &out, const DecodeIPPacket &obj)
{
    out << "\t\t(( Layer 3 ::: IP Header ))\n"
        << "\t\t( Source: " << obj.m_saddr <<  " Dest: " << obj.m_daddr << ")\n"
        << "\t\t( Protocol: " << obj.m_protocol << " ID: " << obj.m_id << " Length: " << obj.m_length
        << ")"<<std::endl;
}


std::string DecodeIPPacket::saddr() const
{
    return m_saddr;
}

std::string DecodeIPPacket::daddr() const
{
    return m_daddr;
}
