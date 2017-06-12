#include "decode_ethernet_packet.h"

#include "fixes_centos.h"

#include <ostream>

std::string DecodeEthernetPacket::to_string_ether_host(const u_int8_t ether_host[])
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

DecodeEthernetPacket::DecodeEthernetPacket(const u_char *packet)
{
    const struct ether_header*  p_ethernet_header = reinterpret_cast<const struct ether_header*>(packet);
    m_ether_shost = to_string_ether_host(p_ethernet_header->ether_shost);
    m_ether_dhost = to_string_ether_host(p_ethernet_header->ether_dhost);
    m_type = std::to_string(p_ethernet_header->ether_type);
}

std::ostream &operator <<(std::ostream &out, const DecodeEthernetPacket &obj)
{
    out << "\t[[ Layer 2 :: Ethernet Header ]]\n"
        << "\t[ Source: " << obj.m_ether_shost
        <<  " Dest: " << obj.m_ether_shost
        <<  " Type: " << obj.m_type
        << " ]" << std::endl;
    return out;
}
