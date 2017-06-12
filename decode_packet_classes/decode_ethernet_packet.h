#ifndef DECODE_ETHERNET_PACKET_H_
#define DECODE_ETHERNET_PACKET_H_

#include <string>
#include <netinet/if_ether.h>

class DecodeEthernetPacket
{
    std::string m_ether_shost,
                m_ether_dhost,
                m_type;

/// Deleted methods:
private:
    DecodeEthernetPacket()=delete;
    DecodeEthernetPacket& operator=(const DecodeEthernetPacket& )=delete;

/// Default methods:
public:
    DecodeEthernetPacket(const DecodeEthernetPacket& )=default;
    ~DecodeEthernetPacket()=default;

/// Static internal functions:
private:
    static std::string to_string_ether_host(const u_int8_t  ether_host[ETH_ALEN]);

public:
    /// Without check on *pkthdr == nullptr !!
    explicit DecodeEthernetPacket(const u_char* packet);

    friend std::ostream&  operator <<(std::ostream& out, const DecodeEthernetPacket& obj);
};

#endif //DECODE_ETHERNET_PACKET_H_
