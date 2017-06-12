#ifndef DECODE_TCP_PACKET_H_
#define DECODE_TCP_PACKET_H_

#include <string>
#include <vector>

class DecodeTCPPacket
{
    u_int8_t    th_flags;

    std::string m_th_sport,
                m_th_dport,
                m_th_seq,
                m_th_ack,
                m_hdr_size,
                m_th_flags;

    std::vector<u_char> m_pkt_data;

private:
    DecodeTCPPacket()=delete;
    DecodeTCPPacket(const DecodeTCPPacket& )=delete;
    DecodeTCPPacket& operator=(const DecodeTCPPacket& )=delete;
private:
    static std::string to_string_tcp_flags(const u_int8_t th_flags);

public:
    /// Without check on *pkthdr == nullptr !!
    explicit DecodeTCPPacket(const struct pcap_pkthdr *pkthdr, const u_char* packet);
    ~DecodeTCPPacket()=default;

    bool emptyData() const;
    const std::vector<u_char>& data()const;

    /// Need for task:
    std::string sport()const;
    std::string dport()const;

public:
    friend std::ostream&  operator <<(std::ostream& out, const DecodeTCPPacket& obj);
};


#endif //DECODE_TCP_PACKET_H_
