#ifndef DECODE_IP_PACKET_H_
#define DECODE_IP_PACKET_H_

#include <string>

class DecodeIPPacket
{
    int         protocol;

    std::string m_saddr,
                m_daddr,
                m_protocol,
                m_id,
                m_length;
private:
    DecodeIPPacket()=delete;
    DecodeIPPacket& operator=(const DecodeIPPacket& )=delete;
private:
    static std::string to_string_ip4_proto(const int ipproto);
public:
    DecodeIPPacket(const DecodeIPPacket& )=default;
    ~DecodeIPPacket()=default;

    bool isProtocol(const int IPPROTO);

    /// Without check on *pkthdr == nullptr !!
    explicit DecodeIPPacket(const u_char* packet);

    /// Need for task:
    std::string saddr()const;
    std::string daddr()const;

public:
    friend std::ostream&  operator <<(std::ostream& out, const DecodeIPPacket& obj);
};

#endif //DECODE_IP_PACKET_H_
