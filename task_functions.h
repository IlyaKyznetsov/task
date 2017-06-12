#ifndef TASK_FUNCTIONS_H_
#define TASK_FUNCTIONS_H_

#include <pcap.h>

/// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN    ETHER_MAX_LEN

/// compiled filter program (expression)
#define FILTER      "tcp port 80 or tcp port 8080 or tcp port 5000"

struct Args
{
    int     m_argc;
    char**  m_argv;

    pcap_t* &m_handle;     // packet capture handle

    Args(int argc, char **argv, pcap_t* &handle):m_argc(argc),m_argv(argv),m_handle(handle){}
private:
    Args& operator=(const Args&)=delete;
};

void pcap_handler_tcp(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void* start_routine(void* args);


#endif //TASK_FUNCTIONS_H_
