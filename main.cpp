#
#include "fixes_centos.h"

#include "task_functions.h"

#include <iostream>
#include <pthread.h>

int main(int argc, char **argv)
{
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    pcap_t *handle = nullptr;

    Args args(argc, argv, handle);

    void* p_args = &args;

    pthread_create(&tid,
                   &attr,
                   start_routine,
                   p_args);

    std::cout << "Input \"q\" to exit" << std::endl;
    char ch;
    do
    {
        std::cin >> ch;
    }while(ch!='q');

    pcap_breakloop(handle);
    pthread_join(tid, nullptr);

    ///std::cout << "Goodbye" << std::endl;

    return 0;
}

