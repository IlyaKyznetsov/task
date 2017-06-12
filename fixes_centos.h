#ifndef FIXES_CENTOS_H_
#define FIXES_CENTOS_H_

#define __FAVOR_BSD         //for th_* names

#ifndef nullptr
#define nullptr 0
#endif

#include <string>

namespace std
{
    std::string to_string(uint16_t value);
    std::string to_string(int16_t value);
    std::string to_string(uint32_t value);
    std::string to_string(int32_t value);
}

#endif
