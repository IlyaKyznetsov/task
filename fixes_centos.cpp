#include "fixes_centos.h"


std::string std::to_string(uint16_t value)
{
    return std::to_string((unsigned long long)value);
}


std::string std::to_string(int16_t value)
{
    return std::to_string((long long)value);
}


std::string std::to_string(uint32_t value)
{
    return std::to_string((unsigned long long)value);
}


std::string std::to_string(int32_t value)
{
    return std::to_string((long long)value);
}
