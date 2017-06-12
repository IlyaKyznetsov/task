#include "decode_http_request.h"

#include <string>
#include <iostream>

#include <algorithm>

const std::string DecodeHTTPRequest::method[METHODS]={"POST","GET"};

const std::string DecodeHTTPRequest::protocol[PROTOCOLS]={"HTTP/1.0", "HTTP/1.1"};

const std::string DecodeHTTPRequest::request_fields[]={"Host",
                                                       "User-Agent",
                                                       "Accept",
                                                       "Accept-Language",
                                                       "Accept-Encoding",
                                                       "Connection",
                                                       "Upgrade-Insecure-Requests"};

/// request smaple: req = "GET / HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
DecodeHTTPRequest::DecodeHTTPRequest(const std::vector<u_char>& request):
    m_method(), m_URL(), m_httpVersion()
{
    if(!request.empty())
    {
        std::string req("\0", request.size());
        std::copy(request.cbegin(), request.cend(), req.begin());

        /// Parse Request-Line
        std::string::size_type posMethodStart=std::string::npos,
                               posProtoStart=std::string::npos;

        for(int i=0 ; i<METHODS && std::string::npos==posMethodStart ; ++i)
        {
            posMethodStart = req.find(method[i]);
            if(std::string::npos != posMethodStart)
            {
                m_method = method[i];
            }
        }

        if(!m_method.empty())
        {
            for(int i=0 ; i<PROTOCOLS && std::string::npos==posProtoStart ; ++i)
            {
                posProtoStart = req.find(protocol[i]);
                if(std::string::npos != posProtoStart)
                {
                    m_httpVersion=protocol[i];
                }
            }
            if(!m_httpVersion.empty())
            {
                const std::string::size_type posURLStart  = posMethodStart+m_method.length()+2,    //+2 -- add length(" /")
                                             posGETParams = req.find("?",posURLStart),
                                             URLLen = (posGETParams==std::string::npos) ? posProtoStart-1-posURLStart //(posProtoStart-1) -- pos last URL symbol
                                                                                        : posGETParams-1-posURLStart;

                m_URL=req.substr(posURLStart+1,URLLen); //+1 for remove first '/'

                /// Parse Headers
                std::string::size_type  posStart = 0,
                                        posEnd;

                const std::string end{"\r\n"};                      //end symbol seqence in header line

                for (size_t i=0 ; i<HEADERS ; ++i)
                {
                    posStart = req.find(request_fields[i]);
                    if(posStart!=std::string::npos)
                    {
                        posStart+=(request_fields[i].length()+2);   //+2 -- length(": ")
                        posEnd = req.find(end, posStart);
                        if(posEnd!=std::string::npos)
                        {
                            m_headers.insert(std::pair<std::string,std::string>(request_fields[i],req.substr(posStart, posEnd-posStart)));
                        }
                    }
                }
            }
        }
    }
}

bool DecodeHTTPRequest::empty() const
{
    return (m_method.empty() && m_URL.empty() && m_httpVersion.empty() && m_headers.empty());
}

std::string DecodeHTTPRequest::URL() const
{
    return m_URL;
}

std::string DecodeHTTPRequest::host() const
{
    const auto it = m_headers.find("Host");
    if(m_headers.end() == it)
        return "Unknown host";
    else
    {
        std::string host_str(it->second);
        std::string::size_type posPort = host_str.find(":");
        if(std::string::npos != posPort)
        {
            return host_str.substr(0,posPort);
        }
        else
        {
            return host_str;
        }
    }
}

std::ostream& operator <<(std::ostream &out, const DecodeHTTPRequest &obj)
{
    if(!obj.empty())
    {
        out << "HTTP Request:\n"
            << " " << obj.m_method << " " << obj.m_URL << " " << obj.m_httpVersion << "\n";

        /*
        for(const auto& x : obj.m_headers)
        {
            out << " " << x.first << " : " << x.second << "\n";
        }
        */

        for(auto it=obj.m_headers.cbegin() ; it!=obj.m_headers.cend() ; ++it)
        {
            out << " " << it->first << " : " << it->second << "\n";
        }
    }

    return out;
}
