#ifndef DECODE_HTTP_REQUEST
#define DECODE_HTTP_REQUEST

#include <string>
#include <vector>
#include <map>

class DecodeHTTPRequest
{
    #define HEADERS     7
    const static std::string request_fields[HEADERS];

    #define METHODS     2
    const static std::string method[METHODS];

    #define PROTOCOLS   2
    const static std::string protocol[PROTOCOLS];

    /// Sample Request-Line: "GET / HTTP/1.1\r\nHost: localhost:5000\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    std::string m_method,       // GET POST
                m_URL,          // /index.html
                m_httpVersion;  // HTTP/1.0 HTTP/1.1

    std::map<std::string, std::string> m_headers;

private:
    DecodeHTTPRequest()=default;
    DecodeHTTPRequest(const DecodeHTTPRequest&)=delete;
    DecodeHTTPRequest& operator=(const DecodeHTTPRequest&)=delete;

public:
    DecodeHTTPRequest (DecodeHTTPRequest& obj)=default;
    DecodeHTTPRequest (const std::vector<u_char>& request);
    bool empty()const;

    /// Need for task:
    std::string URL()const;
    std::string host()const;

    friend std::ostream& operator <<(std::ostream& out, const DecodeHTTPRequest& obj);
};

#endif //DECODE_HTTP_REQUEST
