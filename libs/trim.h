#ifndef TRIM_OLAF_N
#define TRIM_OLAF_N

#include <string>


std::string trim(const std::string& line) {
    const char* WhiteSpace = " \t\v\r\n";
    std::size_t end = line.find_last_not_of(WhiteSpace);
    return line.substr(0, end + 1);
}


#endif // !TRIM_OLAF_N