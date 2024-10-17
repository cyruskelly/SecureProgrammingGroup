#include "trim.h"

std::string trim(const std::string& line) {
    const char* WhiteSpace = " \t\v\r\n";
    std::size_t end = line.find_last_not_of(WhiteSpace);
    return line.substr(0, end + 1);
}

/*
Group 7
Bunsarak Ann | Cyrus Kelly | Md Raiyan Rahman
*/