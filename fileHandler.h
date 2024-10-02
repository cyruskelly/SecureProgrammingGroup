#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <unordered_map>
#include <string>
#include <memory>
#include <iostream>

// Define the File structure to hold file information
struct File {
    std::string file_url;                               // Unique file URL
    size_t file_size;                                   // Size of the file in bytes
    std::unique_ptr<unsigned char[]> file_content;      // Unique pointer to file content

    File(const std::string &url, size_t size, unsigned char *content)
        : file_url(url), file_size(size), file_content(content) {}
};


class FileHandler {
private:
    // A map to store files in memory, keyed by unique URLs
    std::unordered_map<std::string, std::unique_ptr<File>> file_store;

public:
    FileHandler();                   // Constructor
    ~FileHandler();                  // Destructor

    // Store a file in memory and generate a unique URL
    std::string store_file(const std::string &file_name, const unsigned char *data, size_t size);

    // Retrieve a file from memory using its URL
    File *get_file(const std::string &file_url) const;

    // Delete a file from memory using its URL
    bool delete_file(const std::string &file_url);

    // Generate a unique URL for a file
    std::string generate_unique_url();

    // Print all stored files
    void print_stored_files() const;
};

#endif // FILE_HANDLER_H

