#include "fileHandler.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <cstdlib>

// Constructor
FileHandler::FileHandler() {}

// Destructor
FileHandler::~FileHandler() {
    // No manual deletion needed; std::unique_ptr will automatically clean up.
}

// Store a file in memory and generate a unique URL
std::string FileHandler::store_file(const std::string &file_name, const unsigned char *data, size_t size) {
    std::string file_url = generate_unique_url();

    // Create a new File object and store its content in memory using std::unique_ptr
    std::unique_ptr<unsigned char[]> content_copy(new unsigned char[size]);
    std::memcpy(content_copy.get(), data, size);

    // Use std::make_unique to create the File object
    auto new_file = std::make_unique<File>(file_url, size, content_copy.release());
    file_store[file_url] = std::move(new_file);

    std::cout << "File stored at URL: " << file_url << " (Size: " << size << " bytes)" << std::endl;
    return file_url;
}

// Retrieve a file from memory using its URL
File *FileHandler::get_file(const std::string &file_url) const {
    if (file_store.find(file_url) != file_store.end()) {
        return file_store.at(file_url).get();
    }
    std::cout << "File not found: " << file_url << std::endl;
    return nullptr;
}

// Delete a file from memory using its URL
bool FileHandler::delete_file(const std::string &file_url) {
    if (file_store.find(file_url) != file_store.end()) {
        file_store.erase(file_url);  // Automatically deletes the unique_ptr and its content
        std::cout << "File deleted: " << file_url << std::endl;
        return true;
    }
    std::cout << "File not found for deletion: " << file_url << std::endl;
    return false;
}

// Generate a unique URL for a file
std::string FileHandler::generate_unique_url() {
    static int file_id = 0;
    std::stringstream ss;
    ss << "/file_" << file_id++;
    return ss.str();
}

// Print all stored files
void FileHandler::print_stored_files() const {
    std::cout << "Stored Files:" << std::endl;
    for (const auto &pair : file_store) {
        std::cout << " - " << pair.first << " (Size: " << pair.second->file_size << " bytes)" << std::endl;
    }
}


