#include "fileHandler.h"  // Only include FileHandler header
#include <iostream>

int main() {
    // Create an instance of FileHandler
    FileHandler file_handler;

    // Create a sample file content
    std::string sample_content = "This is a sample file content";
    unsigned char *data = new unsigned char[sample_content.size()];
    std::memcpy(data, sample_content.c_str(), sample_content.size());

    // Store the file
    std::string file_url = file_handler.store_file("sample.txt", data, sample_content.size());
    std::cout << "Stored file at URL: " << file_url << std::endl;

    // Retrieve the stored file
    File *retrieved_file = file_handler.get_file(file_url);
    if (retrieved_file) {
        std::cout << "Retrieved file content: ";
        std::cout.write((char *)retrieved_file->file_content.get(), retrieved_file->file_size);
        std::cout << "\n";
    }

    // Delete the file
    if (file_handler.delete_file(file_url)) {
        std::cout << "File deleted successfully.\n";
    }

    // Clean up the allocated memory
    delete[] data;

    return 0;
}
