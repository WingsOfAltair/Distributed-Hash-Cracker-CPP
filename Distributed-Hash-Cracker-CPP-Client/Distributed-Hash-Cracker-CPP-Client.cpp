#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <algorithm>

#define PORT 8080
#define WORDLIST_FILE "D:\\GitHub\\Distributed-Hash-Cracker-CPP\\x64\\Debug\\wordlist.txt" // Specify your wordlist file here

// Function to calculate hash using EVP
std::string calculate_hash(const std::string& hash_type, const std::string& input) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length;

    const EVP_MD* md = nullptr;

    // Choose the appropriate hash function
    if (hash_type == "MD5") {
        md = EVP_md5();
    }
    else if (hash_type == "SHA1") {
        md = EVP_sha1();
    }
    else if (hash_type == "SHA256") {
        md = EVP_sha256();
    }
    else {
        std::cerr << "Unsupported hash type: " << hash_type << std::endl;
        return "";
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, input.c_str(), input.length());
    EVP_DigestFinal_ex(mdctx, digest, &digest_length);
    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < digest_length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return oss.str();
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // Create client socket
    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr); // Use inet_pton for IPv4

    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == SOCKET_ERROR) {
        std::cerr << "Connection failed: " << WSAGetLastError() << std::endl;
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    char buffer[1024];
    while (true) {
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            std::cerr << "Disconnected from server or error occurred: " << WSAGetLastError() << std::endl;
            break;
        }
        buffer[bytes_received] = '\0';

        // Parse received message (e.g., "MD5:49f68a5c8493ec2c0bf489821c21fc3b")
        std::string message(buffer);
        size_t delimiter_pos = message.find(':');
        if (delimiter_pos != std::string::npos) {
            std::string hash_type = message.substr(0, delimiter_pos);
            std::string hash_value = message.substr(delimiter_pos + 1);

            std::cout << "Processing " << hash_type << " hash: " << hash_value << std::endl;

            // Open the wordlist file
            std::ifstream wordlist(WORDLIST_FILE);
            if (!wordlist.is_open()) {
                std::cerr << "Could not open wordlist file: " << WORDLIST_FILE << std::endl;
                break;
            }

            std::string word;
            bool match_found = false;

            int line_number = 0; // Initialize line number counter
            // Iterate through each word in the wordlist
            while (std::getline(wordlist, word)) {
                line_number++; // Increment the line number for each line read
                // Trim whitespace (if needed)
                word.erase(std::remove_if(word.begin(), word.end(), ::isspace), word.end());

                // Hash the word
                std::string calculated_hash = calculate_hash(hash_type, word);
                std::cout << "Calculated hash for '" << word << "': " << calculated_hash << std::endl;

                // Compare the calculated hash with the received hash
                if (calculated_hash == hash_value) {
                    std::cout << "Match found: " << word << " -> " << hash_value << std::endl;

                    // Notify the server of the match
                    std::string notification = "MATCH:" + word + ":" + hash_value + " found in wordfile: " + WORDLIST_FILE + " at line: " + std::to_string(line_number); // Update to include found word and hash
                    send(client_socket, notification.c_str(), notification.size(), 0);

                    match_found = true;
                    break; // Stop searching after finding a match
                }
            }

            if (!match_found) {
                std::cout << "No match found for the provided hash." << std::endl;

                // Notify the server that no match was found
                std::string notification = "NO_MATCH:" + hash_value; // Update to include no match notification
                send(client_socket, notification.c_str(), notification.size(), 0);
            }

            wordlist.close(); // Close the wordlist file
        }
    }

    closesocket(client_socket);
    WSACleanup();
    return 0;
}
