#include "bcrypt/BCrypt.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <vector>
#include <algorithm>

#define PORT 8080
#define WORDLIST_FILE "D:\\GitHub\\Distributed-Hash-Cracker-CPP\\x64\\Debug\\wordlist.txt"

// Function to calculate hash using EVP
std::string calculate_hash(const std::string& hash_type, const std::string& input) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length;

    const EVP_MD* md = nullptr;

    if (hash_type == "md5") {
        md = EVP_md5();
    }
    else if (hash_type == "sha1") {
        md = EVP_sha1();
    }
    else if (hash_type == "sha256") {
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

std::string to_lowercase(const std::string& str) {
    std::string lower_str = str; // Create a copy of the input string
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lower_str;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
        return 1;
    }

    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);

    // Attempt to connect to the server continuously
    while (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == SOCKET_ERROR) {
        std::cerr << "Connection failed: " << WSAGetLastError() << ". Retrying..." << std::endl;
        Sleep(1000); // Wait before retrying
    }

    char buffer[1024];
    bool match_found = false;
    while (true) {
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            std::cerr << "Disconnected from server or error occurred: " << WSAGetLastError() << std::endl;
            break; // Exit on disconnect
        }

        buffer[bytes_received] = '\0';
        std::string message(buffer);
        size_t delimiter_pos = message.find(':');

        if (message == "STOP") {
            std::cout << "Received STOP command. Stopping processing.\n";
            continue; // Stop processing for new hash
        }

        if (delimiter_pos != std::string::npos) {
            std::string hash_type = message.substr(0, delimiter_pos);
            std::string hash_value;
            std::string salt;

            size_t second_delimiter_pos = message.find(':', delimiter_pos + 1);
            if (second_delimiter_pos != std::string::npos) {
                hash_value = message.substr(delimiter_pos + 1, second_delimiter_pos - delimiter_pos - 1);
                salt = message.substr(second_delimiter_pos + 1); // Get the salt if present
            }
            else {
                hash_value = message.substr(delimiter_pos + 1); // Only hash_value is present
            }

            std::cout << "Processing " << hash_type << " hash: " << hash_value;
            if (!salt.empty()) {
                std::cout << " with salt: " << salt;
            }
            std::cout << std::endl;

            // Open the wordlist file
            std::wifstream wordlist(WORDLIST_FILE);
            std::wstring utf8_word;

            int line_number = 0;
            while (std::getline(wordlist, utf8_word)) {
                line_number++;
                std::string utf8_word_str(utf8_word.begin(), utf8_word.end());
                std::string calculated_hash;

                if (to_lowercase(hash_type) == "bcrypt") {
                    //calculated_hash = BCrypt::generateHash(utf8_word_str, std::stoi(salt));

                    //std::cout << "Calculated the password: " << utf8_word_str << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;
                    std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;

                    if (BCrypt::validatePassword(utf8_word_str, hash_value))
                    {
                        match_found = true;
                        std::string match_message = "MATCH:" + utf8_word_str + " in wordlist: " + WORDLIST_FILE + ", line: " + std::to_string(line_number);
                        send(client_socket, match_message.c_str(), match_message.length(), 0);
                        break; // Exit the loop on a match
                    }
                }
                else {
                    std::string input_with_salt = utf8_word_str + salt; // Append salt to the word
                    calculated_hash = calculate_hash(hash_type, input_with_salt);

                    std::cout << "Calculated the password: " << utf8_word_str << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;

                    if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                        match_found = true;
                        std::string match_message = "MATCH:" + utf8_word_str + " in wordlist: " + WORDLIST_FILE + ", line: " + std::to_string(line_number);
                        send(client_socket, match_message.c_str(), match_message.length(), 0);
                        std::cout << "Match found: " << utf8_word_str << " in wordlist: " << WORDLIST_FILE << ", line: " << std::to_string(line_number) << std::endl;
                        break; // Exit the loop on a match
                    }
                }
            }

            // Notify the server if no match was found
            if (!match_found) {
                std::string no_match_message = "NO_MATCH";
                send(client_socket, no_match_message.c_str(), no_match_message.length(), 0);
                std::cout << "No match was found in wordlist: " << WORDLIST_FILE << std::endl;
            }
        }
    }

    closesocket(client_socket);
    WSACleanup();
    return 0;
}