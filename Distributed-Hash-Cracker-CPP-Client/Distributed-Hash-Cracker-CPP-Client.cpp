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
#include <map>
#include <filesystem>
#include <thread>
#include <mutex>
#include <atomic>

std::string WORDLIST_FILE = "";
std::string SERVER_IP = "";
int SERVER_PORT = 0;

std::mutex send_mutex;           // Mutex for sending messages to the server
std::atomic<bool> stop_processing(false);  // Global flag for stopping threads

char buffer[1024];

void RestartApplication() {
    // Get the current executable's path
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string exePath = buffer;

    // Create a new process to restart the application
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        // Successfully started the new instance
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cerr << "Failed to restart application." << std::endl;
    }

    // Exit the current instance
    ExitProcess(0);
}

// Function to read config file
std::map<std::string, std::string> readConfig(const std::string& filename) {
    std::map<std::string, std::string> configMap;
    std::filesystem::path fullPath = std::filesystem::absolute(filename);
    std::ifstream configFile(fullPath);
    std::string line;

    if (configFile.is_open()) {
        while (std::getline(configFile, line)) {
            size_t delimiterPos = line.find('=');
            if (delimiterPos != std::string::npos) {
                std::string key = line.substr(0, delimiterPos);
                std::string value = line.substr(delimiterPos + 1);
                configMap[key] = value;
            }
        }
        configFile.close();
    }
    else {
        std::cerr << "Unable to open config file: " << filename << std::endl;
    }
    return configMap;
}

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
    else if (hash_type == "sha512") {
        md = EVP_sha512();
    }
    else if (hash_type == "sha384") {
        md = EVP_sha384();
    }
    else if (hash_type == "sha256") {
        md = EVP_sha256();
    }
    else if (hash_type == "sha224") {
        md = EVP_sha224();
    }
    else if (hash_type == "sha3-512") {
        md = EVP_sha3_512();
    }
    else if (hash_type == "sha3-384") {
        md = EVP_sha3_384();
    }
    else if (hash_type == "sha3-256") {
        md = EVP_sha3_256();
    }
    else if (hash_type == "sha3-224") {
        md = EVP_sha3_224();
    }
    else if (hash_type == "ripemd160") {
        md = EVP_ripemd160();
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
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lower_str;
}

// Function to report match found to the server
void report_match(const std::string& word, int line, SOCKET client_socket, const std::string& wordlist_file) {
    std::ostringstream match_message_self;
    match_message_self << "Match found: " << word << " in wordlist: " << wordlist_file
        << ", line: " << line;

    std::string match_message = "MATCH:" + word + " in wordlist: " + WORDLIST_FILE + ", line: " + std::to_string(line);
    std::lock_guard<std::mutex> lock(send_mutex);  // Protect sending message
    send(client_socket, match_message.c_str(), match_message.length(), 0);
    std::cout << match_message_self.str() << std::endl;
}

// Function to process a chunk of the wordlist
void process_chunk(int start_line, int end_line, const std::string& hash_type, const std::string& hash_value, const std::string& salt, SOCKET client_socket) {
    std::wifstream wordlist(WORDLIST_FILE);
    wordlist.seekg(0, std::ios::beg);
    std::wstring utf8_word;

    int current_line = 0;

    // Skip to the start line
    for (int i = 0; i < start_line && std::getline(wordlist, utf8_word); ++i) {
        current_line++;
    }

    // Process the chunk
    for (int i = start_line; i < end_line && std::getline(wordlist, utf8_word); ++i) {
        // Check for STOP signal after processing each word
        fd_set readfds;
        struct timeval tv;
        tv.tv_sec = 0; // No waiting time
        tv.tv_usec = 0;

        FD_ZERO(&readfds);
        FD_SET(client_socket, &readfds);

        // Check if there's data to read
        if (select(client_socket + 1, &readfds, nullptr, nullptr, &tv) > 0) {
            // Socket is ready for reading
            int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                std::cerr << "Disconnected from server or error occurred: " << WSAGetLastError() << std::endl;
                break; // Exit on disconnect
            }

            buffer[bytes_received] = '\0';
            std::string message(buffer);

            if (message == "STOP") {
                std::cout << "Received STOP command. Stopping processing.\n";
                stop_processing = true;
                break; // Exit the loop if STOP command is received
            }
        }

        if (stop_processing) {
            RestartApplication();
            return;  // Exit the thread early if a match is found
        }

        current_line++;
        std::string utf8_word_str(utf8_word.begin(), utf8_word.end());
        std::string calculated_hash;

        if (to_lowercase(hash_type) == "bcrypt") {
            std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
            if (BCrypt::validatePassword(utf8_word_str, hash_value)) {
                report_match(utf8_word_str, current_line, client_socket, WORDLIST_FILE);
                stop_processing = true;  // Set the flag to stop all other threads
                return;
            }
        }
        else {
            std::string input_with_salt = utf8_word_str + salt;
            calculated_hash = calculate_hash(hash_type, input_with_salt);
            std::cout << "Calculated password: " << utf8_word_str << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;

            if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                report_match(utf8_word_str, current_line, client_socket, WORDLIST_FILE);
                stop_processing = true;  // Set the flag to stop all other threads
                return;
            }
        }
    }

    // If no match was found in this chunk
    if (!stop_processing) {
        std::lock_guard<std::mutex> lock(send_mutex);
        send(client_socket, "NO_MATCH", 8, 0);
    }
}

int main() {
    std::map<std::string, std::string> config = readConfig("config.ini");

    SERVER_IP = config["SERVER_IP"];
    SERVER_PORT = std::stoi(config["SERVER_PORT"]);
    WORDLIST_FILE = config["WORDLIST_FILE"];

    // Initialize Winsock
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
    server_address.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP.c_str(), &server_address.sin_addr);

    // Attempt to connect to the server in a loop
    while (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == SOCKET_ERROR) {
        std::cerr << "Connection failed: " << WSAGetLastError() << ". Retrying..." << std::endl;
        Sleep(1000);
    }

    while (true) {
        std::string readyStr = "Ready to accept new requests.";
        std::cout << readyStr << std::endl;
        send(client_socket, readyStr.c_str(), readyStr.length(), 0);

        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            std::cerr << "Disconnected from server or error occurred: " << WSAGetLastError() << std::endl;
            break;
        }

        buffer[bytes_received] = '\0';
        std::string message(buffer);
        size_t delimiter_pos = message.find(':');

        if (message == "STOP") {
            std::cout << "Received STOP command. Stopping processing.\n";
            stop_processing = true;
            continue;
        }

        if (delimiter_pos != std::string::npos) {
            std::string hash_type = message.substr(0, delimiter_pos);
            std::string hash_value, salt;
            size_t second_delimiter_pos = message.find(':', delimiter_pos + 1);

            if (second_delimiter_pos != std::string::npos) {
                hash_value = message.substr(delimiter_pos + 1, second_delimiter_pos - delimiter_pos - 1);
                salt = message.substr(second_delimiter_pos + 1);
            }
            else {
                hash_value = message.substr(delimiter_pos + 1);
            }

            std::wifstream wordlist(WORDLIST_FILE);
            if (!wordlist.is_open()) {
                std::cerr << "Failed to open wordlist file: " << WORDLIST_FILE << std::endl;
                continue;
            }

            int total_lines = 0;
            std::wstring temp_line;
            while (std::getline(wordlist, temp_line)) {
                ++total_lines;
            }

            wordlist.clear();
            wordlist.seekg(0, std::ios::beg);

            int num_threads = std::thread::hardware_concurrency();
            int chunk_size = total_lines / num_threads;

            std::vector<std::thread> threads;
            stop_processing = false;  // Reset the flag before starting new work

            for (int i = 0; i < num_threads; ++i) {
                int start_line = i * chunk_size;
                int end_line = (i == num_threads - 1) ? total_lines : (i + 1) * chunk_size;

                threads.emplace_back(process_chunk, start_line, end_line, hash_type, hash_value, salt, client_socket);
            }

            // Join threads after processing
            for (auto& t : threads) {
                if (t.joinable()) {
                    t.join();
                }
            }
        }
    }

    closesocket(client_socket);
    WSACleanup();
    return 0;
}