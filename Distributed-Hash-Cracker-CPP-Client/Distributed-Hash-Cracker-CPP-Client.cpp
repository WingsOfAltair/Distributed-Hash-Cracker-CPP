#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <openssl/md5.h>
#include <winsock2.h>
#include <ws2tcpip.h>   

#include <openssl/evp.h> // Include the EVP header

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_IP "192.168.1.29" // Change this to your server's IP if needed
#define PORT 8080

std::string wordlistFilename = "D:\\GitHub\\Distributed-Hash-Cracker-CPP\\x64\\Debug\\wordlist.txt";

std::atomic<bool> match_found(false); // Atomic flag to signal when a match is found
std::mutex mtx; // Mutex for shared resources (like printing to console)

// Function to compute MD5 hash using EVP
std::string compute_md5(const std::string& input) {
    unsigned char digest[EVP_MAX_MD_SIZE]; // Buffer for the hash
    unsigned int digest_len; // Length of the digest

    // Create a new context for the MD5 hash computation
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Failed to create MD context.\n";
        return "";
    }

    // Initialize the MD5 hashing context
    if (EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1) {
        std::cerr << "Failed to initialize MD5 digest.\n";
        EVP_MD_CTX_free(mdctx); // Free the context
        return "";
    }

    // Update the MD5 context with input data
    if (EVP_DigestUpdate(mdctx, input.c_str(), input.size()) != 1) {
        std::cerr << "Failed to update MD5 digest.\n";
        EVP_MD_CTX_free(mdctx); // Free the context
        return "";
    }

    // Finalize the MD5 hash and get the output in digest
    if (EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
        std::cerr << "Failed to finalize MD5 digest.\n";
        EVP_MD_CTX_free(mdctx); // Free the context
        return "";
    }

    // Free the MD5 context
    EVP_MD_CTX_free(mdctx);

    // Convert the hash to a hexadecimal string
    char md5string[33]; // 32 characters + null terminator for a 128-bit MD5 hash
    for (unsigned int i = 0; i < digest_len; ++i) {
        sprintf_s(&md5string[i * 2], sizeof(md5string) - i * 2, "%02x", (unsigned int)digest[i]);
    }

    return std::string(md5string); // Return the MD5 hash as a string
}



void match_in_range(const std::vector<std::string>& wordlist, const std::string& target_hash, int start, int end, SOCKET socket) {
    for (int i = start; i < end && !match_found; ++i) {
        std::string word = wordlist[i];
        std::string word_hash = compute_md5(word);
        if (word_hash == target_hash) {
            // Lock mutex for safe console output and match found notification
            std::lock_guard<std::mutex> lock(mtx);
            if (!match_found) {  // Check again after acquiring the lock
                std::cout << "MATCH FOUND: " << word << " at line " << i << std::endl;

                // Notify the server of the match
                std::string message = std::string("MATCH FOUND: ") + word + " in Wordlist: " + wordlistFilename + " at Line: " + std::to_string(i);
                send(socket, message.c_str(), message.size(), 0);

                match_found = true;  // Set the match found flag
            }
            return;  // Exit the thread after finding a match
        }
    }
}


void receive_messages(SOCKET socket, const std::vector<std::string>& wordlist) {
    char buffer[1024];
    while (true) {
        int valread = recv(socket, buffer, sizeof(buffer), 0);
        if (valread <= 0) {
            std::cout << "Disconnected from server.\n";
            break;
        }

        std::string hash(buffer, valread);
        std::cout << "Received MD5 hash: " << hash << std::endl;

        // Check if we received a stop command
        if (hash == "STOP") {
            std::cout << "Stopping client operations as per server instruction.\n";
            match_found = false; // Reset the match flag
            continue; // Skip to the next iteration to wait for a new hash
        }

        // Reset match_found for each new hash processing
        match_found = false;

        // Split the workload across all CPU cores
        int num_threads = std::thread::hardware_concurrency(); // Get number of cores
        int chunk_size = wordlist.size() / num_threads;

        std::vector<std::thread> threads;

        for (int i = 0; i < num_threads; ++i) {
            int start = i * chunk_size;
            int end = (i == num_threads - 1) ? wordlist.size() : start + chunk_size;
            threads.emplace_back(match_in_range, std::ref(wordlist), hash, start, end, socket);
        }

        // Wait for all threads to complete
        for (auto& t : threads) {
            t.join();
        }

        // Check if a match was found after all threads complete
        if (match_found) {
            // Notify the server that a match was found
            std::string message = "Match found, asking for a new MD5 hash...";
            send(socket, message.c_str(), message.size(), 0);
        }
        else {
            // If no match was found, notify the server
            std::string message = "NO MATCH for hash " + hash;
            send(socket, message.c_str(), message.size(), 0);
        }
    }
}

int main() {
    // Read wordlist file into memory
    std::ifstream wordlist_file(wordlistFilename);
    std::vector<std::string> wordlist;
    std::string line;
    while (std::getline(wordlist_file, line)) {
        wordlist.push_back(line);
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create client socket
    SOCKET client_socket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);

    // Use inet_pton instead of inet_addr
    if (inet_pton(AF_INET, SERVER_IP, &server_address.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported.\n";
        return -1;
    }

    // Connect to server
    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        std::cerr << "Connection to server failed.\n";
        return -1;
    }

    std::cout << "Connected to server!\n";

    // Start a thread to receive messages from the server and process hashes
    std::thread(receive_messages, client_socket, std::ref(wordlist)).detach();

    // Main loop for client operations
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Close the socket
    closesocket(client_socket);
    WSACleanup();
    return 0;
}
