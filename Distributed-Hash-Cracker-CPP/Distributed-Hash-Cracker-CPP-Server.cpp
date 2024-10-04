#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <algorithm>
#include <map>
#include <fstream>
#include <sstream>
#include <filesystem>    
#include <regex>  
#include <unordered_map>

int SERVER_PORT = 0;

std::vector<SOCKET> clients;
std::map<SOCKET, bool> clients_ready;  // Track the "ready" state of each client
std::atomic<bool> match_found(false);
std::atomic<int> clients_responses(0);
int total_clients = 0;

bool ready = true;

std::map<std::string, std::string> readConfig(const std::string& filename) {
    std::map<std::string, std::string> configMap;
    std::filesystem::path currentPath = std::filesystem::current_path();
    std::filesystem::path fullPath = std::filesystem::absolute(currentPath / filename);
    std::ifstream configFile(fullPath);
    std::string line;

    if (std::filesystem::exists(fullPath)) {
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
    }
    else {
        std::cerr << "File does not exist." << std::endl;
    }

    return configMap;
}

// Function to convert std::string to UTF-8 (if needed)
std::string to_utf8(const std::string& str) {
    return str; // Assuming str is already in UTF-8 format
}

std::string to_lowercase(const std::string& str) {
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lower_str;
}

// Function to check if the given hash is bcrypt
bool isBcryptHash(const std::string& hash) {
    // Regex pattern to match bcrypt hashes
    std::regex bcryptPattern(R"(^\$(2[aby])\$\d{2}\$[./A-Za-z0-9]{53}$)");

    // Return true if the hash matches the bcrypt format
    return std::regex_match(hash, bcryptPattern);
}

// Function to determine if it's SHA, SHA-3, or RIPEMD-160 based on length
std::string getHashType(const std::string& hash) {
    // Map of hash types with their expected lengths in hexadecimal
    std::unordered_map<std::string, size_t> hashTypes = {
        {"MD5", 32},
        {"SHA-1", 40},
        {"RIPEMD-160", 40},
        {"SHA-224", 56},
        {"SHA-256", 64},
        {"SHA-384", 96},
        {"SHA-512", 128},
        {"SHA3-224", 56},
        {"SHA3-256", 64},
        {"SHA3-384", 96},
        {"SHA3-512", 128}
    };

    // Get the length of the hash
    size_t hashLength = hash.length();

    // Try to match the length with known hash types
    for (const auto& [type, length] : hashTypes) {
        if (hashLength == length) {
            return type;  // Return the first match found
        }
    }

    return "Unknown hash type";  // No match found
}

// Function to notify clients of the new hash with optional salt
void notify_clients(const std::string& hash_type, const std::string& hash, const std::string& salt = "") {
    for (const auto& client : clients) {
        std::string message = to_utf8(hash_type + ":" + hash + (salt.empty() ? "" : ":" + salt)); // Append salt if present
        send(client, message.c_str(), message.length(), 0);
    }
}

// Function to handle each client
void handle_client(SOCKET client_socket) {
    clients.push_back(client_socket);
    clients_ready[client_socket] = false;
    total_clients++;

    while (true) {
        char buffer[1024];
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            break; // Client disconnected
        }
        buffer[bytes_received] = '\0';
        std::string message(buffer);

        // Check for match notifications
        if (message.find("MATCH:") == 0) {
            std::string match_info = message.substr(6); // Remove "MATCH:"
            std::cout << "Client " << client_socket << " Match found: " << match_info << std::endl;
            match_found = true;

            // Notify all clients to stop processing
            for (const auto& client : clients) {
                std::string stop_message = "STOP";
                send(client, stop_message.c_str(), stop_message.length(), 0);
            }
        }
        else if (message.find("NO_MATCH") == 0) {
            std::cout << "Match not found in client: " << client_socket << std::endl;
        }
        else if (message.find("Ready to accept new requests.") == 0) {
            clients_ready[client_socket] = true;  // Mark this client as ready

            // Check if all clients are ready
            bool all_clients_ready = true;  // Assume all clients are ready
            for (const auto& client : clients_ready) {
                if (!client.second) {  // If any client is not ready, set to false
                    std::cout << "Client " << std::to_string(client_socket) << " is still working..." << std::endl;
                    all_clients_ready = false;
                    break;
                }
            }

            if (all_clients_ready) {
                for (auto& client : clients_ready) {  // Use non-const reference to modify the map
                    client.second = false;  // Reset each client's ready state to false
                }
                ready = true;  // Set ready to true only when all clients are ready
            }
        }

        clients_responses++;
    }

    // Clean up on client disconnection
    closesocket(client_socket);
    clients.erase(std::remove(clients.begin(), clients.end(), client_socket), clients.end());
    clients_ready.erase(client_socket);
    total_clients--;
}

int main() {
    std::map<std::string, std::string> config = readConfig("server.ini");

    for (const auto& pair : config) {
        if (pair.first == "SERVER_PORT")
            SERVER_PORT = std::stoi(pair.second);
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // Create server socket
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SERVER_PORT);
    if (bind(server_socket, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    if (listen(server_socket, 3) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server is listening on port " << SERVER_PORT << std::endl;

    // Thread to accept clients
    std::thread client_handler([&]() { // Capture by reference
        while (true) {
            SOCKET client_socket = accept(server_socket, nullptr, nullptr);
            if (client_socket == INVALID_SOCKET) {
                std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
                continue; // Skip this iteration if accept fails
            }

            std::thread(handle_client, client_socket).detach(); // Handle each client in a separate thread
        }
        });

    while (true) {
        while (ready) {
            std::string hash_type;
            std::string hash;
            std::string salt;

            // Ask for the hash type, hash, and optional salt from the user     
            std::cout << "Hash type (BCRYPT, MD5, SHA1, SHA512, sha384, SHA256, sha224, sha3-512, sha3-384, sha3-256, sha3-224, ripemd160): " << std::endl;
            std::cout << "To check hash type, enter 'type' as the hash type." << std::endl;
            std::cout << "Enter the hash type: ";
            std::getline(std::cin, hash_type);

            std::cout << "Enter the hash: ";
            std::getline(std::cin, hash);

            if (to_lowercase(hash_type) == "type") {
                std::string hashType = getHashType(hash);
                if (hashType == "Unknown hash type") {
                    bool isBcrypt = isBcryptHash(hash);
                    if (isBcrypt) {
                        std::cout << "Hash Type: BCrypt" << std::endl;
                        continue;
                    }
                    else {
                        std::cout << "Unknown hash type." << std::endl;
                        continue;
                    }
                }
                else {
                    std::cout << "Hash Type: " << getHashType(hash) << std::endl;
                    continue;
                }
            }

            std::cout << "Enter the salt (leave empty if none, or BCRYPT): ";
            std::getline(std::cin, salt);

            if (!hash_type.empty() && !hash.empty()) {
                ready = false;
                notify_clients(hash_type, hash, salt);
                match_found = false; // Reset match_found flag for the next round
                clients_responses = 0; // Reset responses for the next round
                
                std::cout << "Processing entered hash, please wait..." << std::endl;

                // Wait for all clients to respond before checking for matches
                while (clients.size() > 0 && clients_responses < total_clients) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Optional delay
                    if (match_found) {
                        break; // Break out to prompt for a new hash if a match is found
                    }
                }

                // If all clients report no match
                if (!match_found && clients_responses == total_clients) {
                    std::cout << "All clients reported no matches. please wait until you can enter a new hash...\n";
                }
                else if (match_found) {
                    std::cout << "Match found, please wait until you can enter a new hash...\n";
                }
            }
            else {
                std::cout << "No hash or hash type entered. Please try again." << std::endl;
            }
        }
    }

    client_handler.join();

    closesocket(server_socket);
    WSACleanup();
    return 0;
}
