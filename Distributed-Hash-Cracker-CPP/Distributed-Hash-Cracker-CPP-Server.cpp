#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <algorithm>

#define PORT 8080

std::vector<SOCKET> clients;
std::atomic<bool> match_found(false);
std::atomic<int> clients_responses(0);
int total_clients = 0;

// Function to convert std::string to UTF-8 (if needed)
std::string to_utf8(const std::string& str) {
    return str; // Assuming str is already in UTF-8 format
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

        clients_responses++;
    }

    // Clean up on client disconnection
    closesocket(client_socket);
    clients.erase(std::remove(clients.begin(), clients.end(), client_socket), clients.end());
    total_clients--;
}

int main() {
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
    address.sin_port = htons(PORT);
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

    std::cout << "Server is listening on port " << PORT << std::endl;

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
        std::string hash_type;
        std::string hash;
        std::string salt;

        // Ask for the hash type, hash, and optional salt from the user
        std::cout << "Enter the hash type (MD5, SHA1, SHA256): ";
        std::getline(std::cin, hash_type);

        std::cout << "Enter the hash: ";
        std::getline(std::cin, hash);

        std::cout << "Enter the salt (leave empty if none): ";
        std::getline(std::cin, salt);

        if (!hash_type.empty() && !hash.empty()) {
            notify_clients(hash_type, hash, salt);
            match_found = false; // Reset match_found flag for the next round
            clients_responses = 0; // Reset responses for the next round

            // Wait for all clients to respond before checking for matches
            while (clients.size() > 0 && clients_responses < total_clients) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Optional delay
                if (match_found) {
                    break; // Break out to prompt for a new hash if a match is found
                }
            }

            // If all clients report no match
            if (!match_found && clients_responses == total_clients) {
                std::cout << "All clients reported no matches. Asking for a new hash...\n";
            }
            else if (match_found) {
                std::cout << "Match found, asking for a new hash...\n";
            }
        }
        else {
            std::cout << "No hash or hash type entered. Please try again." << std::endl;
        }
    }

    client_handler.join();

    closesocket(server_socket);
    WSACleanup();
    return 0;
}
