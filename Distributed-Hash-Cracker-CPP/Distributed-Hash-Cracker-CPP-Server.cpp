#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <winsock2.h>

#pragma comment(lib, "Ws2_32.lib")
#define PORT 8080

std::mutex mtx;
std::unordered_set<SOCKET> clients;
int total_clients = 0; // Track total number of connected clients
int clients_responses = 0; // Track the number of responses received
bool match_found = false; // Flag to track if a match was found

// Function to notify all clients of a new hash
void notify_clients(const std::string& hash) {
    for (const auto& client_socket : clients) {
        send(client_socket, hash.c_str(), hash.size(), 0);
    }
}

// Function to handle each client connection
void handle_client(SOCKET client_socket) {
    char buffer[1024] = { 0 };
    clients.insert(client_socket); // Add the client to the set

    {
        std::lock_guard<std::mutex> lock(mtx);
        total_clients++; // Increment total clients on connection
        std::cout << "Client connected: " << client_socket << std::endl;
    }

    while (true) {
        // Receive message from the client
        int valread = recv(client_socket, buffer, sizeof(buffer), 0);
        if (valread <= 0) {
            std::cout << "Client disconnected: " << client_socket << std::endl;
            clients.erase(client_socket); // Remove the client from the set
            {
                std::lock_guard<std::mutex> lock(mtx);
                total_clients--; // Decrement total clients on disconnection
            }
            break; // Exit loop on disconnection
        }

        std::string message(buffer);
        //std::cout << "Received from client " << client_socket << ": " << message << std::endl;

        // Check if a match was found
        if (message.find("MATCH FOUND") != std::string::npos) {
            std::lock_guard<std::mutex> lock(mtx);
            std::cout << message << " from client " << client_socket << "\n";
            clients_responses++; // Increment responses
            match_found = true; // Set flag to true if any client finds a match
            notify_clients("STOP"); // Notify all clients to stop processing
        }
        else if (message.find("NO MATCH") != std::string::npos) {
            std::lock_guard<std::mutex> lock(mtx);
            // Extract hash from the message
            std::string hash = message.substr(message.find(':') + 1); // Assuming the format is "NO MATCH: <hash>"
            std::cout << "Client " << client_socket << ": " << hash << "\n"; // Print NO MATCH with hash
            clients_responses++; // Increment responses
        }
    }

    // Close the client socket
    closesocket(client_socket);
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

    std::thread client_handler([&]() {
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
        std::string hash;

        // Ask for a new MD5 hash from the user
        std::cout << "Enter the MD5 hash: ";
        std::getline(std::cin, hash); // Get new hash from user input

        if (!hash.empty()) {
            notify_clients(hash); // Notify all clients of the new hash
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
                std::cout << "All clients reported no matches. Asking for a new MD5 hash...\n";
            }
            else if (match_found) {
                std::cout << "Match found, asking for a new MD5 hash...\n";
            }
        }
        else {
            std::cout << "No hash entered. Please try again." << std::endl;
        }
    }

    client_handler.join();

    closesocket(server_socket);
    WSACleanup();
    return 0;
}
