#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>
#include <boost/locale.hpp>
#include <boost/process.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>

using boost::asio::ip::tcp;

int SERVER_PORT = 0;
std::vector<std::shared_ptr<tcp::socket>> clients;
std::unordered_map<std::string, bool> clients_ready;
std::atomic<bool> match_found(false);
std::atomic<int> clients_responses(0);
int total_clients = 0;

// Read config file
std::map<std::string, std::string> readConfig(const std::string& filename) {
    std::map<std::string, std::string> configMap;
    boost::filesystem::path fullPath = boost::filesystem::absolute(filename);
    std::ifstream configFile(fullPath.string());

    if (boost::filesystem::exists(fullPath)) {
        std::string line;
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
        std::cerr << "Config file does not exist.\n";
    }

    return configMap;
}

// Convert to lowercase
std::string to_lowercase(const std::string& str) {
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lower_str;
}

// Check bcrypt hash format
bool isBcryptHash(const std::string& hash) {
    boost::regex bcryptPattern(R"(^\$(2[aby])\$\d{2}\$[./A-Za-z0-9]{53}$)");
    return boost::regex_match(hash, bcryptPattern);
}

// Determine hash type by length
std::string getHashType(const std::string& hash) {
    if (hash.rfind("$argon2id$", 0) == 0) return "Argon2id";
    if (hash.rfind("$argon2i$", 0) == 0) return "Argon2i";
    if (hash.rfind("$argon2d$", 0) == 0) return "Argon2d";

    std::map<std::string, size_t> hashTypes = {
        {"MD5", 32}, {"SHA-1 or RIPEMD-160", 40}, {"SHA-224 or SHA3-224", 56},
        {"SHA-256 or SHA3-256", 64}, {"SHA-384 or SHA3-384", 96}, {"SHA-512 or SHA3-512", 128} };
    size_t hashLength = hash.length();
    for (const auto& [type, length] : hashTypes) {
        if (hashLength == length) return type;
    }
    return "Unknown hash type";
}

// Notify clients with new hash
void notify_clients(const std::string& hash_type, const std::string& hash, const std::string& salt = "") {
    std::string message = hash_type + ":" + hash + (salt.empty() ? "" : ":" + salt);
    for (auto& client : clients) {
        boost::asio::write(*client, boost::asio::buffer(message + "\n"));
    }
}

// Handle each client connection
void handle_client(std::shared_ptr<tcp::socket> client_socket) {
    clients.push_back(client_socket);
    auto client_endpoint = client_socket->remote_endpoint();
    std::string client_key = client_endpoint.address().to_string() + ":" + std::to_string(client_endpoint.port());
    total_clients++;

    try {
        boost::asio::streambuf buffer;
        while (true) {
            boost::system::error_code error;
            size_t len = boost::asio::read_until(*client_socket, buffer, "\n", error);
            
            if (error == boost::asio::error::eof) {
                std::cout << "Client disconnected normally.\n";
                break;
            }
            else if (error) {
                std::cerr << "Client read error: " << error.message() << std::endl;
                break;
            }

            std::istream is(&buffer);
            std::string message;
            std::getline(is, message);
            boost::algorithm::trim(message);

            // Handle client messages
            if (message.find("MATCH:") == 0) {
                std::string match_info = message.substr(6); // Remove "MATCH:"
                std::cout << "Client " << client_socket << " Match found: " << match_info << std::endl;
                match_found = true;
                for (auto& client : clients) {
                    boost::asio::write(*client, boost::asio::buffer("STOP\n"));
                }
            }
            else if (message.find("NO_MATCH") == 0) {
                std::cout << "Match not found in client: " << client_socket << std::endl;
            }
            else if (message.find("Ready") == 0) {
                clients_ready[client_key] = true;
                std::cout << "Client " << client_key << " is ready.\n";
            }
            clients_responses++;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in client handling: " << e.what() << std::endl;
    }

    // Cleanup client on disconnect
    clients.erase(std::remove(clients.begin(), clients.end(), client_socket), clients.end());
    clients_ready.erase(client_key);
    total_clients--;
}

// Main function to initialize server and manage client connections
int main() {
    auto config = readConfig("server.ini");
    SERVER_PORT = std::stoi(config["SERVER_PORT"]);

    std::string hash_type;
    std::string hash;
    std::string salt;

    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), SERVER_PORT));

    std::cout << "Server is listening on port " << SERVER_PORT << "\n";

    // Thread to accept clients
    boost::thread client_handler([&]() {
        while (true) {
            auto client_socket = std::make_shared<tcp::socket>(io_context);
            acceptor.accept(*client_socket);
            boost::thread(handle_client, client_socket).detach();
        }
        });

    // Main loop for hash input
    while (true) {
        while (std::all_of(clients_ready.begin(), clients_ready.end(), [](auto& entry) { return entry.second; }) && total_clients > 0) {
            std::cout << "Hash type (BCRYPT, argon2, MD5, SHA1, SHA512, sha384, SHA256, sha224, sha3-512, sha3-384, sha3-256, sha3-224, ripemd160): " << std::endl;
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

            std::cout << "Enter the salt (leave empty if none, or BCRYPT or argon2): ";
            std::getline(std::cin, salt);

            if (!hash_type.empty() && !hash.empty()) {
                notify_clients(hash_type, hash, salt);
                match_found = false;
                clients_responses = 0;

                for (auto& pair : clients_ready) {
                    pair.second = false;
                }

                std::cout << "Processing entered hash, please wait...\n";
                while (clients_responses < total_clients) {
                    boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
                    if (match_found) {
                        break;
                    }
                }

                if (!match_found && clients_responses == total_clients) {
                    std::cout << "No matches found, please wait until you can enter a new hash...\n";
                }
                else if (match_found) {
                    std::cout << "Match found, please wait until you can enter a new hash...\n";
                }
            }
            else {
                std::cout << "No hash or hash type entered. Try again.\n";   
                for (auto& pair : clients_ready) {
                    pair.second = true; // example: mark all clients as not ready
                }
            }
        }
    }

    client_handler.join();
    return 0;
}
