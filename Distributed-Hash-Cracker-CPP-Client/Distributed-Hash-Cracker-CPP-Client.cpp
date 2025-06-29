#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
#include <boost/algorithm/string.hpp>    
#include <boost/lexical_cast.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include "bcrypt/BCrypt.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <filesystem>
#include "argon2/argon2.h"
#include <queue>

namespace asio = boost::asio;

using boost::asio::ip::tcp;

// Globals
asio::io_context io_context;
tcp::socket client_socket(io_context);

std::string WORDLIST_FILE = "";
std::string SERVER_IP = "";
int SERVER_PORT = 0;
std::string SHOW_PROGRESS = "";

bool match_found = false;

std::mutex send_mutex;           // Mutex for sending messages to the server
std::atomic<bool> stop_processing(false);  // Global flag for stopping threads

// Pointer to client socket, shared for reading thread and workers
boost::asio::ip::tcp::socket* global_socket_ptr = nullptr;

// Thread-safe message queue
std::queue<std::string> message_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;

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

// Convert hex string to binary
std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

argon2_type detect_argon2_type(const std::string& encoded_hash) {
    if (encoded_hash.rfind("$argon2id$", 0) == 0) return Argon2_id;
    if (encoded_hash.rfind("$argon2i$", 0) == 0) return Argon2_i;
    if (encoded_hash.rfind("$argon2d$", 0) == 0) return Argon2_d;
    // Default fallback or invalid format
    return Argon2_id;
}

bool verify_argon2_encoded(const std::string& password, const std::string& encoded_hash) {
    argon2_type type = detect_argon2_type(encoded_hash);

    int result = argon2_verify(encoded_hash.c_str(), password.c_str(), password.size(), type);

    return result == ARGON2_OK;
}

// Function to report match found to the server
void report_match(const std::string& word, int line, boost::asio::ip::tcp::socket& socket, const std::string& wordlist_file) {
    match_found = true;
    std::ostringstream match_message_self;
    match_message_self << "Match found: " << word << " in wordlist: " << wordlist_file
        << ", line: " << line;

    std::string match_message = "MATCH:" + word + " in wordlist: " + wordlist_file + ", line: " + std::to_string(line);
    {
        std::lock_guard<std::mutex> lock(send_mutex);
        boost::asio::write(socket, boost::asio::buffer(match_message + "\n"));
    }
    std::cout << match_message_self.str() << std::endl;
}

// Dedicated socket reader thread function
void socket_reader() {
    char temp[1024];
    boost::system::error_code ec;

    while (!stop_processing) {
        size_t bytes_received = global_socket_ptr->read_some(boost::asio::buffer(temp), ec);
        if (ec) {
            std::cerr << "Disconnected from server or error occurred: " << ec.message() << std::endl;
            stop_processing = true;
            break;
        }

        std::string message(temp, bytes_received);

        if (message.find("STOP") == 0) {
            std::cout << "Received STOP command. Stopping processing.\n";
            stop_processing.store(true, std::memory_order_release);
            break;  // Exit the reader thread or continue to clean shutdown
        }

        size_t newline_pos;
        while ((newline_pos = message.find('\n')) != std::string::npos) {
            std::string line = message.substr(0, newline_pos);   // Extract one line
            message.erase(0, newline_pos + 1);                    // Remove extracted line + '\n' from the original string
            boost::algorithm::trim(line);                         // Trim the extracted line

            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                message_queue.push(line);
            }
            queue_cv.notify_one();
        }
    }
}

// Process chunk - NO socket reading here!
void process_chunk(int start_line, int end_line, const std::string& hash_type, const std::string& hash_value, const std::string& salt) {
    std::ifstream wordlist(WORDLIST_FILE);
    if (!wordlist.is_open()) {
        std::cerr << "Failed to open wordlist file: " << WORDLIST_FILE << std::endl;
        return;
    }

    // Skip UTF-8 BOM if present
    char bom[3] = { 0 };
    wordlist.read(bom, 3);
    if (!(bom[0] == '\xEF' && bom[1] == '\xBB' && bom[2] == '\xBF')) {
        wordlist.seekg(0);  // rewind if no BOM
    }
    std::string utf8_word;
    int current_line = 0;

    // Skip lines to start_line
    for (int i = 0; i < start_line && std::getline(wordlist, utf8_word); ++i) {
        current_line++;
    }

    // Process assigned chunk
    for (int i = start_line; i < end_line && std::getline(wordlist, utf8_word); ++i) {
        if (stop_processing.load(std::memory_order_acquire)) {
            break;
        }

        if (wordlist.eof()) {
            std::cerr << "[DEBUG] Reached EOF early at line: " << i << std::endl;
            return;
        }

        std::string utf8_word_str = utf8_word;

        if (to_lowercase(hash_type) == "bcrypt") {
            if (to_lowercase(SHOW_PROGRESS) == "true")
                std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
            if (BCrypt::validatePassword(utf8_word_str, hash_value)) {
                report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
            }
        }
        else if (to_lowercase(hash_type) == "argon2") {
            if (to_lowercase(SHOW_PROGRESS) == "true")
                std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
            if (verify_argon2_encoded(utf8_word_str, hash_value)) {
                report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
            }
        }
        else {
            std::string input_with_salt = utf8_word_str + salt;
            std::string calculated_hash = calculate_hash(hash_type, input_with_salt);
            if (to_lowercase(SHOW_PROGRESS) == "true")
                std::cout << "Calculated password: " << utf8_word_str << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;
            if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
            }
        }
        current_line++;
    }
}

int main() {
    // Read configuration from the file
    std::map<std::string, std::string> config = readConfig("config.ini");

    SERVER_IP = config["SERVER_IP"];
    SERVER_PORT = boost::lexical_cast<int>(config["SERVER_PORT"]);
    WORDLIST_FILE = config["WORDLIST_FILE"];
    SHOW_PROGRESS = config["SHOW_PROGRESS"];

    // Attempt to connect to the server in a loop
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(SERVER_IP, std::to_string(SERVER_PORT));

    while (true) {
        try {
            asio::connect(client_socket, endpoints);
            break; // Successfully connected
        }
        catch (std::exception& e) {
            std::cerr << "Connection failed: " << e.what() << ". Retrying..." << std::endl;
            boost::this_thread::sleep_for(boost::chrono::seconds(1));
        }
    }

    global_socket_ptr = &client_socket;
    boost::thread reader_thread(socket_reader);

    while (true) {
        match_found = false;
        stop_processing.store(false);
        std::string readyStr = "Ready to accept new requests.";
        std::cout << readyStr << std::endl;

        // Send ready message to server
        asio::write(client_socket, asio::buffer(readyStr + "\n"));

        std::unique_lock<std::mutex> lock(queue_mutex);
        queue_cv.wait(lock, [] { return !message_queue.empty(); });

        std::string message = message_queue.front();
        message_queue.pop();
        lock.unlock();                   

        if (message.find("STOP") == 0) {
            std::cout << "Received STOP command. Stopping processing.\n";
            stop_processing = true;
            continue;
        }

        size_t delimiter_pos = message.find(':');

        if (delimiter_pos == std::string::npos) {
            std::cerr << "Malformed request from server: " << message << std::endl;
            continue;
        }

        std::string hash_type = message.substr(0, delimiter_pos);
        std::string hash_value, salt;
        size_t second_delimiter_pos = message.find(':', delimiter_pos + 1);

        if (second_delimiter_pos != std::string::npos) {
            hash_value = message.substr(delimiter_pos + 1, second_delimiter_pos - delimiter_pos - 1);
            salt = message.substr(second_delimiter_pos + 1);
        }
        else {
            hash_value = message.substr(delimiter_pos + 1);
            salt = "";
        }

        // Count total lines in wordlist
        std::ifstream wordlist(WORDLIST_FILE);
        if (!wordlist.is_open()) {
            std::cerr << "Failed to open wordlist file: " << WORDLIST_FILE << std::endl;
            continue;
        }

        int total_lines = std::count(std::istreambuf_iterator<char>(wordlist),
            std::istreambuf_iterator<char>(), '\n');
        wordlist.close();

        int num_threads = boost::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 2; // fallback to 2 if undetectable
        int chunk_size = total_lines / num_threads;

        // Start the socket reader thread
        boost::thread reader_thread(socket_reader);

        // Start worker threads
        std::vector<boost::thread> threads;
        for (int i = 0; i < num_threads; ++i) {
            int start_line = i * chunk_size;
            int end_line = (i == num_threads - 1) ? total_lines : (i + 1) * chunk_size;
            threads.emplace_back(process_chunk, start_line, end_line, hash_type, hash_value, salt);
        }

        // Join worker threads
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }

        // Only send NO_MATCH once if no password was found
        if (!match_found && (message.find("STOP") == 0)) {
            std::lock_guard<std::mutex> lock(send_mutex);
            boost::asio::write(client_socket, boost::asio::buffer("NO_MATCH\n"));
        }
    }

    client_socket.close();
    return 0;
}