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
#include <cwctype> 
#include <boost/locale.hpp>
#include <codecvt>
#include <algorithm>
#include "../shared/AsyncLogger.h"

namespace asio = boost::asio;

using boost::asio::ip::tcp;

// Globals
asio::io_context io_context;
tcp::socket client_socket(io_context);

std::string WORDLIST_FILE = "";
std::string SERVER_IP = "";
int SERVER_PORT = 0;
std::string SHOW_PROGRESS = "";
std::string AUTO_RECONNECT = "";
std::vector<std::string> MUTATION_RULES;
AsyncLogger logger("client.log");

bool match_found = false;

std::mutex send_mutex;           // Mutex for sending messages to the server
std::atomic<bool> stop_processing(false);  // Global flag for stopping threads
std::atomic<bool> server_disconnected(false);

// Pointer to client socket, shared for reading thread and workers
boost::asio::ip::tcp::socket* global_socket_ptr = nullptr;

// Thread-safe message queue
std::queue<std::string> message_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;

// Function to read config/settings files
std::map<std::string, std::string> readFile(const std::string& filename) {
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

// Returns a trimmed copy of the input string
inline std::string trim(const std::string& s) {
    auto start = std::find_if_not(s.begin(), s.end(),
        [](unsigned char ch) { return std::isspace(ch); });

    auto end = std::find_if_not(s.rbegin(), s.rend(),
        [](unsigned char ch) { return std::isspace(ch); }).base();

    if (start >= end) return ""; // All whitespace or empty
    return std::string(start, end);
}

std::wstring utf8_to_wstring(const std::string& str) {
    return boost::locale::conv::to_utf<wchar_t>(str, "UTF-8");
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    return boost::locale::conv::from_utf<wchar_t>(wstr, "UTF-8");
}

std::string applyRule(const std::string& password, const std::string& rule) {
    // Convert UTF-8 input to wide string for Unicode-safe processing
    std::wstring wresult = utf8_to_wstring(password);

    if (rule == "normal") {
        return password;
    }

    for (size_t i = 0; i < rule.size(); ++i) {
        char cmd = rule[i];

        switch (cmd) {
        case 'l': // Lowercase (Unicode-aware)
            std::transform(wresult.begin(), wresult.end(), wresult.begin(),
                [](wchar_t ch) { return std::towlower(ch); });
            continue;

        case 'u': // Uppercase (Unicode-aware)
            std::transform(wresult.begin(), wresult.end(), wresult.begin(),
                [](wchar_t ch) { return std::towupper(ch); });
            continue;

        case 'r': // Reverse
            std::reverse(wresult.begin(), wresult.end());
            continue;

        case 'c': // Capitalize first letter (Unicode-aware)
            if (!wresult.empty())
                wresult[0] = std::towupper(wresult[0]);
            continue;

        case 't': // Toggle case (Unicode-aware)
            for (wchar_t& ch : wresult) {
                if (std::iswlower(ch))
                    ch = std::towupper(ch);
                else if (std::iswupper(ch))
                    ch = std::towlower(ch);
                // else leave as is (e.g., digits, punctuation)
            }
            continue;

        case 'd': // Duplicate
            wresult += wresult;
            continue;

        case 's': // Substitute sXY (simple char replacement on wide chars)
            if (i + 2 < rule.size()) {
                // Convert src and dst from char (assumed ASCII) to wchar_t for substitution
                wchar_t src = static_cast<wchar_t>(rule[++i]);
                wchar_t dst = static_cast<wchar_t>(rule[++i]);
                for (wchar_t& ch : wresult) {
                    if (ch == src)
                        ch = dst;
                }
            }
            continue;

        case 'n': // Append Numbers (append ASCII digits as wide chars)
            wresult.append(utf8_to_wstring("123"));
            continue;

        case '1': // Prepends !
            wresult.insert(wresult.begin(), L'!');
            continue;

        case '2': // Postpends !   
            wresult.append(utf8_to_wstring("!"));
            continue;

        case '3': // Prepends @
            wresult.insert(wresult.begin(), L'@');
            continue;

        case '4': // Postpends @   
            wresult.append(utf8_to_wstring("@"));
            continue;

        case '5': // Replaces @ with 4
            for (auto& ch : wresult) {
                if (ch == L'@') {
                    ch = L'4';
                }
            }
            continue;

        case 'p': // L33tSpeak substitution - works only on ASCII letters
        {
            static const std::unordered_map<wchar_t, wchar_t> leet = {
                {L'a', L'@'}, {L'e', L'3'}, {L'i', L'1'}, {L'o', L'0'}, {L's', L'$'}, {L't', L'7'}
            };

            for (wchar_t& ch : wresult) {
                wchar_t lower = std::towlower(ch);
                auto it = leet.find(lower);
                if (it != leet.end()) {
                    ch = it->second;
                }
            }
            continue;
        }

        default:
            std::cerr << "Unsupported rule command: " << cmd << ", removing now.\n";
            MUTATION_RULES.erase(
                std::remove(MUTATION_RULES.begin(), MUTATION_RULES.end(), rule),
                MUTATION_RULES.end()
            );
            break;
        }
    }

    // Convert back to UTF-8 before returning
    return wstring_to_utf8(wresult);
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
        logger.log(match_message);
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
            server_disconnected.store(true);
            queue_cv.notify_all();  // Wake up main thread if it's waiting
            return;
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
    for (int i = start_line; i <= end_line && std::getline(wordlist, utf8_word); ++i) {
        if (stop_processing.load(std::memory_order_acquire)) {
            break;
        }
        std::string utf8_word_str;

        try {
            utf8_word_str = utf8_word;

            if (MUTATION_RULES.size() > 0)
            {
                for (const std::string& rule : MUTATION_RULES) {
                    if (stop_processing.load(std::memory_order_acquire)) {
                        break;
                    }
                    std::string mutated = applyRule(utf8_word_str, rule);
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Rule: " << rule << " = " << mutated << std::endl;

                    if (to_lowercase(hash_type) == "bcrypt") {
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (BCrypt::validatePassword(mutated, hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                    else if (to_lowercase(hash_type) == "argon2") {
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (verify_argon2_encoded(mutated, hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                    else {
                        std::string input_with_salt = mutated + salt;
                        std::string calculated_hash = calculate_hash(hash_type, input_with_salt);
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Calculated password: " << mutated << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;
                        if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                            if (!match_found) {
                                report_match(mutated, current_line, *global_socket_ptr, WORDLIST_FILE);
                            }
                        }
                    }
                }
            }
            else {
                if (to_lowercase(hash_type) == "bcrypt") {
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (BCrypt::validatePassword(utf8_word_str, hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
                else if (to_lowercase(hash_type) == "argon2") {
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (verify_argon2_encoded(utf8_word_str, hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
                else {
                    std::string input_with_salt = utf8_word_str + salt;
                    std::string calculated_hash = calculate_hash(hash_type, input_with_salt);
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Calculated password: " << utf8_word_str << " with salt: " << salt << ", calculated hash: " << calculated_hash << std::endl;
                    if (to_lowercase(calculated_hash) == to_lowercase(hash_value)) {
                        if (!match_found) {
                            report_match(utf8_word_str, current_line, *global_socket_ptr, WORDLIST_FILE);
                        }
                    }
                }
            }
            current_line++;
        }
        catch (const std::exception& err) { 
            std::ostringstream oss;
            oss << "Error occurred during processing word: " << utf8_word_str
                << " on line: " << current_line << "." << std::endl
                << err.what();
            std::string errText = oss.str();
            std::cerr << errText << std::endl;
            logger.log(errText);
            current_line++;
        }
    }
}                

void splitAndAppend(const std::string& input, std::vector<std::string>& output) {
    std::stringstream ss(input);
    std::string token;

    while (std::getline(ss, token, ',')) {
        std::stringstream subss(token);
        std::string word;

        while (subss >> word) {
            output.push_back(word);
        }
    }
}

int main() {
    // Read configuration from the file
    std::map<std::string, std::string> config = readFile("config.ini");
    std::map<std::string, std::string> mutation_list = readFile("mutation_list.txt");

    SERVER_IP = config["SERVER_IP"];
    SERVER_PORT = boost::lexical_cast<int>(config["SERVER_PORT"]);
    WORDLIST_FILE = config["WORDLIST_FILE"];
    SHOW_PROGRESS = config["SHOW_PROGRESS"];
    std::string MUTE_RULES = mutation_list["MUTATION_RULES"];

    if (!trim(MUTE_RULES).empty())
        splitAndAppend(MUTE_RULES, MUTATION_RULES);

    AUTO_RECONNECT = "true";
    server_disconnected.store(true);

    std::locale::global(boost::locale::generator().generate("en_US.UTF-8"));

    // Attempt to connect to the server in a loop
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(SERVER_IP, std::to_string(SERVER_PORT));

    while (to_lowercase(AUTO_RECONNECT) == "true" && server_disconnected && !stop_processing) {
        AUTO_RECONNECT = config["AUTO_RECONNECT"];
        while (server_disconnected) {
            try {
                asio::connect(client_socket, endpoints);
                server_disconnected.store(false);
                break; // Successfully connected
            }
            catch (std::exception& e) {
                std::cerr << "Connection failed: " << e.what() << ". Retrying..." << std::endl;
                boost::this_thread::sleep_for(boost::chrono::seconds(1));
            }
        }

        global_socket_ptr = &client_socket;

        while (!server_disconnected) {
            match_found = false;
            stop_processing.store(false);
            boost::thread reader_thread(socket_reader);
            std::string readyStr = "Ready to accept new requests.";
            std::cout << readyStr << std::endl;

            // Send ready message to server
            asio::write(client_socket, asio::buffer(readyStr + "\n"));

            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, [] { return !message_queue.empty() || server_disconnected.load(); });

			if (server_disconnected.load()) {
                stop_processing.store(false);
				continue; // Exit the loop if server is disconnected
			}

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

			if (hash_type.empty() || hash_value.empty()) {
				std::cerr << "Invalid request from server: " << message << std::endl;
				continue;
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

            total_lines++;

            int num_threads = boost::thread::hardware_concurrency();
            if (num_threads == 0) num_threads = 2; // fallback to 2 if undetectable   
            if (total_lines < num_threads) {
                num_threads = total_lines; // avoid having more threads than lines
            }
            int chunk_size = total_lines / num_threads;
            int remainder = total_lines % num_threads; // for better load balancing

            int current_line = 0;

            // Start worker threads
            std::vector<boost::thread> threads;
            for (int i = 0; i < num_threads; ++i) {
                int start_line = current_line;
                int end_line = (i == num_threads - 1) ? total_lines : (i + 1) * chunk_size + (i < remainder ? 1 : 0);
                threads.emplace_back(process_chunk, start_line, end_line, hash_type, hash_value, salt);
                current_line = end_line; // Update for next thread
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
    }
    return 0;
}