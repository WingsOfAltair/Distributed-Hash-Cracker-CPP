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
#include <scrypt/sodium.h>
#include "include/scrypt/crypto_scrypt.h"           
#include <openssl/sha.h>
#include <scrypt/libscrypt.h>

namespace asio = boost::asio;

using boost::asio::ip::tcp;

// Globals
asio::io_context io_context;
tcp::socket client_socket(io_context);

std::map<std::string, std::string> config;
std::map<std::string, std::string> mutation_list;

std::string WORDLIST_FILE = "";
std::string LINE_COUNT = "";
std::string SERVER_IP = "";
int SERVER_PORT = 0;
std::string SHOW_PROGRESS = "";
std::string AUTO_RECONNECT = "";
std::string MULTI_THREADED = "";
std::vector<std::string> MUTATION_RULES;
AsyncLogger logger("client.log");

bool match_found = false;

int total_lines;

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

std::string wstring_to_utf8(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(wstr);
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

int count_lines(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return 0;
    }

    auto start = std::chrono::high_resolution_clock::now();

    const size_t buffer_size = 1024 * 1024; // 1 MB buffer
    char* buffer = new char[buffer_size];
    std::uintmax_t line_count = 0;

    std::cout << "Counting lines in wordlist..." << std::endl;

    while (file) {
        file.read(buffer, buffer_size);
        std::streamsize bytes_read = file.gcount();
        for (std::streamsize i = 0; i < bytes_read; ++i) {
            if (buffer[i] == '\n') {
                ++line_count;
            }
        }
    }

    delete[] buffer;

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_ms = end - start;

    std::cout << "Line count in wordlist: " + filepath + " is: " + std::to_string(++line_count) <<
        std::endl << "Counting elapsed time: " << duration_ms.count() << " ms." << std::endl;

    return line_count;
}

std::string applyRule(const std::wstring& password, const std::string& rule) {
    // Convert UTF-8 input to wide string for Unicode-safe processing
    std::wstring wresult = password;

    if (rule == "normal") {
        return wstring_to_utf8(password);
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
            wresult.append(boost::locale::conv::to_utf<wchar_t>("123", "UTF-8"));
            continue;

        case '1': // Prepends !
            wresult.insert(wresult.begin(), L'!');
            continue;

        case '2': // Postpends !   
            wresult.append(boost::locale::conv::to_utf<wchar_t>("!", "UTF-8"));
            continue;

        case '3': // Prepends @
            wresult.insert(wresult.begin(), L'@');
            continue;

        case '4': // Postpends @   
            wresult.append(boost::locale::conv::to_utf<wchar_t>("@", "UTF-8"));
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

std::vector<unsigned char> base64_decode(const std::string& input) {
    std::string padded = input;
    while (padded.size() % 4 != 0) {
        padded.push_back('=');
    }

    BIO* bio = BIO_new_mem_buf(padded.data(), static_cast<int>(padded.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  // Disable line breaks
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> decoded(padded.size());
    int decodedLen = BIO_read(bio, decoded.data(), static_cast<int>(decoded.size()));

    BIO_free_all(bio);

    if (decodedLen <= 0) {
        throw std::runtime_error("Base64 decode failed");
    }

    decoded.resize(decodedLen);
    return decoded;
}

// Split string by delimiter
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream tokenStream(s);
    std::string token;
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

bool is_base64_char(char c) {
    return (std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=');
}

bool is_base64_scrypt_hash(const std::string& hash) {
    // Check length roughly 43-44
    if (hash.length() < 43 || hash.length() > 44)
        return false;

    // Check all chars are valid base64 chars
    for (char c : hash) {
        if (!is_base64_char(c)) return false;
    }
    return true;
}

std::string to_hex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

// validate Nodejs's scrypt hash format crypto.scrypt backed by OpenSSL
bool validate_scrypt(const std::string& password, const std::string& salt, 
    const std::string& expected_hex) {
    uint64_t N = 16384;
    uint32_t r = 8;
    uint32_t p = 1;
    size_t key_len = 64;

    std::vector<unsigned char> out(key_len);

    if (crypto_pwhash_scryptsalsa208sha256_ll(
        (const uint8_t*)password.data(), password.size(),
        (const uint8_t*)salt.data(), salt.size(),
        N, r, p, out.data(), key_len) != 0) {
        std::cerr << "scrypt failed (out-of-memory?)\n";
        return false;
    }

    std::string result_hex = to_hex(out.data(), key_len);
    return result_hex == expected_hex;
}

// Constant-time memory comparison
bool secure_compare(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b) {
    if (a.size() != b.size()) return false;
    uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// Hash a password using libsodium's low-level Scrypt and a custom salt.
// Returns the hash as a base64 string.
std::string scrypt_hash_password_libsodium(const std::string& password, const std::string& salt_str) {
    const std::size_t HASH_LEN = 32;
    const std::uint64_t N = 1 << 15;  // CPU cost
    const std::uint32_t r = 8;        // Memory cost
    const std::uint32_t p = 1;        // Parallelism

    unsigned char hash[HASH_LEN];

    const uint8_t* salt = reinterpret_cast<const uint8_t*>(salt_str.data());
    std::size_t salt_len = salt_str.size();

    if (crypto_pwhash_scryptsalsa208sha256_ll(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt, salt_len,
        N, r, p,
        hash, HASH_LEN) != 0) {
        throw std::runtime_error("Scrypt hash failed (likely out of memory)");
    }

    // Calculate base64 buffer size manually
    size_t base64_len = 4 * ((HASH_LEN + 2) / 3) + 1;

    std::vector<char> b64(base64_len);

    sodium_bin2base64(b64.data(), base64_len, hash, HASH_LEN, sodium_base64_VARIANT_ORIGINAL);

    return std::string(b64.data());
}

bool verify_libsodium_hash(const std::string& password, const std::string& stored_b64_hash, const std::string& salt_str) {
    std::string computed_b64_hash = scrypt_hash_password_libsodium(password, salt_str);

    // Constant-time comparison to avoid timing attacks
    return sodium_memcmp(computed_b64_hash.data(), stored_b64_hash.data(), stored_b64_hash.size()) == 0;
}

// Verify PHP-scrypt style hash: N$r$p$salt$hash
bool verify_php_scrypt_hash(const std::string& password, const std::string& fullHash) {
    auto parts = split(fullHash, '$');
    if (parts.size() != 5) return false;

    uint64_t N = std::stoull(parts[0]);
    uint32_t r = std::stoul(parts[1]);
    uint32_t p = std::stoul(parts[2]);

    std::vector<unsigned char> salt = base64_decode(parts[3]);
    std::vector<unsigned char> targetHash = base64_decode(parts[4]);

    std::vector<unsigned char> computedHash(targetHash.size());

    int rc = crypto_scrypt(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(),
        N, r, p,
        computedHash.data(), computedHash.size());

    if (rc != 0) {
        std::cerr << "crypto_scrypt failed\n";
        return false;
    }

    auto print_hex = [](const std::string& label, const std::vector<unsigned char>& data) {
        std::cout << label << ": ";
        for (unsigned char c : data)
            printf("%02x", c);
        std::cout << "\n";
        };

    print_hex("Computed", computedHash);
    print_hex("Target  ", targetHash);   
    print_hex("Salt", salt);          
    std::cout << "Salt size: " << salt.size() << std::endl;          // Should be 16
    std::cout << "Target hash size: " << targetHash.size() << std::endl; // Should be 32

    return secure_compare(computedHash, targetHash);
}

bool verify_scrypt_hash_base64(const std::string& password, const std::string& salt_raw, const std::string& base64_hash) {
    const std::size_t HASH_LEN = 32;
    const std::uint64_t N = 2048;
    const std::uint32_t r = 8;
    const std::uint32_t p = 1;

    unsigned char computed_hash[HASH_LEN];
    unsigned char stored_hash[HASH_LEN];
    unsigned char salt[64]; // Use correct length if salt is binary

    // Use raw salt data directly
    std::memcpy(salt, salt_raw.data(), salt_raw.size());

    // Decode base64 hash into binary
    size_t decoded_len = 0;
    if (sodium_base642bin(stored_hash, HASH_LEN,
        base64_hash.c_str(), base64_hash.length(),
        nullptr, &decoded_len, nullptr,
        sodium_base64_VARIANT_ORIGINAL) != 0) {
        std::cerr << "Failed to decode base64 hash" << std::endl;
        return false;
    }

    if (decoded_len != HASH_LEN) {
        std::cerr << "Hash length mismatch" << std::endl;
        return false;
    }

    // Compute hash
    if (crypto_pwhash_scryptsalsa208sha256_ll(
        reinterpret_cast<const uint8_t*>(password.c_str()), password.size(),
        salt, salt_raw.size(),  // match real salt size
        N, r, p,
        computed_hash, HASH_LEN) != 0) {
        std::cerr << "Out of memory while computing scrypt.\n";
        return false;
    }

    return sodium_memcmp(computed_hash, stored_hash, HASH_LEN) == 0;
}

// Main verify dispatcher
bool verify_scrypt_hash(const std::string& password, std::string& stored_salt_hex, const std::string& hash) {
    if (hash.empty()) return false;

    if (is_base64_scrypt_hash(hash)) {
        // Libsodium modular crypt format
        return verify_libsodium_hash(password, hash, stored_salt_hex) || verify_scrypt_hash_base64(password, stored_salt_hex, hash);
    }
    else if (std::count(hash.begin(), hash.end(), '$') == 4) {
        // PHP style: N$r$p$salt$hash
        return verify_php_scrypt_hash(password, hash);
    }
    else {
        return validate_scrypt(password, stored_salt_hex, hash);
    }
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

        if (message.find("reload") == 0) {
            std::cout << "Received Reload command. Disconnecting & reloading wordlist & mutations' options list.\n";

            config = readFile("config.ini");
            mutation_list = readFile("mutation_list.txt");

            SERVER_IP = config["SERVER_IP"];
            SERVER_PORT = boost::lexical_cast<int>(config["SERVER_PORT"]);
            WORDLIST_FILE = config["WORDLIST_FILE"];
            LINE_COUNT = config["LINE_COUNT"];
            SHOW_PROGRESS = config["SHOW_PROGRESS"];
            MULTI_THREADED = config["MULTI_THREADED"];
            std::string MUTE_RULES = mutation_list["MUTATION_RULES"];

            if (!trim(MUTE_RULES).empty())
                splitAndAppend(MUTE_RULES, MUTATION_RULES);

            if (to_lowercase(MULTI_THREADED) == "true")
            {
                if (to_lowercase(LINE_COUNT) == "auto")
                {
                    total_lines = -1;
                }
                else {
                    total_lines = std::stoi(LINE_COUNT);
                }

                if (total_lines == -1) {
                    total_lines = count_lines(WORDLIST_FILE);
                }
            }
            else {
                total_lines = -1;
            }

            stop_processing.store(true, std::memory_order_release);
            client_socket.close();
            server_disconnected.store(true);
            queue_cv.notify_all();  // Wake up main thread if it's waiting
            break;
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
void process_chunk(int start_line, int end_line, const std::string& hash_type, const std::string& hash_value, std::string& salt) {
    std::ifstream wordlist(WORDLIST_FILE, std::ios::binary);
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

    // Skip lines before the chunk
    while (current_line < start_line && std::getline(wordlist, utf8_word)) {
        if (stop_processing.load(std::memory_order_acquire)) {
            break;
        }
        ++current_line;
    }

    // Process assigned chunk
    while (current_line < end_line && std::getline(wordlist, utf8_word)) { 
        if (stop_processing.load(std::memory_order_acquire)) {
            break;
        }
        std::wstring utf8_word_str_w = boost::locale::conv::to_utf<wchar_t>(utf8_word, "UTF-8");
        boost::algorithm::trim_right_if(utf8_word_str_w, boost::is_any_of("\r\n"));
        std::string utf8_word_str= wstring_to_utf8(utf8_word_str_w);

        try {

            if (MUTATION_RULES.size() > 0)
            {
                for (const std::string& rule : MUTATION_RULES) {
                    if (stop_processing.load(std::memory_order_acquire)) {
                        break;
                    }
                    std::string mutated = applyRule(utf8_word_str_w, rule);
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
                    else if (to_lowercase(hash_type) == "scrypt") {
                        std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (verify_scrypt_hash(mutated, salt, hash_value)) {
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
                else if (to_lowercase(hash_type) == "scrypt") {
                    std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (verify_scrypt_hash(utf8_word_str, salt, hash_value)) {
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

// Process chunk - NO socket reading here!
void process_chunk_single_threaded(const std::string& hash_type, const std::string& hash_value, std::string& salt) {
    std::ifstream wordlist(WORDLIST_FILE, std::ios::binary);
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

    // Process assigned chunk
    while (std::getline(wordlist, utf8_word)) {
        if (stop_processing.load(std::memory_order_acquire)) {
            break;
        }
        std::wstring utf8_word_str_w = boost::locale::conv::to_utf<wchar_t>(utf8_word, "UTF-8");
        boost::algorithm::trim_right_if(utf8_word_str_w, boost::is_any_of("\r\n"));
        std::string utf8_word_str = wstring_to_utf8(utf8_word_str_w);

        try {

            if (MUTATION_RULES.size() > 0)
            {
                for (const std::string& rule : MUTATION_RULES) {
                    if (stop_processing.load(std::memory_order_acquire)) {
                        break;
                    }
                    std::string mutated = applyRule(utf8_word_str_w, rule);
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
                    else if (to_lowercase(hash_type) == "scrypt") {
                        if (to_lowercase(SHOW_PROGRESS) == "true")
                            std::cout << "Validating the hash against the word: " << mutated << std::endl;
                        if (verify_scrypt_hash(mutated, salt, hash_value)) {
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
                else if (to_lowercase(hash_type) == "scrypt") {
                    if (to_lowercase(SHOW_PROGRESS) == "true")
                        std::cout << "Validating the hash against the word: " << utf8_word_str << std::endl;
                    if (verify_scrypt_hash(utf8_word_str, salt, hash_value)) {
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

bool udp_ping(const std::string& ip, int port, int timeout_ms = 1000) {
    using namespace boost::asio;
    boost::asio::io_context io;

    // Replace the problematic line with the following:  
    boost::asio::ip::address server_address = boost::asio::ip::make_address(ip);  
    ip::udp::socket socket(io);
    boost::system::error_code ec;

    socket.open(ip::udp::v4(), ec);
    if (ec) return false;

    boost::asio::ip::udp::endpoint server_endpoint(server_address, port);
    ip::udp::endpoint sender_endpoint;

    // Send "ping"
    std::string message = "ping";
    socket.send_to(buffer(message), server_endpoint, 0, ec);
    if (ec) return false;

    // Set receive timeout
    socket.non_blocking(true);
    char reply[128];
    std::size_t len = 0;

    auto start = std::chrono::steady_clock::now();
    while (true) {
        ec.clear();
        len = socket.receive_from(buffer(reply), sender_endpoint, 0, ec);

        if (!ec && len > 0) {
            std::string response(reply, len);
            return response == "pong";  // or whatever your expected response is
        }

        if ((std::chrono::steady_clock::now() - start) > std::chrono::milliseconds(timeout_ms)) {
            return false;  // timeout
        }

        // Yield to avoid CPU burn
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// Base64 encode a byte vector using libsodium
std::string base64Encode(const std::vector<uint8_t>& data) {
    size_t len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> encoded(len);
    sodium_bin2base64(encoded.data(), len,
        data.data(), data.size(),
        sodium_base64_VARIANT_ORIGINAL);
    return std::string(encoded.data());
}

// Generate deterministic salt from string like PHP
std::vector<uint8_t> generate_salt_from_string(const std::string& input) {
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256())); // 32 bytes for SHA256
    unsigned int hash_len = 0;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP SHA256 digest failed");
    }

    EVP_MD_CTX_free(mdctx);

    // Return first 16 bytes as salt
    return std::vector<uint8_t>(hash.begin(), hash.begin() + 16);
}

void test_php_crypto_scrypt()
{
    std::string password = "jesperhp10";
    std::string salt_str = "123";
    uint64_t N = 16384; // Must be power of 2
    uint32_t r = 8;
    uint32_t p = 1;
    size_t dkLen = 32; // Length of derived key (same as PHP output)

    // Output buffer                                                 
    std::vector<uint8_t> salt2 = generate_salt_from_string(salt_str);
    std::string salt_base64 = base64Encode(salt2);
    std::vector<uint8_t> derivedKey(dkLen);

    // Call scrypt
    int rc = crypto_scrypt(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt2.data(), salt2.size(),
        N, r, p,
        derivedKey.data(), dkLen
    );

    if (rc != 0) {
        std::cerr << "scrypt failed with error code: " << rc << std::endl;
        return;// originally return 1;
    }

    std::cout << N << "$" << r << "$" << p << "$"
        << base64Encode(salt2) << "$"
        << base64Encode(derivedKey) << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Libsodium init failed\n";
        return 1;
    }
    //test_php_crypto_scrypt();
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::locale::global(boost::locale::generator().generate("en_US.UTF-8"));
    std::wcin.imbue(std::locale());
    std::wcout.imbue(std::locale());

    // Read configuration from the file
    config = readFile("config.ini");
    mutation_list = readFile("mutation_list.txt");

    SERVER_IP = config["SERVER_IP"];
    SERVER_PORT = boost::lexical_cast<int>(config["SERVER_PORT"]);
    WORDLIST_FILE = config["WORDLIST_FILE"];
    LINE_COUNT = config["LINE_COUNT"];
    SHOW_PROGRESS = config["SHOW_PROGRESS"];
    MULTI_THREADED = config["MULTI_THREADED"];

    if (to_lowercase(MULTI_THREADED) == "true")
    {
        if (to_lowercase(LINE_COUNT) == "auto")
        {
            total_lines = -1;
        }
        else {
            total_lines = std::stoi(LINE_COUNT);
        }
    }
    else {
        total_lines = -1;
    }

    std::string MUTE_RULES = mutation_list["MUTATION_RULES"];

    if (!trim(MUTE_RULES).empty())
        splitAndAppend(MUTE_RULES, MUTATION_RULES);

    // Attempt to check if server is online or offline.
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(SERVER_IP, std::to_string(SERVER_PORT));

    if (udp_ping(SERVER_IP, SERVER_PORT))
    {
        std::cout << "Server is online." << std::endl;
        stop_processing.store(false);
        server_disconnected.store(true);
    }
    else {
        std::cerr << "Server is offline or the ip/port combination is incorrect." << std::endl;
        server_disconnected.store(true);
    }

    AUTO_RECONNECT = "true";

    std::ifstream wordlist(WORDLIST_FILE);

    if (to_lowercase(MULTI_THREADED) == "true")
    {
        if (total_lines == -1)
        {
            // Count total lines in wordlist
            if (!wordlist.is_open()) {
                std::cerr << "Failed to open wordlist file: " << WORDLIST_FILE << std::endl;
                logger.log("Failed to open wordlist file: " + WORDLIST_FILE);
                return 0;
            }

            total_lines = count_lines(WORDLIST_FILE);
            wordlist.close();
        }
    }

    while (to_lowercase(AUTO_RECONNECT) == "true") {
        AUTO_RECONNECT = config["AUTO_RECONNECT"];
        // Attempt to connect to the server in a loop
        while (server_disconnected && ((to_lowercase(MULTI_THREADED) == "true" && total_lines >= 0) || (to_lowercase(MULTI_THREADED) == "false" && total_lines == -1))) {
            try {
                asio::connect(client_socket, endpoints);
                server_disconnected.store(false);
                stop_processing.store(false);
                std::cout << "Connected to server." << std::endl;
                break; // Successfully connected
            }
            catch (std::exception& e) {
                std::cerr << "Connection failed: " << e.what() << ". Retrying..." << std::endl;
                boost::this_thread::sleep_for(boost::chrono::seconds(1));
            }
        }

        if (to_lowercase(MULTI_THREADED) == "true") {
            if (total_lines == -1)
            {
                std::string message = "Shutting down due to incorrect wordlist file.";
                std::cout << message << std::endl;
                logger.log(message);
                return 0;
            }
        }

        global_socket_ptr = &client_socket;

        while (!server_disconnected && ((to_lowercase(MULTI_THREADED) == "true" && total_lines >= 0) || (to_lowercase(MULTI_THREADED) == "false" && total_lines == -1))) {
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

            if (to_lowercase(MULTI_THREADED) == "true")
            {
                int num_threads = boost::thread::hardware_concurrency();
                if (num_threads == 0) num_threads = 2; // fallback to 2 if undetectable   
                if (total_lines < num_threads) {
                    num_threads = total_lines; // avoid having more threads than lines
                }
                int chunk_size = total_lines / num_threads;
                int remainder = total_lines % num_threads; // for better load balancing

                int start_line = 0;
                // Start worker threads
                std::vector<boost::thread> threads;
                for (int i = 0; i < num_threads; ++i) {
                    if (stop_processing.load(std::memory_order_acquire)) {
                        break;
                    }
                    int lines_for_this_thread = chunk_size + (i < remainder ? 1 : 0);
                    int end_line = start_line + lines_for_this_thread;
                    threads.emplace_back(process_chunk, start_line, end_line, hash_type, hash_value, salt);
                    start_line = end_line;
                }

                // Join worker threads
                for (auto& t : threads) {
                    if (t.joinable()) t.join();
                }
            }
            else {
                process_chunk_single_threaded(hash_type, hash_value, salt);
            }

            // Only send NO_MATCH once if no password was found
            if (!match_found && (message.find("STOP") == 0)) {
                std::lock_guard<std::mutex> lock(send_mutex);
                boost::asio::write(client_socket, boost::asio::buffer("NO_MATCH\n"));
            }
        }
    }
    client_socket.close();
    return 0;
}