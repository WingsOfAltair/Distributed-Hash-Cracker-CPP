#include <iostream>
#include <fstream>
#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <chrono>
#include <iomanip>
#include <atomic>
#include <filesystem>

class AsyncLogger {
public:
    AsyncLogger(const std::string& filename)
        : logFilePath(std::filesystem::absolute(filename)), running(true), logThread(&AsyncLogger::processQueue, this) {
    }

    ~AsyncLogger() {
        stop();
    }

    void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push(timestamp() + " " + message);
        queueCV.notify_one();
    }

    void stop() {
        if (running.exchange(false)) {
            queueCV.notify_all();
            if (logThread.joinable()) logThread.join();
        }
    }

private:
    std::filesystem::path logFilePath;
    std::queue<std::string> logQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;
    std::thread logThread;
    std::atomic<bool> running;

    std::string timestamp() {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &now_c);
#else
        localtime_r(&now_c, &tm);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    void processQueue() {
        std::ofstream outFile(logFilePath, std::ios::app);
        if (!outFile.is_open()) {
            std::cerr << "Failed to open log file: " << logFilePath << std::endl;
            return;
        }

        while (running || !logQueue.empty()) {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this]() { return !logQueue.empty() || !running; });

            while (!logQueue.empty()) {
                outFile << logQueue.front() << '\n';
                logQueue.pop();
            }
            outFile.flush(); // optional: flush to disk each batch
        }

        outFile.close();
    }
};
