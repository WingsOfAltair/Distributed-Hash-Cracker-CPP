#pragma once
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
#include <sstream>

class BaseAsyncLogger {
public:
    explicit BaseAsyncLogger(const std::string& filename)
        : logFilePath(std::filesystem::absolute(filename)),
        running(true),
        logThread(&BaseAsyncLogger::processQueue, this) {
    }

    virtual ~BaseAsyncLogger() {
        stop();
    }

    void log(const std::string& message) {
        std::lock_guard<std::mutex> lock(queueMutex);
        logQueue.push(formatMessage(message));
        queueCV.notify_one();
    }

    void stop() {
        if (running.exchange(false)) {
            queueCV.notify_all();
            if (logThread.joinable()) logThread.join();
        }
    }

protected:
    virtual std::string formatMessage(const std::string& message) = 0;  // abstract

private:
    std::filesystem::path logFilePath;
    std::queue<std::string> logQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;
    std::thread logThread;
    std::atomic<bool> running;

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
            outFile.flush();
        }

        outFile.close();
    }
};