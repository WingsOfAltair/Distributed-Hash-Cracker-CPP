#pragma once
#include "BaseAsyncLogger.h"

class AsyncLogger : public BaseAsyncLogger {
public:
    using BaseAsyncLogger::BaseAsyncLogger;

protected:
    std::string formatMessage(const std::string& message) override {
        return timestamp() + " " + message;
    }

private:
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
};