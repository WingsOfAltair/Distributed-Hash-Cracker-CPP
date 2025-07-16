#pragma once
#include "BaseAsyncLogger.h"

class AsyncStorageLogger : public BaseAsyncLogger {
public:
    using BaseAsyncLogger::BaseAsyncLogger;

protected:
    std::string formatMessage(const std::string& message) override {
        return message;
    }
};