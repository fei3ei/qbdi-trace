//
// Created by chenfangzheng on 2025/8/6.
//

#ifndef QBDITRACE_HEXDUMP_H
#define QBDITRACE_HEXDUMP_H
#include <cctype>
#include <string>
#include <fmt/core.h>
#include <android/log.h>
#define LOGI_FMT(...) \
    do { \
        std::string _log = fmt::format(__VA_ARGS__); \
        __android_log_write(ANDROID_LOG_INFO, "Hexdump", _log.c_str()); \
    } while (0)

/**
 * @brief CustomHexdump struct - templated hex dump utility
 * @tparam RowSize - Number of bytes per row
 * @tparam ShowAscii - Whether to show ASCII representation
 */
template <unsigned RowSize, bool ShowAscii>
struct CustomHexdump {
    CustomHexdump(const void* data, unsigned length)
            : mData(static_cast<const unsigned char*>(data)), mLength(length) {
        dump(); // 🔥 自动打印
    }

private:
    void dump() const {
        for (unsigned i = 0; i < mLength; i += RowSize) {
            std::string hexPart;
            std::string asciiPart;

            for (unsigned j = 0; j < RowSize; ++j) {
                if (i + j < mLength) {
                    hexPart += fmt::format("{:02x} ", mData[i + j]);
                    if constexpr (ShowAscii) {
                        unsigned char ch = mData[i + j];
                        asciiPart += std::isprint(ch) ? static_cast<char>(ch) : '.';
                    }
                } else {
                    hexPart += "   ";
                    if constexpr (ShowAscii) {
                        asciiPart += ' ';
                    }
                }
            }
            if constexpr (ShowAscii) {
                LOGI_FMT("{:#018x}: {:<48}|{}|", reinterpret_cast<uintptr_t>(mData + i), hexPart, asciiPart);
            } else {
                LOGI_FMT("{:#018x}: {}", reinterpret_cast<uintptr_t>(mData + i), hexPart);
            }
        }
    }

    const unsigned char* mData;
    const unsigned mLength;
};

// 默认行宽为 16，显示 ASCII
using Hexdump = CustomHexdump<16, true>;

#endif //QBDITRACE_HEXDUMP_H
