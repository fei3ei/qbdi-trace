//
// Created by chenfangzheng on 2025/10/14.
//
#include "crc32.h"

uint32_t crc32(const uint8_t *data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i   = 0; i < size; i++) {
        crc ^= data[i];
        for (size_t j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}