//
// Created by chenfangzheng on 2025/8/6.
//

#ifndef QBDITRACE_LOG_H
#define QBDITRACE_LOG_H
#include <android/log.h>
#define LOG_TAG "[fei3ei-qbdi]"
#define  LOGV(...)  __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif //QBDITRACE_LOG_H
