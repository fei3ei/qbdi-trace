//
// Created by chenfangzheng on 2025/7/15.
//

#ifndef QBDI_DEMO_LOGMANAGER_H
#define QBDI_DEMO_LOGMANAGER_H
#include <string>
#include "utils/log.h"

class logManager {
public:
    explicit logManager(const std::string *filename){
        fileHandle = fopen(reinterpret_cast<const char *>(filename), "w");
        if(fileHandle == NULL ){
//            __android_log_print(ANDROID_LOG_ERROR, "LogManager", "Failed to open log file: %s.", filename->c_str());
            LOGE("Failed to open log file: %s.", filename->c_str());
        }
    }
    ~logManager(){
        fclose(fileHandle);
    }

    void logPrint(const char* message) {
        if(fileHandle == NULL){
//            __android_log_print(ANDROID_LOG_ERROR, "LogManager", "File handle is null, cannot write it.");
            LOGE("File handle is null, cannot write it.");
            return;
        }
        if (fputs(message, fileHandle) == EOF) {
//            __android_log_print(ANDROID_LOG_ERROR, "LogManager", "fputs call fail.");
            LOGE("fputs call fail.");
        }
        fflush(fileHandle);
    }
    int suojinNum = 0; //用于记录日志缩进的数量
private:
    FILE* fileHandle;
};


#endif //QBDI_DEMO_LOGMANAGER_H
