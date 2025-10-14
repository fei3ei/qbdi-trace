//
// Created by chenfangzheng on 2025/7/15.
//

#include <string>
#include <cassert>
#include "vm.h"
#include <fcntl.h>
#include <sys/mman.h>


extern "C"
__attribute__((visibility("default")))
QBDI::rword start_trace(QBDI::rword targetFuncAddr, const QBDI::rword *argsPtr, uint32_t argNum, const std::string *logpathPtr){
    QBDI::GPRState *state;
    QBDI::rword retval;
    auto vm_ = new vm();
    assert(vm_ != nullptr);
    logManager *logData = new logManager(logpathPtr);
    auto qvm = vm_->init(targetFuncAddr, logData);
    state = qvm.getGPRState();
    assert(state != nullptr);
    //设置虚拟机的栈的大小
    uint8_t *fakestack = nullptr;
    QBDI::allocateVirtualStack(state, _STACK_SIZE, &fakestack);
    qvm.callA(&retval, targetFuncAddr, argNum, argsPtr);
    QBDI::alignedFree(fakestack);
    delete logData;
    return retval;
}



//test测试代码
#include <jni.h>

extern "C"
JNIEXPORT jstring JNICALL
Java_com_fei3ei_qbditrace_MainActivity_stringFromJNI(JNIEnv *env, jobject thiz) {
    std::string hello = "fei3ei qbdi";
    return env->NewStringUTF(hello.c_str());
}