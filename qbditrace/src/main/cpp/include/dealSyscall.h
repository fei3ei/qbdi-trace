//
// Created by chenfangzheng on 2025/7/22.
//

#ifndef QBDI_DEMO_DEALSYSCALL_H
#define QBDI_DEMO_DEALSYSCALL_H
#include <string>
#include <sys/syscall.h>
#include "parseExternalCall.h"

std::string dealSyscall(uint64_t SyscallNumber, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6);


#endif //QBDI_DEMO_DEALSYSCALL_H
