//
// Created by chenfangzheng on 2025/7/15.
//

#ifndef QBDI_DEMO_VM_H
#define QBDI_DEMO_VM_H

#include <QBDI/VM.h>
#include <QBDI/Memory.hpp>
#include "logManager.h"
#include "utils/log.h"
#include "utils/hexdump.h"
#include <cassert>
#include <fmt/core.h>
#include "parseSymbol.h"
#include "dealSyscall.h"
#include <string>
#include <stack>
#define _STACK_SIZE 0x800000 //8MB
class vm{
public:
    static QBDI::VM init(QBDI::rword address, logManager *logData);
private:

};

#endif //QBDI_DEMO_VM_H
