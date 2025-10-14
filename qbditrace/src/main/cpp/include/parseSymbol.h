//
// Created by chenfangzheng on 2025/7/21.
//

#ifndef QBDI_DEMO_PARSESYMBOL_H
#define QBDI_DEMO_PARSESYMBOL_H

#include <LIEF/LIEF.hpp>
#include <QBDI/State.h>
#include <QBDI.h>
#include "utils/log.h"
#include <string>
#include <fmt/core.h>
#include <elf.h>
typedef struct {
    QBDI::rword start;
    QBDI::rword end;
    std::string path;
} moduleInfo;

void initModuleInfo();
std::string get_SymbolName_by_address(QBDI::rword address);
std::string get_prefix_by_address(QBDI::rword address);
void get_Module_internal_Symbol(std::string path, QBDI::rword base);
void initModuleSection(std::string moduleName);
void parse_Symbol_from_Memory(QBDI::rword address);
#endif //QBDI_DEMO_PARSESYMBOL_H
