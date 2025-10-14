//
// Created by chenfangzheng on 2025/7/21.
//
#include "parseSymbol.h"
#include "crc32.h"
#include "hexdump.h"
std::map<QBDI::rword, std::string> symbolNameCache; //address -> symbol name
std::map<std::string, moduleInfo> moduleInfoCache; //module name -> module base
QBDI::rword thisModuleStart = 0x0;
std::vector<std::string> excludeModules = {"libmsaoaidsec.so", "libmsaoaidauth.so"};
std::string tmpModuleID = "";
void initModuleInfo(){
    for(QBDI::MemoryMap& map : QBDI::getCurrentProcessMaps(true)){
        std::string modulePath = map.name;
        if(modulePath.ends_with(".so")){ //说明是一个so文件
            std::string moduleName = modulePath.substr(modulePath.find_last_of('/') + 1);
            if(std::find(excludeModules.begin(), excludeModules.end(), moduleName) != excludeModules.end()) { //排除列表中的模块
                continue;
            }
            if(*(uint32_t*)map.range.start() == 0x464c457f){ //开头为elf的魔术，初始化一个moduleInfo
                moduleInfo info;
                info.path = modulePath;
                info.base = map.range.start();
                info.exeStart = 0xffffffffffffffff;
                info.exeEnd = 0;
                std::string moduleID = fmt::format("{}_{:x}", moduleName, info.base);
                tmpModuleID = moduleID;
                moduleInfoCache[moduleID] = info; //将这个module的信息加入到缓存中
            }else{ //模块已经被缓存了
                if((map.permission & QBDI::PF_EXEC) != 0){
                    if(map.range.start() < moduleInfoCache[tmpModuleID].exeStart){
                        moduleInfoCache[tmpModuleID].exeStart = map.range.start();
                    }
                    if(map.range.end() > moduleInfoCache[tmpModuleID].exeEnd) {
                        moduleInfoCache[tmpModuleID].exeEnd = map.range.end();
                    }
                }
            }
        }
    }
    LOGI("Module info initialized with %zu modules", moduleInfoCache.size());
}

std::string get_SymbolName_by_address(QBDI::rword address) {
    if (symbolNameCache.find(address) == symbolNameCache.end()) { //该地址的符号信息没有缓存，那么将此so的符号
        for(const auto& [name, info] : moduleInfoCache) {
            if (address >= info.exeStart && address < info.exeEnd) { //如果地址在这个so的范围内,则开始解析该so的符号
                get_Module_internal_Symbol(info.path, info.base);
                break;
            }
        }
    }
    if(symbolNameCache.find(address) != symbolNameCache.end()) { //如果缓存中有这个地址的符号信息
        return symbolNameCache[address];
    }
    LOGI("Symbol not found, try find so in memory");
    initModuleInfo(); //这个so可能现在才加载进去
    parse_Symbol_from_Memory(address);//从内存中解析符号信息
    if(symbolNameCache.find(address) != symbolNameCache.end()) { //如果缓存中有这个地址的符号信息
        return symbolNameCache[address];
    }
    symbolNameCache[address] = "unknown"; //如果还是没有找到符号信息，则返回unknown
    LOGE("Symbol not found for address: %#lx", address);
    return "unknown";
}

void get_Module_internal_Symbol(std::string path, QBDI::rword base) {
    std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(path);
    if(elf->has_section(".symtab")){
        for(const LIEF::ELF::Symbol& sym : elf->symtab_symbols()){ //这里直接获取symtab里面的函数
            if(sym.is_function() && sym.is_imported() == 0 && sym.value() != 0){ //是函数且不是导入的函数
                if(sym.demangled_name() == "") { //如果没有demangled_name，则使用name
                    symbolNameCache[sym.value() + base] = sym.name();
                } else { //如果有demangled_name，则使用demangled_name
                    symbolNameCache[sym.value() + base] = sym.demangled_name();
                }
            }
        }
    }else if(elf->has_section(".dynsym")){
        for(const LIEF::ELF::Symbol& sym : elf->dynamic_symbols()){ //这里直接获取dynamic symtab里面的函数
            if(sym.is_function() && sym.is_imported() == 0 && sym.value() != 0){ //是函数且不是导入的函数
                if(sym.demangled_name() == "") { //如果没有demangled_name，则使用name
                    symbolNameCache[sym.value() + base] = sym.name();
                } else { //如果有demangled_name，则使用demangled_name
                    symbolNameCache[sym.value() + base] = sym.demangled_name();
                }
            }
        }
    }else{
        LOGE("No symbol and dynamic symbol table found in %s", path.c_str());
    }
    LOGI("Parsed symbols from %s", path.c_str());
}

void parse_Symbol_from_Memory(QBDI::rword address){
    std::string moduleID;
    for(const auto& [ID, info] : moduleInfoCache) {
        if (address >= info.exeStart && address < info.exeEnd) { //如果地址在这个so的范围内,则开始解析该so的符号
            moduleID = ID;
            break;
        }
    }
    if(moduleInfoCache.find(moduleID) == moduleInfoCache.end()) {
        LOGE("Module %s not found in cache", moduleID.c_str());
        return;
    }
    QBDI::rword base = moduleInfoCache[moduleID].base;
    std::string path = moduleInfoCache[moduleID].path;
    std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(path);
    const LIEF::ELF::Section* dynstr_section = elf->get_section(".dynstr");
    const char* dynstr = reinterpret_cast<const char*>(base + dynstr_section->virtual_address());
    const LIEF::ELF::Section* dynsym_section = elf->get_section(".dynsym");
    uint64_t dynsym_table_size = dynsym_section->size() / dynsym_section->entry_size();
    Elf64_Sym* dynsym_table = reinterpret_cast<Elf64_Sym*>(base + dynsym_section->virtual_address());
    for(uint64_t i = 1; i < dynsym_table_size; i++) {
        std::string symbolName = dynstr + dynsym_table[i].st_name;
        if(dynsym_table[i].st_value == 0) continue;
        QBDI::rword symboladdress = base + dynsym_table[i].st_value;
        symbolNameCache[symboladdress] = symbolName; //将符号地址和符号名加入缓存
    }
}
std::string get_prefix_by_address(QBDI::rword address){
    std::string prefix;
    for(const auto& [moduleID, info] : moduleInfoCache) {
        if (address >= info.exeStart && address < info.exeEnd) { //如果地址在这个so的范围内,则开始解析该so的符号
            std::string name = moduleID.substr(0, moduleID.find('_'));
            prefix = fmt::format("[{}!{:#x}]", name, address - info.base);
            return prefix;
        }
    }
    prefix = fmt::format("[unknown.so!{:#x}]", address);
    return prefix;
}

void initModuleStart(std::string moduleName){
    for(const auto& [moduleID, info] : moduleInfoCache) {
        if(moduleID.starts_with(moduleName)) {
            thisModuleStart = info.base;
            LOGI("this module %s start at %#lx", moduleName.c_str(), thisModuleStart);
            return;
        }
    }
}
