//
// Created by chenfangzheng on 2025/7/21.
//
#include "parseSymbol.h"
std::map<QBDI::rword, std::string> symbolNameCache; //address -> symbol name
std::map<std::string, moduleInfo> moduleInfoCache; //module name -> module base
QBDI::rword thisModuleTextStart = 0x0;
QBDI::rword thisModuleTextEnd = 0x0;
QBDI::rword thisModuleStart = 0x0;
QBDI::rword thisModulePltStart = 0x0;
QBDI::rword thisModulePltEnd = 0x0;
std::vector<std::string> excludeModules = {"libmsaoaidsec.so", "libmsaoaidauth.so"};
void initModuleInfo(){
    for(QBDI::MemoryMap& map : QBDI::getCurrentProcessMaps(true)){
        std::string modulePath = map.name;
        if(modulePath.ends_with(".so")){
            std::string moduleName = modulePath.substr(modulePath.find_last_of('/') + 1);
            if(std::find(excludeModules.begin(), excludeModules.end(), moduleName) != excludeModules.end()) {
                continue;
            }
            if(moduleInfoCache.find(moduleName) == moduleInfoCache.end()){ //初始化一个moduleInfo
                LOGI("Module path: %s ", modulePath.c_str());
                moduleInfo info;
                info.path = modulePath;
                info.start = map.range.start();
                std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(modulePath);
                const LIEF::ELF::Section* text_section = elf->get_section(".text");
                info.end = text_section->virtual_address() + text_section->size() + info.start;
                moduleInfoCache[moduleName] = info; //将这个module的信息加入到缓存中
            }
        }
    }
    LOGI("Module info initialized with %zu modules", moduleInfoCache.size());
}

std::string get_SymbolName_by_address(QBDI::rword address) {
    if (symbolNameCache.find(address) == symbolNameCache.end()) { //该地址的符号信息没有缓存，那么将此so的符号
        for(const auto& [name, info] : moduleInfoCache) {
            if (address >= info.start && address < info.end) { //如果地址在这个so的范围内,则开始解析该so的符号
                get_Module_internal_Symbol(info.path, info.start);
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
    std::string moduleName;
    for(const auto& [name, info] : moduleInfoCache) {
        if (address >= info.start && address < info.end) { //如果地址在这个so的范围内,则开始解析该so的符号
            moduleName = name;
            break;
        }
    }
    if(moduleInfoCache.find(moduleName) == moduleInfoCache.end()) {
        LOGE("Module %s not found in cache", moduleName.c_str());
        return;
    }
    QBDI::rword base = moduleInfoCache[moduleName].start;
    std::string path = moduleInfoCache[moduleName].path;
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
    for(const auto& [name, info] : moduleInfoCache) {
        if (address >= info.start && address < info.end) { //如果地址在这个so的范围内,则开始解析该so的符号
            prefix = fmt::format("[{}!{:#x}]", name, address - info.start);
            return prefix;
        }
    }
    prefix = fmt::format("[unknown.so!{:#x}]", address);
    return prefix;
}

void initModuleSection(std::string moduleName){
    thisModuleStart = moduleInfoCache[moduleName].start;
    std::unique_ptr<LIEF::ELF::Binary> elf = LIEF::ELF::Parser::parse(moduleInfoCache[moduleName].path);
    const LIEF::ELF::Section* text_section = elf->get_section(".text");
    if (text_section) {
        thisModuleTextStart = text_section->virtual_address() + moduleInfoCache[moduleName].start;
        thisModuleTextEnd = thisModuleTextStart + text_section->size();
        LOGI("Module %s text section: Start: %#lx, End: %#lx", moduleName.c_str(), thisModuleTextStart, thisModuleTextEnd);
    } else {
        LOGE("No .text section found in module %s", moduleName.c_str());
    }

    const LIEF::ELF::Section* plt_section = elf->get_section(".plt");
    if (text_section) {
        thisModulePltStart = plt_section->virtual_address() + moduleInfoCache[moduleName].start;
        thisModulePltEnd = thisModulePltStart + plt_section->size();
        LOGI("Module %s plt section: Start: %#lx, End: %#lx", moduleName.c_str(), thisModulePltStart, thisModulePltEnd);
    } else {
        LOGE("No .plt section found in module %s", moduleName.c_str());
    }
}
