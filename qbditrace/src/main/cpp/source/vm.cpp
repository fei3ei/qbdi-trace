#include "vm.h"
#include <stack>
extern QBDI::rword thisModuleStart;
std::stack<QBDI::rword> retaddrStack;
QBDI::VMAction // deal with BL
dealPostInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis();
    if(instAnalysis->isCall && strcmp(instAnalysis->mnemonic, "BL") == 0) { //BL指令多用于内部模块的调用
        auto* logData = reinterpret_cast<logManager *>(data);
        retaddrStack.push(gprState->lr);
        std::string logtext;
        logtext = fmt::format("{:>{}}{}call sub_{:X}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(instAnalysis->address), gprState->pc - thisModuleStart);
        logData->suojinNum++;
        logData->logPrint(logtext.c_str());
        return QBDI::VMAction::CONTINUE;
    }else{
        QBDI::rword addr = instAnalysis->address;
        if(!retaddrStack.empty() && addr == retaddrStack.top()) { //函数返回
            retaddrStack.pop();
            auto *logData = reinterpret_cast<logManager *>(data);
            logData->suojinNum--;
        }
    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction
dealSVCPreInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
//#include <private/bionic_asm.h>
//
//    ENTRY(syscall)
//    /* Move syscall No. from x0 to x8 */
//    mov     x8, x0
//    /* Move syscall parameters from x1 thru x6 to x0 thru x5 */
//    mov     x0, x1
//    mov     x1, x2
//    mov     x2, x3
//    mov     x3, x4
//    mov     x4, x5
//    mov     x5, x6
//    svc     #0
//
//    /* check if syscall returned successfully */
//    cmn     x0, #(MAX_ERRNO + 1)
//    cneg    x0, x0, hi
//    b.hi    __set_errno_internal
//
//            ret
//    END(syscall)
//
//    NOTE_GNU_PROPERTY()
    std::string logtext;
    auto* logData = reinterpret_cast<logManager *>(data);
    uint64_t SVCNumber = gprState->x8;
    uint64_t arg1 = gprState->x0;
    uint64_t arg2 = gprState->x1;
    uint64_t arg3 = gprState->x2;
    uint64_t arg4 = gprState->x3;
    uint64_t arg5 = gprState->x4;
    uint64_t arg6 = gprState->x5;
    logtext = fmt::format("{:>{}}{}SVC: {}\n", " ", logData->suojinNum * 4,
                          get_prefix_by_address(gprState->pc) ,dealSyscall(SVCNumber, arg1, arg2, arg3, arg4, arg5, arg6));
    logData->logPrint(logtext.c_str());
    logData->suojinNum++;
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction
dealSVCPostInstruction(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {


    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction
dealCallEvent(QBDI::VM *vm, const QBDI::VMState *vmState, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    // Check that the event is a CALL
    if ((vmState->event & QBDI::EXEC_TRANSFER_CALL) == 0) {
        return QBDI::CONTINUE;
    }
    std::string funcName = get_SymbolName_by_address(gprState->pc);
    std::string logtext;
    auto* logData = reinterpret_cast<logManager *>(data);
    uint64_t x0 = gprState->x0;
    uint64_t x1 = gprState->x1;
    uint64_t x2 = gprState->x2;
    uint64_t x3 = gprState->x3;
    uint64_t x4 = gprState->x4;
    uint64_t x5 = gprState->x5;
    uint64_t x6 = gprState->x6;
    if( funcName == "unknown"){
        logtext = fmt::format("{:>{}} unknown function{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc));
    //下面的就是得到了函数名字的外部调用，根据需要再处理函数参数的打印
    }else if (funcName == "syscall") { //通过syscall调用的外部函数需要单独处理
        uint64_t SVCNumber = x0;
        uint64_t arg1 = x1;
        uint64_t arg2 = x2;
        uint64_t arg3 = x3;
        uint64_t arg4 = x4;
        uint64_t arg5 = x5;
        uint64_t arg6 = x6;
        logtext = fmt::format("{:>{}}{}syscall: {}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc),
                              dealSyscall(SVCNumber, arg1, arg2, arg3, arg4, arg5, arg6));
        //下面是没有用syscall调用的外部函数，处理了参数的打印
    }else if(funcName == "pthread_create"){
        uint64_t thread = x0;
        uint64_t attr = x1;
        uint64_t start_routine = x2;
        uint64_t arg = x3;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_pthread_create(thread, attr, start_routine - thisModuleStart, arg));
    }else if(funcName.find("mmap") != std::string::npos) {
        uint64_t addr = x0;
        uint64_t length = x1;
        int prot = (int)x2;
        int flags = (int)x3;
        int fd = (int)x4;
        uint64_t offset = x5;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_mmap(addr, length, prot, flags, fd, offset));
    }else if(funcName == "mprotect") {
        uint64_t addr = x0;
        size_t size = x1;
        int prot = (int)x2;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_mprotect(addr, size, prot));
    }else if(funcName == "memset") {
        uint64_t ptr = x0;
        int value = (int)x1;
        size_t num = (size_t)x2;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_memset(ptr, value, num));
    }else if(funcName.find("memcpy") != std::string::npos) {
        uint64_t dest = x0;
        uint64_t src = x1;
        uint64_t n = x2;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_memcpy(dest, src, n));
    }else if(funcName == "memcmp") {
        const char* s1 = reinterpret_cast<const char *>(x0);
        const char* s2 = reinterpret_cast<const char *>(x1);
        uint64_t n = x2;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_memcmp(s1, s2, n));
    }else if(funcName.find("strlen") != std::string::npos){
        const char *s = reinterpret_cast<const char *>(x0);
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_strlen(s));
    }else if(funcName.find("strcmp") != std::string::npos) {
        const char *s1 = reinterpret_cast<const char *>(x0);
        const char *s2 = reinterpret_cast<const char *>(x1);
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_strcmp(s1, s2));
    }else if(funcName == "strstr"){
        const char *haystack = reinterpret_cast<const char *>(x0);
        const char *needle = reinterpret_cast<const char *>(x1);
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_strstr(haystack, needle));
    }else if(funcName == "sscanf"){
        const char* str = reinterpret_cast<const char *>(x0);
        const char* format = reinterpret_cast<const char *>(x1);
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_sscanf(str, format));
    }else if(funcName == "sleep"){
        uint64_t seconds = x0;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_sleep(seconds));
    }else if(funcName == "usleep"){
        uint64_t usec = x0;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_usleep(usec));
    }else if(funcName == "malloc"){
        uint64_t size = x0;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_malloc(size));
    }else if(funcName.find("fopen") != std::string::npos){
        const char *filename = reinterpret_cast<const char *>(x0);
        const char *mode = reinterpret_cast<const char *>(x1);
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_fopen(filename, mode));
    }else if(funcName == "openat"){
        //openat(uint64_t fd, const char *pathname, uint64_t flags, uint64_t mode)
        uint64_t fd = x0;
        const char *pathname = reinterpret_cast<const char *>(x1);
        uint64_t flags = x2;
        uint64_t mode = x3;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_openat(fd, pathname, flags, mode));
    }else if(funcName == "dlopen"){
        const char* path = reinterpret_cast<const char *>(x0);
        int flag = (int)x1;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_dlopen(path, flag));
    }else if(funcName == "dlsym"){
        uint64_t handle = x0;
        const char* symbol = reinterpret_cast<const char *>(x1);
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_dlsym(handle, symbol));
    }else if(funcName == "__system_property_get"){
        const char* name = reinterpret_cast<const char *>(x0);
        uint64_t value = x1;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse__system_property_get(name));
    }else if(funcName == "atoi"){
        const char* str = reinterpret_cast<const char *>(x0);
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_atoi(str));
    }else if(funcName == "sysconf"){
        int name = (int)x0;
        logtext = fmt::format("{:>{}}{}{}\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), parse_sysconf(name));
    }else{//没有处理参数的外部函数调用
        logtext = fmt::format("{:>{}}{}{}(...)\n", " ", logData->suojinNum * 4,
                              get_prefix_by_address(gprState->pc), funcName);
    }
    logData->logPrint(logtext.c_str());
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction
dealReturnEvent(QBDI::VM *vm, const QBDI::VMState *vmState, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
//    if ((vmState->event & QBDI::EXEC_TRANSFER_RETURN) == 0) {
//        return QBDI::CONTINUE;
//    }
    return QBDI::VMAction::CONTINUE;
}

QBDI::VMAction initModuleBase(QBDI::VM *vm, QBDI::GPRState *gprState, QBDI::FPRState *fprState, void *data) {
    std::string logtext;
    auto* logData = reinterpret_cast<logManager *>(data);
    const QBDI::InstAnalysis *instAnalysis = vm->getInstAnalysis(QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_SYMBOL | QBDI::ANALYSIS_DISASSEMBLY);
    std::string moduleName = instAnalysis->moduleName;
    initModuleStart(moduleName);
    logtext = fmt::format("{:>{}}{}sub_{:X}\n", " ", logData->suojinNum * 4,
                          get_prefix_by_address(gprState->pc), gprState->pc - thisModuleStart);
    logData->logPrint(logtext.c_str());
    logData->suojinNum++;
    return QBDI::VMAction::CONTINUE;
}

QBDI::VM vm::init(QBDI::rword address, logManager *logData) {
    uint32_t cid;
    QBDI::VM _vm{};
    initModuleInfo();
    //hook 内部函数调用
    cid = _vm.addCodeAddrCB(address, QBDI::InstPosition::PREINST, initModuleBase, logData);
    assert(cid != QBDI::INVALID_EVENTID);
    //对所有的指令进行hook
    cid = _vm.addCodeCB(QBDI::InstPosition::POSTINST, dealPostInstruction, logData);
    assert(cid != QBDI::INVALID_EVENTID);
    //hook 外部函数调用（SVC和库函数得分开）
    cid = _vm.addVMEventCB(QBDI::VMEvent::EXEC_TRANSFER_CALL, dealCallEvent, logData);
    assert(cid != QBDI::INVALID_EVENTID);
    cid = _vm.addVMEventCB(QBDI::VMEvent::EXEC_TRANSFER_RETURN, dealReturnEvent, logData);
    assert(cid != QBDI::INVALID_EVENTID);
    //hook 自定义的SVC指令
    cid = _vm.addMnemonicCB("SVC", QBDI::InstPosition::PREINST, dealSVCPreInstruction, logData);
    assert(cid != QBDI::INVALID_EVENTID);
    cid = _vm.addMnemonicCB("SVC", QBDI::InstPosition::POSTINST, dealSVCPostInstruction, logData);
    assert(cid != QBDI::INVALID_EVENTID);
    bool ret = _vm.addInstrumentedModuleFromAddr(address);
    assert(ret == true);
    return _vm;
}//




