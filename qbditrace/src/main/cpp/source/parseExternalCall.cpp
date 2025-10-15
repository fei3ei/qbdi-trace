//
// Created by chenfangzheng on 2025/7/22.
//


#include <unistd.h>
#include "parseExternalCall.h"

static int get_filename_by_fd(int fd, char * out, size_t outlen){
    char procpath[64];
    ssize_t r;
    snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", fd);
    r = readlink(procpath, out, outlen - 1);
    if (r < 0) return -1;
    out[r] = '\0';
    return 0;
}

std::string parse_mmap(uint64_t addr, uint64_t length, int prot, int flags, int fd, uint64_t offset){
    std::string logtext;
    char buf[512] = {0};
    if(fd == -1){
        logtext = fmt::format("mmap({:#x},{:#x},{},{},{},{:#x})", addr, length, prot, flags, fd, offset);
    }else{
        if(get_filename_by_fd(fd, buf, sizeof(buf)) == 0){ //成功从fd中获取到了文件名
            logtext = fmt::format("mmap({:#x},{:#x},{},{},{}, {:#x})", addr, length, prot, flags, buf, offset);
        }else{ //没有获取到文件名
            logtext = fmt::format("mmap({:#x},{:#x},{},{},{},{:#x})", addr, length, prot, flags, fd, offset);
        }
    }
    return logtext;
}

std::string parse_munmap(uint64_t addr, size_t len) {
    std::string logtext;
    logtext = fmt::format("munmap({:#x},{:#x})", addr, len);
    return logtext;
}

std::string parse_memset(uint64_t ptr, int value, size_t num) {
    std::string logtext;
    logtext = fmt::format("memset({:#x},{},{})", ptr, value, num);
    return logtext;
}

std::string parse_openat(uint64_t fd, const char *pathname, uint64_t flags, uint64_t mode) {
    std::string logtext;
    logtext = fmt::format("openat({:#x},{},{:#x},{:#x})", fd, pathname, flags, (uint32_t)mode);
    return logtext;
}

std::string parse_process_vm_readv(uint64_t pid, uint64_t local_iov, uint64_t liovcnt, uint64_t remote_iov, uint64_t riovcnt, uint64_t flags) {
    std::string logtext;
    logtext = fmt::format("process_vm_readv({},{:#x},{},{:#x},{},{})", pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
    return logtext;
}

std::string parse_process_vm_writev(uint64_t pid, uint64_t local_iov, uint64_t liovcnt, uint64_t remote_iov, uint64_t riovcnt, uint64_t flags) {
    std::string logtext;
    logtext = fmt::format("process_vm_writev({},{:#x},{},{:#x},{},{})", pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
    return logtext;
}

std::string parse_pthread_create(uint64_t thread, uint64_t attr, uint64_t start_routine, uint64_t arg) {
    std::string logtext;
    logtext = fmt::format("pthread_create(thread,attr,{:#x},arg)", start_routine);
    return logtext;
}

std::string parse_strstr(const char *haystack, const char *needle) {
    std::string logtext;
    logtext = fmt::format("strstr({},{})", haystack, needle);
    return logtext;
}

std::string parse_strlen(const char *s) {
    std::string logtext;
    logtext = fmt::format("strlen({})", s);
    return logtext;
}

std::string parse_strcmp(const char *s1, const char *s2) {
    std::string logtext;
    logtext = fmt::format("strcmp({},{})", s1, s2);
    return logtext;
}

std::string parse_memcmp(const char *s1, const char *s2, uint64_t n) {
    std::string logtext;
    logtext = fmt::format("memcmp({},{},{:#x})", s1, s2, n);
    return logtext;
}

std::string parse_memcpy(uint64_t dest, uint64_t src, uint64_t n) {
    std::string logtext;
    const char* tmp = reinterpret_cast<const char*>(src);
    size_t safe_len = strnlen(tmp, n);
    if(safe_len <= n){//说明src是一个字符串，直接打印字符串内容
        logtext = fmt::format("memcpy({:#x},{},{})", dest, reinterpret_cast<const char *>(src), n);
    }else{
        logtext = fmt::format("memcpy({:#x},{:#x},{})", dest, src, n);
    }
    return logtext;
}

std::string parse_sscanf(const char* str, const char* format) {
    std::string logtext;
    logtext = fmt::format("sscanf({},{},...)", str, format);
    return logtext;
}

std::string parse_fopen(const char *filename, const char *mode) {
    std::string logtext;
    logtext = fmt::format("fopen({},{})", filename, mode);
    return logtext;
}

std::string parse_fgets(uint64_t dest, int n) {
    std::string logtext;
    logtext = fmt::format("fgets({:#x},{})", dest, n);
    return logtext;
}

std::string parse_sleep(uint32_t seconds) {
    std::string logtext;
    logtext = fmt::format("sleep({})", seconds);
    return logtext;
}

std::string parse_usleep(uint64_t usec) {
    std::string logtext;
    logtext = fmt::format("usleep({})", usec);
    return logtext;
}

std::string parse_malloc(uint64_t size) {
    std::string logtext;
    logtext = fmt::format("malloc({})", size);
    return logtext;
}

std::string parse_mprotect(uint64_t addr, size_t size, int prot) {
    std::string logtext;
    logtext = fmt::format("mprotect({:#x},{:#x},{})", addr, size, prot);
    return logtext;
}

std::string parse_dlopen(const char *path, int flag) {
    std::string logtext;
    logtext = fmt::format("dlopen({},{})", path, flag);
    return logtext;
}

std::string parse_dlsym(uint64_t handle, const char *symbol) {
    std::string logtext;
    logtext = fmt::format("dlsym({:#x},{})", handle, symbol);
    return logtext;
}

std::string parse__system_property_get(const char *name){
    std::string logtext;
    logtext = fmt::format("__system_property_get({})", name);
    return logtext;
}

std::string parse_atoi(const char *str){
    std::string logtext;
    logtext = fmt::format("atoi({})", str);
    return logtext;
}

std::string parse_sysconf(int name){
    std::string logtext;
    logtext = fmt::format("sysconf({})", name);
    return logtext;
}