//
// Created by chenfangzheng on 2025/7/22.
//

#ifndef QBDI_DEMO_PARSEEXTERNALCALL_H
#define QBDI_DEMO_PARSEEXTERNALCALL_H

#include <string>
#include <fmt/core.h>
#include <sys/types.h>
std::string parse_mmap(uint64_t addr, uint64_t length, int prot, int flags, int fd, uint64_t offset);
std::string parse_munmap(uint64_t addr, size_t len);
std::string parse_memset(uint64_t ptr, int value, size_t num);
std::string parse_openat(uint64_t fd, const char *pathname, uint64_t flags, uint64_t mode);
std::string parse_process_vm_readv(uint64_t pid, uint64_t local_iov, uint64_t liovcnt, uint64_t remote_iov, uint64_t riovcnt, uint64_t flags);
std::string parse_process_vm_writev(uint64_t pid, uint64_t local_iov, uint64_t liovcnt, uint64_t remote_iov, uint64_t riovcnt, uint64_t flags);
std::string parse_pthread_create(uint64_t thread, uint64_t attr, uint64_t start_routine, uint64_t arg);
std::string parse_memcmp(const char *s1, const char *s2, uint64_t n);
std::string parse_sleep(uint32_t seconds);
std::string parse_usleep(uint64_t usec);
std::string parse_malloc(uint64_t size);
std::string parse_fopen(const char *filename, const char *mode);
std::string parse_fgets(uint64_t dest, int n);
std::string parse_strstr(const char *haystack, const char *needle);
std::string parse_strlen(const char *s);
std::string parse_strcmp(const char *s1, const char *s2);
std::string parse_sscanf(const char* str, const char* format);
std::string parse_memcpy(uint64_t dest, uint64_t src, uint64_t n);
std::string parse_mprotect(uint64_t addr, size_t size, int prot);
std::string parse_dlopen(const char *path, int flag);
std::string parse_dlsym(uint64_t handle, const char *symbol);
std::string parse__system_property_get(const char *name);
std::string parse_atoi(const char *str);
std::string parse_sysconf(int name);
#endif //QBDI_DEMO_PARSEEXTERNALCALL_H
