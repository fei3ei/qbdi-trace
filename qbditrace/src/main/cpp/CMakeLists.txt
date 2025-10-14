
cmake_minimum_required(VERSION 3.22.1)
project("qbditrace")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=format -fdata-sections -ffunction-sections -fvisibility=hidden -Wl,--exclude-libs,ALL")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-rtti -fvisibility=hidden -Wl,--exclude-libs,ALL")
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

add_library(local_qbdi STATIC IMPORTED)
add_library(local_LIEF STATIC IMPORTED)
add_library(local_fmt STATIC IMPORTED)

set_target_properties(local_qbdi PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libQBDI.a)
set_target_properties(local_LIEF PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libLIEF.a)
set_target_properties(local_fmt PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libs/libfmt.a)

add_library(${CMAKE_PROJECT_NAME} SHARED
        source/start_hook.cpp
        source/vm.cpp
        source/parseSymbol.cpp
        source/dealSyscall.cpp
        source/parseExternalCall.cpp
)






target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
#target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/utils)





target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
        local_qbdi
        local_LIEF
        local_fmt)