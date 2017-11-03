cmake_minimum_required(VERSION 3.8)
project(ZSC)

set(CMAKE_C_STANDARD 11)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(BIN_DIR ${CMAKE_SOURCE_DIR}/bin)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(SOURCE_FILES ${SRC_DIR}/main.c)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

find_package(Threads)

include(FindPCAP.cmake)
include_directories(${SRC_DIR} ${BIN_DIR} ${LIB_DIR})

add_executable(ZSC ${SOURCE_FILES})

target_link_libraries(ZSC ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
