cmake_minimum_required(VERSION 3.8)
project(ZSC)

set(CMAKE_C_STANDARD 11)

include(FindPCAP.cmake)

set(SOURCE_FILES main.c)
add_executable(ZSC ${SOURCE_FILES})
target_link_libraries(ZSC ${PCAP_LIBRARY})