cmake_minimum_required(VERSION 3.22.1)
project("anycheck")

add_library(anycheck SHARED lsposed_detect.cpp hunter_elf.cpp)
target_link_libraries(anycheck log)
