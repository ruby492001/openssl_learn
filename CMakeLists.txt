cmake_minimum_required(VERSION 3.25)

project( verify )

add_executable( verify src/verify.cpp)

target_link_directories( verify PUBLIC "/usr/local/ssl/lib64/" )
target_include_directories( verify PUBLIC "/usr/local/ssl/include/" )

target_link_libraries( verify PUBLIC crypto ssl)