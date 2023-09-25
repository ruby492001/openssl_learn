cmake_minimum_required(VERSION 3.25)

project( crypt )

add_executable( ${PROJECT_NAME} main.cpp )

target_link_directories( ${PROJECT_NAME} PUBLIC "/usr/local/ssl/lib64/" )
target_include_directories( ${PROJECT_NAME} PUBLIC "/usr/local/ssl/include/" )

target_link_libraries( ${PROJECT_NAME} PUBLIC crypto ssl)