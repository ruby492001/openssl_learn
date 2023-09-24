cmake_minimum_required(VERSION 3.25)

project( openssl_learn )

add_executable( openssl_learn src/init.cpp)

target_link_directories( openssl_learn PUBLIC "/usr/local/ssl/lib64/" )
target_include_directories( openssl_learn PUBLIC "/usr/local/ssl/include/" )

target_link_libraries( openssl_learn PUBLIC crypto ssl)

#link_libraries( openssl_learn PUBLIC crypto ssl )