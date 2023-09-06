cmake_minimum_required(VERSION 3.25)

project( openssl_learn )

add_executable( openssl_learn src/init.cpp)

target_link_libraries( openssl_learn PUBLIC crypto ssl)

#link_libraries( openssl_learn PUBLIC crypto ssl )