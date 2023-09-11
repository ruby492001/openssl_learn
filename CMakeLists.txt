cmake_minimum_required(VERSION 3.25)

project( openssl_learn )

include_directories( include )

add_subdirectory( src/crypt )
add_subdirectory( src/decrypt )