project( openssl_decrypt )

add_executable( ${PROJECT_NAME} main.cpp )

include_directories( ../include )

target_link_libraries( ${PROJECT_NAME} PUBLIC crypto ssl )
