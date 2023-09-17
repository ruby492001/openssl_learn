project( crypt_lib )

add_library( ${PROJECT_NAME} crypt.cpp )

include_directories( ../../include )

target_link_libraries( ${PROJECT_NAME} PUBLIC crypto ssl algorithm_info )

