project( decrypt_lib )

add_library( ${PROJECT_NAME} decrypt.cpp )

include_directories( ../../include )

target_link_libraries( ${PROJECT_NAME} PUBLIC crypto ssl algorithm_info )

