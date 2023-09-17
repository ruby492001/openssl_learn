project( algorithm_info )

add_library( ${PROJECT_NAME} algorithm_info.cpp )

include_directories( ../../include )

target_link_libraries( ${PROJECT_NAME} PUBLIC crypto ssl )

