project(task)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_BUILD_TYPE "Debug")

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")

aux_source_directory(. SRC_LIST)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} pcap)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)

#ilya            ALL=NOPASSWD:   /usr/bin/chmod, /usr/bin/chown
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND sudo chown root  ${EXECUTABLE_OUTPUT_PATH}/${PROJECT_NAME}
                                                     COMMAND sudo chgrp root  ${EXECUTABLE_OUTPUT_PATH}/${PROJECT_NAME}
                                                     COMMAND sudo chmod u+s   ${EXECUTABLE_OUTPUT_PATH}/${PROJECT_NAME})
