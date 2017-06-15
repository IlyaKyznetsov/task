project(task)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_BUILD_TYPE "Debug")

set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")

aux_source_directory(. SRC_LIST)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} pcap)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)
