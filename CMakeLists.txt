project(pcapSmaple)
cmake_minimum_required(VERSION 2.8)

SET (CMAKE_BUILD_TYPE "Debug")

aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} pcap curl)

#message(STATUS ${CMAKE_INSTALL_PREFIX})
#message(STATUS ${EXECUTABLE_OUTPUT_PATH})
#message(STATUS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
#message(STATUS ${CMAKE_BUILD_WITH_INSTALL_RPATH})
#message(STATUS ${EXECUTABLE_OUTPUT_PATH})
#message(STATUS ${PROJECT_SOURCE_DIR})

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)

#ilya            ALL=NOPASSWD:   /usr/bin/chmod, /usr/bin/chown
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND sudo chown root ${EXECUTABLE_OUTPUT_PATH}/${PROJECT_NAME}
                                                     COMMAND sudo chmod u+s  ${EXECUTABLE_OUTPUT_PATH}/${PROJECT_NAME})
