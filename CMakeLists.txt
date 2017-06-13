project(task)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_BUILD_TYPE "Debug")

if (CMAKE_COMPILER_IS_GNUCC)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    string(REGEX MATCHALL "[0-9]+" GCC_VERSION_COMPONENTS ${GCC_VERSION})
    list(GET GCC_VERSION_COMPONENTS 0 GCC_MAJOR)
    list(GET GCC_VERSION_COMPONENTS 1 GCC_MINOR)
    list(GET GCC_VERSION_COMPONENTS 2 GCC_BUILD)

    if(${GCC_MAJOR}==4 AND ${GCC_MINOR}==4)
        set(CMAKE_CXX_FLAGS "-std=c++0x -DCENTOS")
    else(${GCC_MAJOR}==4 AND ${GCC_MINOR}>=8)
        set(CMAKE_CXX_FLAGS "-std=c++11")
    endif()
endif()

#execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
#                OUTPUT_VARIABLE GCC_VERSION)
#if (GCC_VERSION VERSION_GREATER 4.3 OR GCC_VERSION VERSION_EQUAL 4.3)
#        message(STATUS "Version >= 4.3")
#endif()

aux_source_directory(. SRC_LIST)
aux_source_directory(decode_packet_classes SRC_LIST)
aux_source_directory(decode_packet_classes/decode_tcp_data_classes SRC_LIST)
include_directories(.)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} pcap pthread)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)

#ilya            ALL=NOPASSWD:   /usr/bin/chmod, /usr/bin/chown
#add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND sudo chown root ${EXECUTABLE_OUTPUT_PATH}/${PROJECT_NAME}
#                                                     COMMAND sudo chmod u+s  ${EXECUTABLE_OUTPUT_PATH}/${PROJECT_NAME})
