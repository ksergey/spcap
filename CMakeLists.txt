cmake_minimum_required(VERSION 3.0)

# project name
project(spcap)

# setting the cpp standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# options
option(BUILD_EXAMPLES "Build library examples" ON)

# lzma required for decoding compressed streams
find_package(LibLZMA REQUIRED)
include_directories(${LIBLZMA_INCLUDE_DIRS})

# create library entry
add_library(spcap INTERFACE)
target_include_directories(spcap INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(spcap INTERFACE ${LIBLZMA_LIBRARIES})

if (BUILD_EXAMPLES)
    message(STATUS "spcap: build examples (yes)")
    add_subdirectory(examples)
else()
    message(STATUS "spcap: build examples (no)")
endif()
