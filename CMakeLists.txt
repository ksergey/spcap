cmake_minimum_required(VERSION 3.0)

# Project name
project(spcap)

# Options
option(BUILD_EXAMPLES "Build library examples" ON)

# LZMA required for decoding compressed streams
find_package(LibLZMA REQUIRED)

# ZLIB required for decoding compressed streams
find_package(ZLIB REQUIRED)

# Create library entry
add_library(spcap INTERFACE)
target_include_directories(spcap INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(spcap INTERFACE SYSTEM ${LIBLZMA_INCLUDE_DIRS} SYSTEM ${ZLIB_INCLUDE_DIRS})
target_link_libraries(spcap INTERFACE ${LIBLZMA_LIBRARIES} ${ZLIB_LIBRARIES})
target_compile_features(spcap INTERFACE cxx_std_14)

if (BUILD_EXAMPLES)
    message(STATUS "spcap: build examples (yes)")
    add_subdirectory(examples)
else()
    message(STATUS "spcap: build examples (no)")
endif()
