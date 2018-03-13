cmake_minimum_required(VERSION 3.0)

# Project name
project(spcap)

# Options
option(spcap_BUILD_EXAMPLES "Build library examples" ON)

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

add_library(ksergey::spcap ALIAS spcap)

if (spcap_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
