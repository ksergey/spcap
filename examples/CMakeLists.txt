# some compiler stuff
if ("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU" OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -march=native -mtune=native")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Ofast -DNDEBUG")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
endif()

add_executable(spcap_print spcap_print.cpp)
target_link_libraries(spcap_print spcap)

add_executable(moex_print moex_print.cpp)
target_link_libraries(moex_print spcap)

add_executable(xcat xcat.cpp)
target_link_libraries(xcat spcap)

add_executable(bug_test bug_test.cpp)
target_link_libraries(bug_test spcap)

file(COPY plain.text plain.text.gz plain.text.xz DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
