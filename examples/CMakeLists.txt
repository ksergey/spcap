add_executable(spcap_print spcap_print.cpp)
target_link_libraries(spcap_print spcap)

add_executable(moex_print moex_print.cpp)
target_link_libraries(moex_print spcap)

add_executable(xcat xcat.cpp)
target_link_libraries(xcat spcap)

file(COPY plain.text plain.text.gz plain.text.xz DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
