cmake_minimum_required(VERSION 3.30)
project(boost_socket)

set(CMAKE_CXX_STANDARD 20)

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)

include_directories(boost_socket "${CMAKE_CURRENT_SOURCE_DIR}/include" ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp" )

add_executable(tcp_server tcp_server.cpp ${SOURCES})
target_link_libraries(tcp_server Boost::system OpenSSL::SSL OpenSSL::Crypto)

add_executable(tcp_client tcp_client.cpp ${SOURCES})
target_link_libraries(tcp_client Boost::system OpenSSL::SSL OpenSSL::Crypto)

