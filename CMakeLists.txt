cmake_minimum_required(VERSION 3.10)
project(certificate)

set(CMAKE_CXX_STANDARD 11)

include_directories(.)

add_executable(certificate
        certificate.cpp
        getopt.h
        README.md)

add_definitions(-DNDEBUG)

#set (OPENSSL_ROOT_DIR=/usr/local/opt/openssl)

#find_package(OpenSSL REQUIRED)

#include_directories(${OPENSSL_INCLUDE_DIR})
#message(STATUS "OpenSSL ${OPENSSL_ROOT_DIR} ${OPENSSL_INCLUDE_DIR} ${OPENSSL_LIBRARIES}")

#target_link_libraries(certificate ${OPENSSL_LIBRARIES})
#target_link_libraries(certificate /usr/local/opt/openssl/lib/libcrypto.a)
#target_link_libraries(certificate /usr/local/opt/openssl/lib/libssl.a)

#find_package(ZLIB REQUIRED)
#list(APPEND EXTERNAL_LIBS ${ZLIB_LIBRARIES})

include_directories(/Users/oleggl/src/openssl/include/)
target_link_libraries(certificate /Users/oleggl/src/openssl/libcrypto.dylib)






