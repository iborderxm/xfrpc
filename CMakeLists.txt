
# Minimum CMake version 
cmake_minimum_required(VERSION 3.5...3.27)
project(xfrp C)

# Build options
option(DEBUG "Enable debug mode" OFF)
option(ENABLE_SANITIZER "Enable sanitizer(Debug+Gcc/Clang/AppleClang)" ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# Find required packages from the system
find_package(LibEvent REQUIRED)
find_package(JSON-C REQUIRED)
find_package(ZLIB REQUIRED)

# TLS/SSL + crypto backend: mbedTLS 3.6.x (required)
# - TLS transport: libevent bufferevent_mbedtls (libevent >= 2.2), see tls.c
# - Crypto layer: PBKDF2/AES-128-CFB/MD5 (crypto.c, crypto_stream.c, nathole.c)
find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h)
find_library(MBEDTLS_LIBRARY    NAMES mbedtls)
find_library(MBEDX509_LIBRARY   NAMES mbedx509)
find_library(MBEDCRYPTO_LIBRARY NAMES mbedcrypto)
if(NOT MBEDTLS_INCLUDE_DIR OR NOT MBEDTLS_LIBRARY OR NOT MBEDX509_LIBRARY OR NOT MBEDCRYPTO_LIBRARY)
    message(FATAL_ERROR "mbedTLS not found. Install mbedTLS 3.6.x (mbedtls/mbedx509/mbedcrypto).")
endif()
include_directories(${MBEDTLS_INCLUDE_DIR})
set(SSL_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
message(STATUS "TLS/crypto backend: mbedTLS (${MBEDTLS_LIBRARY})")

# NOTE: QUIC transport (quic_transport.c) is not built with mbedTLS:
# ngtcp2 has no mbedTLS crypto backend (only OpenSSL/GnuTLS/wolfSSL/Picotls).
# quic_client_transport.c is still compiled and provides stub functions
# that report "QUIC not compiled in".

include_directories(
    ${JSON-C_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}
)

set(EXTRA_LIBS)

# Sanitizer configuration
macro(check_asan _RESULT)
    include(CheckCSourceRuns)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
    check_c_source_runs("int main() { return 0; }" ${_RESULT})
    unset(CMAKE_REQUIRED_FLAGS)
endmacro()

if(ENABLE_SANITIZER AND NOT MSVC)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        check_asan(HAS_ASAN)
        if(HAS_ASAN)
            message(STATUS "Adding address sanitizer")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=leak")
            list(APPEND EXTRA_LIBS asan)
        else()
            message(STATUS "Sanitizer not supported with current toolchain")
        endif()
    else()
        message(STATUS "Sanitizer only available in Debug build")
    endif()
endif()

# Source files
set(CORE_SOURCES
    main.c
    client.c
    config.c
    control.c
    ini.c
    toml_parser.c
    vendor/tomlc17/tomlc17.c
    crypto_stream.c
    vendor/snappy/snappy.c
    oidc_auth.c
    msg.c
    xfrpc.c
    debug.c
    zip.c
    commandline.c
    crypto.c
    utils.c
    common.c
    login.c
    tls.c
    health_check.c
)

set(PROXY_SOURCES
    proxy_tcp.c
    proxy_udp.c
    proxy.c
    tcpmux.c
    visitor.c
    xtcp_visitor.c
    xtcp_client.c
    nathole.c
    tcp_redir.c
    mongoose.c
)
# quic_client_transport.c is always compiled but only provides stubs
# ("QUIC not compiled in"): ngtcp2 has no mbedTLS crypto backend.
list(APPEND PROXY_SOURCES quic_client_transport.c)

set(PLUGIN_SOURCES
    plugins/telnetd.c
    plugins/instaloader.c
    plugins/httpd.c
    plugins/youtubedl.c
)

# Combine all sources
set(src_xfrpc
    ${CORE_SOURCES}
    ${PROXY_SOURCES}
    ${PLUGIN_SOURCES}
)

# Required libraries
set(SYSTEM_LIBS
    pthread
    m
    crypt
    dl
)

set(EXTERNAL_LIBS
    ${SSL_LIBRARIES}
    event
    event_mbedtls
    ${JSON-C_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

# Set debug flags
if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
    add_definitions(-DXFRPC_DEBUG)
    message(STATUS "Debug mode: ON (-g -O0 flags added, XFRPC_DEBUG defined)")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
    message(STATUS "Debug mode: OFF (optimized build)")
endif()

# Compiler flags
add_definitions(
    -D_GNU_SOURCE
    -Wall
    -Werror
)

# Build target
add_executable(xfrpc ${src_xfrpc})

# Suppress stringop-truncation warnings from strncpy in legacy code
target_compile_options(xfrpc PRIVATE -Wno-stringop-truncation)

# Link libraries
target_link_libraries(xfrpc PRIVATE
    ${EXTERNAL_LIBS}
    ${SYSTEM_LIBS}
    ${EXTRA_LIBS}
)

# Installation
install(TARGETS xfrpc DESTINATION bin)