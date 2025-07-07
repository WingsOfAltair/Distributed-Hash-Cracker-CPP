cmake_minimum_required(VERSION 3.10)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

project(DistributedHashCracker VERSION 1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find libsodium using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})

link_directories(${CMAKE_SOURCE_DIR}/lib)

# ------------------------------
# Include internal headers
# ------------------------------
include_directories(${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include)

# ------------------------------
# Boost
# ------------------------------
find_package(Boost REQUIRED COMPONENTS system filesystem thread chrono locale)
if(Boost_FOUND)
    message(STATUS "Boost version: ${Boost_VERSION}")
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories("C:/boost/lib64-msvc-14.3")
else()
    message(FATAL_ERROR "Boost not found")
endif()

# ------------------------------
# OpenSSL
# ------------------------------
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

# ------------------------------
# Windows-specific argon2 and bcrypt libs
# ------------------------------
if(WIN32)
    # Full path to argon2.lib
    set(ARGON2_LIB_PATH "${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/argon2/argon2.lib")      
    set(BCRYPT_LIB_PATH "${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/bcrypt/bcrypt.lib")

    # Check if file actually exists
    if(NOT EXISTS "${ARGON2_LIB_PATH}")
        message(FATAL_ERROR "argon2.lib not found at ${ARGON2_LIB_PATH}")
    endif()    

    # Check if file actually exists
    if(NOT EXISTS "${BCRYPT_LIB_PATH}")
        message(FATAL_ERROR "bcrypt.lib not found at ${BCRYPT_LIB_PATH}")
    endif()
endif()

# ------------------------------
# Build scrypt static library from source files
# ------------------------------

file(GLOB_RECURSE SCRYPT_SRC
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/*.c
)

# Exclude ARM-only test files that break build on non-ARM systems
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm|aarch64)")

    list(REMOVE_ITEM SCRYPT_SRC
        ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/cpusupport/Build/cpusupport-ARM-AES.c
        ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/cpusupport/Build/cpusupport-ARM-SHA256.c
        ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/apisupport/Build/apisupport-LIBCRYPTO-LOW_LEVEL_AES.c
        ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/apisupport/Build/apisupport-NONPOSIX-MEMLIMIT.c
        ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/cpusupport/Build/cpusupport-X86-AESNI.c
    )

endif()

add_library(scrypt STATIC ${SCRYPT_SRC})

target_compile_definitions(scrypt PUBLIC HAVE_CONFIG_H)

target_include_directories(scrypt PUBLIC
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt   
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/lib-platform/crypto
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/lib-platform/util
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/lib-platform   
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva       
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/alg   
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/cpusupport   
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/crypto     
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/POSIX
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libcperciva/util
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/lib
)

# ------------------------------
# Client executable
# ------------------------------
add_executable(DistributedHashCrackerClient 
    Distributed-Hash-Cracker-CPP-Client/Distributed-Hash-Cracker-CPP-Client.cpp
)

target_include_directories(DistributedHashCrackerClient PRIVATE
    ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include
)

if (WIN32)
target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    "${BCRYPT_LIB_PATH}"
    "${ARGON2_LIB_PATH}"  
    ${SODIUM_LIBRARIES}   
    scrypt 
)
else()
target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    bcrypt
    argon2
    crypt      
    ${SODIUM_LIBRARIES}   
    scrypt 
)
endif()

# ------------------------------
# Server executable
# ------------------------------
add_executable(DistributedHashCrackerServer 
    Distributed-Hash-Cracker-CPP/Distributed-Hash-Cracker-CPP-Server.cpp
)

target_link_libraries(DistributedHashCrackerServer PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# ------------------------------
# Copy DLLs and config files (Windows)
# ------------------------------
if(WIN32)
    set(BOOST_DLLS
        "C:/boost/lib64-msvc-14.3/boost_thread-vc143-mt-gd-x64-1_85.dll"
        "C:/boost/lib64-msvc-14.3/boost_filesystem-vc143-mt-gd-x64-1_85.dll"
        "C:/boost/lib64-msvc-14.3/boost_locale-vc143-mt-gd-x64-1_85.dll"
    )

    foreach(target DistributedHashCrackerClient DistributedHashCrackerServer)
        foreach(dll ${BOOST_DLLS})
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different "${dll}" $<TARGET_FILE_DIR:${target}>
            )
        endforeach()
    endforeach()
endif()

# ------------------------------
# Copy configuration files
# ------------------------------
set(CONFIG_SRC_DIR "${CMAKE_SOURCE_DIR}/x64/Debug")
set(CONFIG_FILES config.ini server.ini wordlist.txt mutation_list.txt mutation_list_generator_upto_n_times.py)

foreach(FILE ${CONFIG_FILES})
    foreach(target DistributedHashCrackerClient DistributedHashCrackerServer)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CONFIG_SRC_DIR}/${FILE}" $<TARGET_FILE_DIR:${target}>
        )
    endforeach()
endforeach()
       
# ------------------------------
# Copy DLL files
# ------------------------------
if (WIN32)              
    add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/argon2/argon2.dll"
            "$<TARGET_FILE_DIR:DistributedHashCrackerClient>"
    )             
    add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/scrypt/libsodium.dll"
            "$<TARGET_FILE_DIR:DistributedHashCrackerClient>"
    )
endif()