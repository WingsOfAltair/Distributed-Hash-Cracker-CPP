cmake_minimum_required(VERSION 3.10)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

project(DistributedHashCracker VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# ------------------------------
# Include internal headers
# ------------------------------
include_directories(${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include)

# ------------------------------
# Boost
# ------------------------------
find_package(Boost REQUIRED COMPONENTS system filesystem thread chrono)
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
# Client executable
# ------------------------------
add_executable(DistributedHashCrackerClient 
    Distributed-Hash-Cracker-CPP-Client/Distributed-Hash-Cracker-CPP-Client.cpp
)

if (WIN32)
target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    "${BCRYPT_LIB_PATH}"
    "${ARGON2_LIB_PATH}"
)
else()
target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    bcrypt
    argon2
    crypt
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
set(CONFIG_FILES config.ini server.ini wordlist.txt)

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
add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/argon2/argon2.dll"
        "$<TARGET_FILE_DIR:DistributedHashCrackerClient>"
)