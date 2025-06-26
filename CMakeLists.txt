cmake_minimum_required(VERSION 3.10)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

project(DistributedHashCracker VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include internal headers
include_directories(Distributed-Hash-Cracker-CPP-Client/include)

# ------------------------------
# Boost
# ------------------------------
find_package(Boost REQUIRED COMPONENTS system filesystem thread chrono)
if(Boost_FOUND)
    message(STATUS "Boost version: ${Boost_VERSION}")
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories("C:/boost/lib64-msvc-14.3")  # Only needed for Windows
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
# Argon2 (manual, no vcpkg)
# ------------------------------
if(WIN32)
    find_path(ARGON2_INCLUDE_DIR argon2.h PATHS ${CMAKE_SOURCE_DIR}/argon2/include)
    find_library(ARGON2_LIBRARY_RELEASE
        NAMES argon2
        PATHS ${CMAKE_SOURCE_DIR}/argon2/lib
    )
    message(STATUS "Argon2 include dir: ${ARGON2_INCLUDE_DIR}")
    message(STATUS "Argon2 lib found at: ${ARGON2_LIBRARY_RELEASE}")

    if(NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY_RELEASE)
        message(FATAL_ERROR "Argon2 library or headers not found!")
    endif()

    include_directories(${ARGON2_INCLUDE_DIR})
    set(ARGON2_LIB_TARGET ${ARGON2_LIBRARY_RELEASE})
    add_compile_definitions(ARGON2_DLL_IMPORT)
else()
    # For UNIX, use pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ARGON2 REQUIRED argon2)
    include_directories(${ARGON2_INCLUDE_DIRS})
    link_directories(${ARGON2_LIBRARY_DIRS})
    set(ARGON2_LIB_TARGET ${ARGON2_LIBRARIES})
endif()

# ------------------------------
# Client executable
# ------------------------------
add_executable(DistributedHashCrackerClient 
    Distributed-Hash-Cracker-CPP-Client/Distributed-Hash-Cracker-CPP-Client.cpp
)

target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    bcrypt
    ${ARGON2_LIB_TARGET}
)

# Copy Argon2 DLL and LIB after build on Windows
if(WIN32)
    add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/argon2/argon2.dll
            $<TARGET_FILE_DIR:DistributedHashCrackerClient>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${ARGON2_LIB_TARGET}
            $<TARGET_FILE_DIR:DistributedHashCrackerClient>
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
# Copy Boost DLLs (Windows)
# ------------------------------
if(WIN32)
    set(BOOST_DLLS
        "C:/boost/lib64-msvc-14.3/boost_thread-vc143-mt-gd-x64-1_85.dll"
        "C:/boost/lib64-msvc-14.3/boost_filesystem-vc143-mt-gd-x64-1_85.dll"
    )
    foreach(DLL ${BOOST_DLLS})
        add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DLL}" $<TARGET_FILE_DIR:DistributedHashCrackerClient>
        )
        add_custom_command(TARGET DistributedHashCrackerServer POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DLL}" $<TARGET_FILE_DIR:DistributedHashCrackerServer>
        )
    endforeach()
endif()

# ------------------------------
# Copy configuration files
# ------------------------------
set(SRC_DIR "${CMAKE_SOURCE_DIR}/x64/Debug")
set(CONFIG_FILES config.ini server.ini wordlist.txt)

foreach(FILE ${CONFIG_FILES})
    add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SRC_DIR}/${FILE}" $<TARGET_FILE_DIR:DistributedHashCrackerClient>
    )
    add_custom_command(TARGET DistributedHashCrackerServer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${SRC_DIR}/${FILE}" $<TARGET_FILE_DIR:DistributedHashCrackerServer>
    )
endforeach()


if(WIN32)
    # Paths to your libs and dlls - adjust these if needed                                        
    set(ARGON2_DLL "${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/argon2/argon2.dll")
    set(ARGON2_LIB "${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/argon2/argon2.lib")
    set(BCRYPT_LIB "${CMAKE_SOURCE_DIR}/Distributed-Hash-Cracker-CPP-Client/include/bcrypt/bcrypt.lib")

    # Copy argon2.dll and libraries after building the client executable
    add_custom_command(TARGET DistributedHashCrackerClient POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${ARGON2_DLL}"
            $<TARGET_FILE_DIR:DistributedHashCrackerClient>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${ARGON2_LIB}"
            $<TARGET_FILE_DIR:DistributedHashCrackerClient>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${BCRYPT_LIB}"
            $<TARGET_FILE_DIR:DistributedHashCrackerClient>
    )
endif()