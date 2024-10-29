cmake_minimum_required(VERSION 3.10)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

project(DistributedHashCracker VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories
include_directories(Distributed-Hash-Cracker-CPP-Client/include)

# Automatically find Boost
find_package(Boost REQUIRED COMPONENTS system filesystem thread chrono)

# If Boost is found, display its version and add include directories
if(Boost_FOUND)
    message(STATUS "Boost version: ${Boost_VERSION}")
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories("C:/boost/lib64-msvc-14.3")  # Add Boost library directory
else()
    message(FATAL_ERROR "Boost not found")
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# If OpenSSL is found, add include directories
if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})  # Add OpenSSL include directory
    message(STATUS "OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

# Add bcrypt library directory
link_directories(Distributed-Hash-Cracker-CPP-Client/include/bcrypt)  # Add bcrypt library directory

# Add executables
add_executable(DistributedHashCrackerClient 
    Distributed-Hash-Cracker-CPP-Client/Distributed-Hash-Cracker-CPP-Client.cpp
)

if(UNIX)
target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    bcrypt  # Link bcrypt library
    crypt   # Link the crypt library
)
endif()

if(WIN32)
target_link_libraries(DistributedHashCrackerClient PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    bcrypt  # Link bcrypt library
)
endif()

add_executable(DistributedHashCrackerServer 
    Distributed-Hash-Cracker-CPP/Distributed-Hash-Cracker-CPP-Server.cpp
)
target_link_libraries(DistributedHashCrackerServer PRIVATE 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(WIN32)
	# Specify the Boost libraries you want to copy
	set(BOOST_DLLS
    	"C:/boost/lib64-msvc-14.3/boost_thread-vc143-mt-gd-x64-1_85.dll"      # Adjust for your Boost version
    	"C:/boost/lib64-msvc-14.3/boost_filesystem-vc143-mt-gd-x64-1_85.dll"  # Add boost_filesystem DLL
	)
endif()

# Copy Boost DLLs after building the executables
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

if(WIN32)
    set(SRC_DIR "${CMAKE_SOURCE_DIR}/x64/Debug")  # Path to the Debug folder
    set(DEST_DIR "${CMAKE_BINARY_DIR}")

    # List of configuration files to copy
    set(CONFIG_FILES
        config.ini
        server.ini
        wordlist.txt
    )

    # Copy configuration files after building the executables
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
endif()
