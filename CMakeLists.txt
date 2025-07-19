cmake_minimum_required(VERSION 3.20)
project(blacknurse VERSION 3.0.0 LANGUAGES CXX)

# Optional CUDA support
include(CheckLanguage)
check_language(CUDA)
if(CMAKE_CUDA_COMPILER)
    enable_language(CUDA)
    set(CUDA_FOUND TRUE)
else()
    set(CUDA_FOUND FALSE)
    message(STATUS "CUDA not found, building without GPU acceleration")
endif()

# Set C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3 -march=native")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3 -march=native")

# Debug flags
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")

# Find required packages
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

# Check for optional dependencies
find_package(OpenMP)
find_package(CUDA QUIET)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/src/common)
include_directories(${CMAKE_SOURCE_DIR}/src/core)
include_directories(${CMAKE_SOURCE_DIR}/src/network)
include_directories(${CMAKE_SOURCE_DIR}/src/stats)
include_directories(${CMAKE_SOURCE_DIR}/src/gpu)
include_directories(${CMAKE_SOURCE_DIR}/src/framework)
include_directories(${CMAKE_SOURCE_DIR}/src/protocols)
include_directories(${CMAKE_SOURCE_DIR}/src/waf)

# Source files
file(GLOB_RECURSE COMMON_SOURCES "src/common/*.c" "src/common/*.cpp")
file(GLOB_RECURSE CORE_SOURCES "src/core/*.c" "src/core/*.cpp")
file(GLOB_RECURSE NETWORK_SOURCES "src/network/*.c" "src/network/*.cpp")
file(GLOB_RECURSE STATS_SOURCES "src/stats/*.c" "src/stats/*.cpp")
file(GLOB_RECURSE FRAMEWORK_SOURCES "src/framework/*.c" "src/framework/*.cpp")
file(GLOB_RECURSE PROTOCOLS_SOURCES "src/protocols/*.c" "src/protocols/*.cpp")
file(GLOB_RECURSE WAF_SOURCES "src/waf/*.c" "src/waf/*.cpp")

# GPU sources (optional)
if(CUDA_FOUND)
    enable_language(CUDA)
    file(GLOB_RECURSE GPU_SOURCES "src/gpu/*.cu" "src/gpu/*.cpp")
    add_definitions(-DCUDA_ENABLED)
else()
    file(GLOB_RECURSE GPU_SOURCES "src/gpu/*.cpp")
endif()

# Create main executable
set(ALL_SOURCES
    src/main.cpp
    ${COMMON_SOURCES}
    ${CORE_SOURCES}
    ${NETWORK_SOURCES}
    ${STATS_SOURCES}
    ${FRAMEWORK_SOURCES}
    ${PROTOCOLS_SOURCES}
    ${WAF_SOURCES}
    ${GPU_SOURCES}
)

add_executable(blacknurse ${ALL_SOURCES})

# Find additional libraries
find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
find_package(OpenSSL REQUIRED)

# Link libraries
target_link_libraries(blacknurse 
    Threads::Threads
    ${CURL_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(OpenMP_FOUND)
    target_link_libraries(blacknurse OpenMP::OpenMP_CXX)
    add_definitions(-DOPENMP_ENABLED)
endif()

if(CUDA_FOUND)
    target_link_libraries(blacknurse ${CUDA_LIBRARIES})
endif()

# Include directories for external libraries
target_include_directories(blacknurse PRIVATE ${CURL_INCLUDE_DIRS})
target_compile_options(blacknurse PRIVATE ${CURL_CFLAGS_OTHER})

# Platform specific libraries
if(UNIX AND NOT APPLE)
    target_link_libraries(blacknurse rt)
elseif(APPLE)
    target_link_libraries(blacknurse)
endif()

# Install targets
install(TARGETS blacknurse DESTINATION bin)

# CPack configuration
set(CPACK_PACKAGE_NAME "BlackNurse")
set(CPACK_PACKAGE_VERSION "2.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced ICMP DoS Testing Tool")
set(CPACK_PACKAGE_VENDOR "BlackNurse Project")
include(CPack)