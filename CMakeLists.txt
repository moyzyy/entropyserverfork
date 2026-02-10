cmake_minimum_required(VERSION 3.14)
project(entropy_backend VERSION 2.0 LANGUAGES CXX C)


if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    add_compile_options(
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -O3
    )
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
         add_definitions(-DENTROPY_PRODUCTION=1)
    endif()
endif()


find_package(Boost 1.75 REQUIRED COMPONENTS system thread json)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)


include(FetchContent)


# Hiredis configuration
set(DISABLE_TESTS ON CACHE BOOL "" FORCE)
set(ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
# Testing configuration


FetchContent_Declare(
    hiredis
    GIT_REPOSITORY https://github.com/redis/hiredis.git
    GIT_TAG        v1.2.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(hiredis)


list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")


file(MAKE_DIRECTORY "${hiredis_SOURCE_DIR}/hiredis")
file(GLOB HIREDIS_HEADERS "${hiredis_SOURCE_DIR}/*.h")
file(COPY ${HIREDIS_HEADERS} DESTINATION "${hiredis_SOURCE_DIR}/hiredis")


set(HIREDIS_HEADER "${hiredis_SOURCE_DIR}")
set(HIREDIS_JSY_HEADER "${hiredis_SOURCE_DIR}") 



set(HIREDIS_LIB hiredis CACHE STRING "Hiredis target" FORCE)
set(HIREDIS_STATIC_LIB hiredis CACHE STRING "Hiredis target" FORCE)


set(REDIS_PLUS_PLUS_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(REDIS_PLUS_PLUS_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    redis-plus-plus
    GIT_REPOSITORY https://github.com/sewenew/redis-plus-plus.git
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(redis-plus-plus)




set(HEADERS
    include/server_config.hpp
    include/http_session.hpp
    include/websocket_session.hpp
    include/connection_manager.hpp
    include/message_relay.hpp
    include/redis_manager.hpp
    include/key_storage.hpp
    include/rate_limiter.hpp
    include/pow_verifier.hpp
    include/challenge.hpp
    include/input_validator.hpp
    include/metrics.hpp
    include/security_logger.hpp
)

# Server Logic Library
set(LOGIC_SOURCES
    src/http_session.cpp
    src/websocket_session.cpp
    src/connection_manager.cpp
    src/message_relay.cpp
    src/redis_manager.cpp
    src/rate_limiter.cpp
    src/handlers/identity_handler.cpp
    src/handlers/health_handler.cpp
    src/traffic_normalizer.cpp
)

add_library(server_core STATIC ${LOGIC_SOURCES} ${HEADERS})

target_include_directories(server_core PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/handlers
)

target_link_libraries(server_core PUBLIC
    Boost::system
    Boost::thread
    Boost::json
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    hiredis
    redis++
)

add_executable(server src/main.cpp)
target_link_libraries(server PRIVATE server_core)



# Custom target to generate self-signed certificates
add_custom_target(generate_certs
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/certs
    COMMAND openssl req -x509 -newkey rsa:4096 -keyout ${CMAKE_CURRENT_SOURCE_DIR}/certs/server.key -out ${CMAKE_CURRENT_SOURCE_DIR}/certs/server.crt -days 365 -nodes -subj "/CN=localhost"
    COMMENT "Generating self-signed certificates for development..."
    VERBATIM
)

