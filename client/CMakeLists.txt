cmake_minimum_required(VERSION 3.28)

project(Client)

set (BOOST_ROOT "/usr/include/boost/")
set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF) 
find_package(Boost 1.86.0 COMPONENTS system) 

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS} src) 
    set(SOURCE src/main.cpp)
    set(LIBRARIES 
        src/core/client.cpp src/core/client.h 
        src/crypto/srp.cpp src/crypto/srp.h
    )
    add_library(LIBS STATIC ${LIBRARIES})
    add_executable(client ${SOURCE}) 
    find_package(OpenSSL REQUIRED)

    target_link_libraries(client LIBS Boost::boost OpenSSL::SSL)
endif()
