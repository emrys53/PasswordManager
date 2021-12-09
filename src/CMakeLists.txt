cmake_minimum_required(VERSION 3.1)

set(LIBRARY_NAME MyLib)

# list all the headers of the module
set(MODULE_HEADERS util.h sha256.h aes.h)

# list all the code files of the module
set(MODULE_SOURCES sha256.cpp aes.cpp util.cpp)

# build the module library
add_library(${LIBRARY_NAME} ${MODULE_HEADERS} ${MODULE_SOURCES})
add_library(lib::${LIBRARY_NAME} ALIAS ${LIBRARY_NAME})

target_include_directories(${LIBRARY_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# require C++20
target_compile_features(${LIBRARY_NAME} PUBLIC cxx_std_20)
set_target_properties(${LIBRARY_NAME} PROPERTIES LINKER_LANGUAGE CXX)

add_executable(PasswordManager main.cpp)

target_link_libraries(PasswordManager lib::MyLib)

target_compile_options(${LIBRARY_NAME} PUBLIC -Wall -Wextra -Wconversion -pedantic -Wfatal-errors)
target_compile_options(PasswordManager PUBLIC -Wall -Wextra -Wconversion -pedantic -Wfatal-errors)
