cmake_minimum_required(VERSION 3.22)

project(basic-elf)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)


add_executable(${PROJECT_NAME} Source.cpp)