CMAKE_MINIMUM_REQUIRED(VERSION 3.22)

project(so-injector)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)


file(GLOB HEADER_FILES "ElfParser/*.h" "Guards/*.h" "Injector/*.h")
file(GLOB SOURCE_FILES "ElfParser/*.cpp" "Guards/*.cpp" "Injector/*.cpp")

#message(STATUS "headers: ${HEADER_FILES}")
#message(STATUS "sources: ${SOURCE_FILES}")

#add_executable(${PROJECT_NAME} Source.cpp Guards/FileGuard.cpp Guards/FileGuard.h Guards/MapGuard.cpp Guards/MapGuard.h Injector/Injector.cpp Injector/Injector.h)

add_executable(${PROJECT_NAME} Source.cpp "${HEADER_FILES}" "${SOURCE_FILES}")
