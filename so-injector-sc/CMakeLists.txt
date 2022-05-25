CMAKE_MINIMUM_REQUIRED(VERSION 3.22)

project(so-injector-sc)

set(CMAKE_C_FLAGS "-T ${CMAKE_SOURCE_DIR}/${PROJECT_NAME}/linker-script -nostdlib -ffunction-sections")

add_executable(${PROJECT_NAME} Source.c)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND objcopy -O binary --only-section=.bss --only-section=.text --set-section-flags .bss=alloc,load,contents ${PROJECT_NAME} shellcode.bin)