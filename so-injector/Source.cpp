#include <iostream>
#include <sys/mman.h>

#include "Guards/MapGuard.h"
#include "Injector/Injector.h"

constexpr int FILE_TO_INJECT_INDEX = 1;
constexpr int SHELLCODE_TO_INJECT_INDEX = 2;
constexpr int SO_TO_INJECT_INDEX = 3;
constexpr int NUMBER_OF_ARGS = 4;


int main(int argc, char *argv[]) {

    if (NUMBER_OF_ARGS != argc) {
        std::cout << "invalid args" << std::endl;
    }

    auto file_to_inject = std::make_shared<MapGuard>(argv[FILE_TO_INJECT_INDEX], PROT_READ | PROT_WRITE, MAP_SHARED);
    auto shellcode_to_inject = std::make_shared<MapGuard>(argv[SHELLCODE_TO_INJECT_INDEX], PROT_READ | PROT_WRITE, MAP_SHARED);

    Injector injector(std::move(file_to_inject), std::move(shellcode_to_inject), argv[SO_TO_INJECT_INDEX]);
    injector.inject();

    return 0;
}