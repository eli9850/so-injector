#include <iostream>

__attribute__((constructor))
void ctor() {
    std::cout << "ctor" << std::endl;
}

__attribute__((destructor))
void dtor() {
    std::cout << "dtor" << std::endl;
}
