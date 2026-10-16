#include <iostream>
#include <stdexcept>

#include "upf.hpp"

int main()
{
    try {
        Upf upf;
        if (!upf.upf_init()) {
            return 1;
        }
        upf.upf_run();
    } catch (const std::runtime_error& re) {
        std::cout << re.what() << std::endl;
        return 1;
    }
    
    return 0;
}
