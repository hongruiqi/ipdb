# ipdb

C++ library for IP address query, based on https://github.com/killme2008/ip-service/tree/master/17monipdb.

## Usage

```C++
#include "ipdb.h"
#include <iostream>

int main(int argn, char* argv[]) {
  IPDB ip("17monipdb.dat");
  try {
    std::cout<<ip.Find(argv[1])<<std::endl;
  } catch (std::exception& e) {
    std::cerr<<e.what()<<std::endl;
  }
}
```
