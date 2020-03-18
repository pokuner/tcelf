#include "so.h"

int main(void)
{
    Base* p = new Derived();
    p->method();
    return 0;
}