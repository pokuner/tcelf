#pragma once

class Base {
   public:
    virtual ~Base() {}
    virtual void method() = 0;
};
class Derived : public Base {
   public:
    virtual ~Derived() {}
    void method();
};