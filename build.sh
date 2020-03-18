#!/bin/bash
g++ -g -o libmy.so -shared -fPIC so.cc
g++ -g -o main main.cc -L$(pwd) -lmy -Wl,-rpath,'$ORIGIN'