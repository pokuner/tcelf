C++ class instance counter based on vptr and ELF userdefine section.

To run this example
- cd player
- ./build.sh
- ./app

Then in a new shell
- ./dumpinstcnt.py -p $(pidof app) -e libplayer.so