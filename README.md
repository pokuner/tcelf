C++ class instance counter based on vptr and ELF userdefine section.

To run this example
```bash
cd player
./build.sh
./app
```

The dumpinstcnt.py python dependence
- pyelftools
- cxxfilt

Then in a new shell
```bash
- ./dumpinstcnt.py -p $(pidof app) -e libplayer.so
```

Output like this
```
Class           Count
---------------------
CPlayer         3    
CLotteryPlayer  2    
```