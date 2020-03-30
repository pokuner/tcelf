C++ class instance counter based on vptr and ELF userdefine section.

To run this example, build and run the app firstly to demonstrate a running process
```bash
cd player
./build.sh
./app
```

Then execute the script in a new shell
```bash
./dumpinstcnt.py -p $(pidof app) -e libplayer.so
```

Output like this
```
Class           Count
---------------------
CPlayer         3    
CLotteryPlayer  2    
```

The dumpinstcnt.py python dependence
- pyelftools
- cxxfilt