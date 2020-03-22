g++ -g -Wall app.cc -o app -ldl
g++ -g -Wall -shared -fPIC player.cc -o libplayer.so