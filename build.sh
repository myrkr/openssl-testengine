g++ testengine.cpp -Wno-deprecated-declarations -g3 -O0 -ggdb -fPIC -rdynamic -shared -ldl -lrt -lssl -lcrypto -Wl,-soname,libtestengine.so -o libtestengine.so
