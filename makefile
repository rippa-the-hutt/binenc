.EXPORT_ALL_VARIABLES:
P=binenc
PD=debug
S=assembly
T=test
EXT_SOURCES= binIO.cpp
EXT_OBJECTS= RippaSSL/Cipher.o RippaSSL/Mac.o RippaSSL/Base.o binIO.o
SOURCES=main.cpp $(EXT_SOURCES)
OBJECTS=main.o $(EXT_OBJECTS)
T_SOURCES=tests.cpp $(EXT_SOURCES)
T_OBJECTS=tests.o $(EXT_OBJECTS)
DFLAGS= -Wall -ggdb -O0 -std=c++17 -D_GLIBCXX_DEBUG
CFLAGS= -Wall -Os -std=c++17
LDLIBS= -lssl -lcrypto
CC=g++

$(P): $(P).o
	$(CC) -o $(P) $(OBJECTS) $(LDLIBS)

$(P).o: $(SOURCES)
	$(CC) $(CFLAGS) -c $(SOURCES)
	cd RippaSSL && $(MAKE)

$(PD): $(PD).o
	$(CC) -o $(PD) $(OBJECTS) $(LDLIBS)

$(PD).o: $(SOURCES)
	$(CC) $(DFLAGS) -c $(SOURCES)
	cd RippaSSL && $(MAKE)

$(T): $(T).o
	$(CC) -o $(T) $(T_OBJECTS) $(LDLIBS)

$(T).o: $(T_SOURCES)
	$(CC) $(DFLAGS) -c $(T_SOURCES)
	cd RippaSSL && $(MAKE)

$(S): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDLIBS) -fverbose-asm -S $(SOURCES)

clean:
	rm *.o *.exe $(OBJECTS) $(P) $(PD) $(T)
